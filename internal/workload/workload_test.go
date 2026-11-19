package workload

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	appA   = "11111111-1111-4111-8111-111111111111"
	issuer = "https://dex.cell.example/artifacts"
	aud    = "pathops-artifact-store"
	tcp    = "system:serviceaccount:pathops-system:tenant-control-plane"
	run    = "applications/" + appA + "/deliveries/33333333-3333-4333-8333-333333333333/"
)

var now = time.Unix(1_800_000_000, 0)

// sign builds an EdDSA JWT as Dex's workload token exchange (patch 0006) does.
func sign(key ed25519.PrivateKey, kid string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	c, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(in)))
}

func good() map[string]any {
	return map[string]any{"iss": issuer, "aud": aud, "sub": tcp,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Unix() + 300, "jti": "x",
		"pathops_application": appA, "pathops_operations": []string{"read", "write"},
		"pathops_key_prefix": run}
}

func TestVerify(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	v := &Verifier{Issuer: issuer, Audience: aud, KeyID: "artifact-1", Key: pub, Now: func() time.Time { return now }}
	p, err := v.Verify(sign(key, "artifact-1", good()))
	if err != nil || p.Application != appA || !p.Allows(OpRead) || !p.Allows(OpWrite) || p.Subject != tcp || p.KeyPrefix != run {
		t.Fatal(p, err)
	}
	if !p.Covers(run+"build-failure.tar.gz") || p.Covers(run) || p.Covers("applications/"+appA+"/deliveries/other/x") ||
		p.Covers("applications/"+appA+"/x") {
		t.Fatal("Covers")
	}
	// aud as an array.
	c := good()
	c["aud"] = []string{"other", aud}
	if _, err := v.Verify(sign(key, "artifact-1", c)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	v := &Verifier{Issuer: issuer, Audience: aud, KeyID: "artifact-1", Key: pub, Now: func() time.Time { return now }}
	with := func(k string, val any) string {
		c := good()
		if val == nil {
			delete(c, k)
		} else {
			c[k] = val
		}
		return sign(key, "artifact-1", c)
	}
	valid := sign(key, "artifact-1", good())
	parts := strings.Split(valid, ".")
	tamperedClaims := good()
	tamperedClaims["pathops_application"] = "22222222-2222-4222-8222-222222222222"
	tc, _ := json.Marshal(tamperedClaims)
	for name, tok := range map[string]string{
		"expired":              with("exp", now.Unix()-31),
		"not yet valid":        with("nbf", now.Unix()+60),
		"wrong audience":       with("aud", "zot"),
		"wrong issuer":         with("iss", "https://dex.other-cell.example/artifacts"),
		"registry token":       with("iss", "https://dex.cell.example/registry"),
		"no application":       with("pathops_application", nil),
		"application not uuid": with("pathops_application", "../b"),
		"no operations":        with("pathops_operations", nil),
		"unknown operation":    with("pathops_operations", []string{"read", "delete"}),
		"no key prefix":        with("pathops_key_prefix", nil),
		"another app's prefix": with("pathops_key_prefix", "applications/22222222-2222-4222-8222-222222222222/deliveries/"),
		"application root":     with("pathops_key_prefix", "applications/"+appA+"/"),
		"prefix not a dir":     with("pathops_key_prefix", "applications/"+appA+"/deliveries"),
		"prefix escapes":       with("pathops_key_prefix", "applications/"+appA+"/../x/"),
		"prefix outside":       with("pathops_key_prefix", "shared/"),
		"no exp":               with("exp", nil),
		"lifetime over 5m":     with("exp", now.Unix()+3600),
		"no subject":           with("sub", nil),
		"another key":          sign(other, "artifact-1", good()),
		"another kid":          sign(key, "registry-1", good()),
		"tampered claims":      parts[0] + "." + base64.RawURLEncoding.EncodeToString(tc) + "." + parts[2],
		"no signature":         parts[0] + "." + parts[1] + ".",
		"garbage":              "not-a-token",
	} {
		if _, err := v.Verify(tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A token whose header claims another algorithm is not parsed.
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"artifact-1"}`))
	if _, err := v.Verify(h + "." + parts[1] + "." + parts[2]); !errors.Is(err, ErrInvalid) {
		t.Errorf("HS256: %v", err)
	}
}

func TestAllows(t *testing.T) {
	p := Principal{Operations: []string{OpRead}}
	if !p.Allows(OpRead) || p.Allows(OpWrite) {
		t.Fatal(p)
	}
}

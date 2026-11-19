// Package workload verifies the Artifact Store tokens the Cell's Dex issues
// through its generic workload token exchange (Decisions 0061, 0065; Dex
// patch 0006, workloadTokenExchange, output pathops-artifact-store).
//
// The caller is a real workload: today the Tenant Control Plane itself, which
// stores a failed build's evidence; later the environment Evidence Collector.
// It exchanges its own Kubernetes ServiceAccount token, together with an
// actor token of the Tenant CP that decides the authorization, for a
// short-lived JWT signed with Dex's dedicated artifact key (EdDSA):
//
//	{"iss": <artifact issuer>, "aud": <store audience>, "sub": <ServiceAccount>,
//	 "iat", "nbf", "exp", "jti",
//	 "pathops_application": <application id>,
//	 "pathops_operations": ["read", "write"],
//	 "pathops_key_prefix": "applications/<application id>/<scope>/"}
//
// Dex copies the pathops_* claims from the Tenant CP's authorization without
// interpreting them. The store verifies the token locally, with no call to
// Dex or the Kubernetes API: the signature with the configured public key
// (and its kid), the issuer, the audience, the validity window and the
// PathOps claims. The Application and the key prefix are read from the token
// only; a request never names them. The prefix is a directory strictly inside
// the Application's (e.g. one DeliveryRun's), so a token reaches neither
// another Application nor another scope of its own.
package workload

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/PathOps/pathops-artifact-store/internal/key"
)

// Operations a token may carry.
const (
	OpRead  = "read"
	OpWrite = "write"
)

// leeway tolerates clock skew between Dex and the store.
const leeway = 30 * time.Second

// maxLifetime bounds exp-iat: Dex issues at most 5 minutes.
const maxLifetime = 5 * time.Minute

var (
	// ErrInvalid: the token is malformed, forged, expired, not yet valid, of
	// another issuer or audience, or lacks a valid PathOps claim.
	ErrInvalid = errors.New("invalid artifact token")
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Principal is a verified workload.
type Principal struct {
	Subject     string
	Application string
	Operations  []string
	// KeyPrefix bounds every key the token reaches: a directory strictly
	// inside applications/<Application>/, ending with "/".
	KeyPrefix string
	Expiry    time.Time
}

// Allows reports whether the token carries op.
func (p Principal) Allows(op string) bool { return slices.Contains(p.Operations, op) }

// Covers reports whether the valid key k is inside the token's key prefix.
func (p Principal) Covers(k string) bool { return p.KeyPrefix != "" && key.Within(k, p.KeyPrefix) }

// validPrefix: prefix is applications/<app>/<one or more segments>/.
func validPrefix(prefix, app string) bool {
	return key.ValidatePrefix(prefix, 3) == nil && strings.HasPrefix(prefix, "applications/"+app+"/")
}

// Verifier verifies artifact tokens.
type Verifier struct {
	Issuer   string
	Audience string
	KeyID    string
	Key      ed25519.PublicKey
	Now      func() time.Time
}

// LoadPublicKey reads an Ed25519 public key (PEM, PKIX "PUBLIC KEY").
func LoadPublicKey(file string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s is not a PEM PUBLIC KEY", file)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	pub, ok := k.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 public key", file)
	}
	return pub, nil
}

type claims struct {
	Issuer      string          `json:"iss"`
	Subject     string          `json:"sub"`
	Audience    json.RawMessage `json:"aud"`
	IssuedAt    *int64          `json:"iat"`
	NotBefore   *int64          `json:"nbf"`
	Expiry      *int64          `json:"exp"`
	Application string          `json:"pathops_application"`
	Operations  []string        `json:"pathops_operations"`
	KeyPrefix   string          `json:"pathops_key_prefix"`
}

// Verify returns the token's principal, or an error wrapping ErrInvalid.
func (v *Verifier) Verify(raw string) (Principal, error) {
	tok, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(tok.Signatures) != 1 || tok.Signatures[0].Header.KeyID != v.KeyID {
		return Principal{}, fmt.Errorf("%w: not signed with key %s", ErrInvalid, v.KeyID)
	}
	payload, err := tok.Verify(v.Key)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: signature", ErrInvalid)
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Principal{}, fmt.Errorf("%w: claims", ErrInvalid)
	}
	now := v.Now()
	switch {
	case c.Issuer != v.Issuer:
		return Principal{}, fmt.Errorf("%w: issuer %q", ErrInvalid, c.Issuer)
	case !audience(c.Audience, v.Audience):
		return Principal{}, fmt.Errorf("%w: audience", ErrInvalid)
	case c.Expiry == nil || c.IssuedAt == nil:
		return Principal{}, fmt.Errorf("%w: exp and iat are required", ErrInvalid)
	case now.After(time.Unix(*c.Expiry, 0).Add(leeway)):
		return Principal{}, fmt.Errorf("%w: expired", ErrInvalid)
	case c.NotBefore != nil && now.Add(leeway).Before(time.Unix(*c.NotBefore, 0)):
		return Principal{}, fmt.Errorf("%w: not yet valid", ErrInvalid)
	case time.Unix(*c.Expiry, 0).Sub(time.Unix(*c.IssuedAt, 0)) > maxLifetime:
		return Principal{}, fmt.Errorf("%w: lifetime over %s", ErrInvalid, maxLifetime)
	case !uuidRe.MatchString(c.Application):
		return Principal{}, fmt.Errorf("%w: no Application", ErrInvalid)
	case len(c.Operations) == 0 || slices.ContainsFunc(c.Operations, func(o string) bool { return o != OpRead && o != OpWrite }):
		return Principal{}, fmt.Errorf("%w: operations", ErrInvalid)
	case !validPrefix(c.KeyPrefix, c.Application):
		return Principal{}, fmt.Errorf("%w: key prefix", ErrInvalid)
	case c.Subject == "":
		return Principal{}, fmt.Errorf("%w: no subject", ErrInvalid)
	}
	return Principal{Subject: c.Subject, Application: c.Application, Operations: c.Operations, KeyPrefix: c.KeyPrefix,
		Expiry: time.Unix(*c.Expiry, 0)}, nil
}

// audience: "aud" is the expected string, or an array containing it.
func audience(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && slices.Contains(many, want)
}

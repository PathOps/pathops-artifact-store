// Package workload verifies the Artifact Store tokens Dex issues to
// Application workloads (Decision 0061; Dex patch 0007, artifactTokens).
//
// A workload (the Tenant Control Plane acting for one Application) exchanges a
// Kubernetes token of the Application's <app>-artifact ServiceAccount at Dex
// for a short-lived JWT signed with Dex's dedicated artifact key (EdDSA):
//
//	{"iss": <artifact issuer>, "aud": <store audience>, "sub": <ServiceAccount>,
//	 "iat", "nbf", "exp", "jti",
//	 "pathops_application": <application id>,
//	 "pathops_operations": ["read", "write"]}
//
// The store verifies it locally, with no call to Dex or the Kubernetes API:
// the signature with the configured public key (and its kid), the issuer, the
// audience, the validity window and both PathOps claims. The Application is
// read from the token only; a request never names it.
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
	"time"

	jose "github.com/go-jose/go-jose/v4"
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
	Expiry      time.Time
}

// Allows reports whether the token carries op.
func (p Principal) Allows(op string) bool { return slices.Contains(p.Operations, op) }

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
	case c.Subject == "":
		return Principal{}, fmt.Errorf("%w: no subject", ErrInvalid)
	}
	return Principal{Subject: c.Subject, Application: c.Application, Operations: c.Operations, Expiry: time.Unix(*c.Expiry, 0)}, nil
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

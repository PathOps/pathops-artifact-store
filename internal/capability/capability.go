// Package capability issues and verifies attempt-scoped capabilities.
//
// A capability says: the workload identity Subject may perform Operations on
// keys under Prefix until Expires. The store signs it (HMAC-SHA256 with a key
// only the store holds) when its privileged caller (the Tenant Control Plane)
// asks, and verifies it on every request together with the caller's own
// authenticated identity. It is bound to that identity: without a valid
// workload token of Subject it grants nothing, so it can travel as an ordinary
// parameter (for example of a Tekton PipelineRun). It never carries an
// application id chosen by the workload: the privileged caller derives the
// prefix from the Application/Run/Step/Attempt it executes.
//
// Encoding: "v1." + base64url(JSON claims) + "." + base64url(HMAC).
package capability

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// Operations a capability may grant.
const (
	OpPut  = "put"
	OpGet  = "get"
	OpStat = "stat"
)

// MaxLength bounds an encoded capability.
const MaxLength = 4096

var (
	ErrInvalid = errors.New("invalid capability")
	ErrExpired = errors.New("expired capability")
)

// Claims are the content of a capability.
type Claims struct {
	Subject    string   `json:"sub"`
	Prefix     string   `json:"prefix"`
	Operations []string `json:"ops"`
	IssuedAt   int64    `json:"iat"`
	Expires    int64    `json:"exp"`
}

// Allows reports whether the claims allow op.
func (c Claims) Allows(op string) bool { return slices.Contains(c.Operations, op) }

// ValidOperations reports whether ops is a non-empty set of known operations.
func ValidOperations(ops []string) bool {
	if len(ops) == 0 || len(ops) > 3 {
		return false
	}
	for i, op := range ops {
		if op != OpPut && op != OpGet && op != OpStat || slices.Contains(ops[:i], op) {
			return false
		}
	}
	return true
}

// Signer issues and verifies capabilities with one key.
type Signer struct {
	key []byte
	now func() time.Time
}

// NewSigner uses a key of at least 32 bytes.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < 32 {
		return nil, errors.New("capability key shorter than 32 bytes")
	}
	return &Signer{key: key, now: time.Now}, nil
}

// LoadOrCreateKey reads the key file, creating it (0600, 32 random bytes) if
// it does not exist. It lives with the stored objects, so capabilities stay
// valid across restarts.
func LoadOrCreateKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return b, err
}

// Issue signs claims valid for ttl from now.
func (s *Signer) Issue(subject, prefix string, ops []string, ttl time.Duration) (string, Claims, error) {
	now := s.now()
	c := Claims{Subject: subject, Prefix: prefix, Operations: ops, IssuedAt: now.Unix(), Expires: now.Add(ttl).Unix()}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", Claims{}, err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return "v1." + p + "." + base64.RawURLEncoding.EncodeToString(s.mac(p)), c, nil
}

// Verify checks the signature and expiry of an encoded capability.
func (s *Signer) Verify(encoded string) (Claims, error) {
	if len(encoded) > MaxLength {
		return Claims{}, ErrInvalid
	}
	rest, ok := strings.CutPrefix(encoded, "v1.")
	if !ok {
		return Claims{}, ErrInvalid
	}
	p, sig, ok := strings.Cut(rest, ".")
	if !ok {
		return Claims{}, ErrInvalid
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(p)) {
		return Claims{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil || c.Subject == "" || c.Prefix == "" || !ValidOperations(c.Operations) {
		return Claims{}, fmt.Errorf("%w: malformed claims", ErrInvalid)
	}
	if s.now().Unix() >= c.Expires {
		return Claims{}, ErrExpired
	}
	return c, nil
}

func (s *Signer) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("pathops-artifact-store capability v1\x00"))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

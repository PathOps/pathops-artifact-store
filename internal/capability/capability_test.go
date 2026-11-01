package capability

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sub = "system:serviceaccount:app-a:app-a-build"

func signer(t *testing.T, now *time.Time) *Signer {
	t.Helper()
	s, err := NewSigner(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return *now }
	return s
}

func TestIssueVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := signer(t, &now)
	enc, c, err := s.Issue(sub, "applications/a/runs/r/steps/s/attempts/1/", []string{OpPut}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Verify(enc)
	if err != nil || got.Subject != sub || got.Prefix != c.Prefix || !got.Allows(OpPut) || got.Allows(OpGet) {
		t.Fatal(got, err)
	}

	now = now.Add(time.Hour)
	if _, err := s.Verify(enc); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	now = now.Add(-time.Hour)

	// Altered claims (another prefix) with the original signature.
	parts := strings.Split(enc, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	forged := strings.Replace(string(payload), "applications/a/", "applications/b/", 1)
	if _, err := s.Verify("v1." + base64.RawURLEncoding.EncodeToString([]byte(forged)) + "." + parts[2]); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	// Another store's key.
	other, _ := NewSigner(bytes.Repeat([]byte{8}, 32))
	if _, err := other.Verify(enc); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "v1.", "v2." + parts[1] + "." + parts[2], "v1." + parts[1], strings.Repeat("a", MaxLength+1)} {
		if _, err := s.Verify(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestValidOperations(t *testing.T) {
	if !ValidOperations([]string{OpPut, OpGet, OpStat}) || ValidOperations(nil) || ValidOperations([]string{"delete"}) ||
		ValidOperations([]string{OpPut, OpPut}) {
		t.Fatal()
	}
}

func TestKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "capability.key")
	a, err := LoadOrCreateKey(p)
	if err != nil || len(a) != 32 {
		t.Fatal(err)
	}
	b, err := LoadOrCreateKey(p)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("the key changed across restarts")
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}
	if _, err := NewSigner(a[:16]); err == nil {
		t.Fatal("short key accepted")
	}
}

package key

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, k := range []string{
		"a",
		"applications/app-a/runs/run-1/steps/WAIT_BUILD/attempts/1/bundle.tar.gz",
		"x.y_z-1",
		strings.Repeat("a/", MaxSegments-1) + "a",
	} {
		if err := Validate(k); err != nil {
			t.Errorf("%q: %v", k, err)
		}
	}
	for _, k := range []string{
		"", "/", "/a", "a/", "a//b", ".", "..", "a/../b", "a/./b", "../a", "a/..",
		".hidden", "-a", "_a", "a\\b", "a%2Fb", "a%2e%2e", "a b", "a\x00b", "é",
		"a/@data", strings.Repeat("a", 129), strings.Repeat("a/", MaxSegments) + "a",
		strings.Repeat("a", MaxLength+1),
	} {
		if Validate(k) == nil {
			t.Errorf("%q accepted", k)
		}
	}
}

func TestPrefix(t *testing.T) {
	p := "applications/app-a/runs/r1/steps/s/attempts/1/"
	if err := ValidatePrefix(p, 2); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "/", "applications", "applications/", "applications//", "../x/"} {
		if ValidatePrefix(bad, 2) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !Within(p+"bundle.tar.gz", p) || Within(p, p) || Within("applications/app-b/x", p) ||
		Within("applications/app-a/runs/r1/steps/s/attempts/10/x", p) {
		t.Fatal("Within")
	}
}

// Package key validates object keys and key prefixes.
//
// A key is one or more "/"-separated segments. A segment starts with a letter
// or digit and continues with letters, digits, ".", "_" or "-" (at most 128
// bytes), so ".", "..", empty segments, absolute paths, backslashes and
// percent-encoding cannot be expressed. The same rule makes every key a safe
// relative path for a filesystem backend; backends still confine themselves.
package key

import (
	"errors"
	"strings"
)

const (
	// MaxLength is the maximum length of a key in bytes.
	MaxLength = 1024
	// MaxSegments is the maximum number of segments of a key.
	MaxSegments = 16
	maxSegment  = 128
)

// ErrInvalid is returned for a key or prefix that does not follow the rule.
var ErrInvalid = errors.New("invalid key")

// Validate checks k.
func Validate(k string) error {
	if k == "" || len(k) > MaxLength {
		return ErrInvalid
	}
	segs := strings.Split(k, "/")
	if len(segs) > MaxSegments {
		return ErrInvalid
	}
	for _, s := range segs {
		if !validSegment(s) {
			return ErrInvalid
		}
	}
	return nil
}

// ValidatePrefix checks p: the segments of a key followed by "/", at least
// minSegments of them.
func ValidatePrefix(p string, minSegments int) error {
	k, ok := strings.CutSuffix(p, "/")
	if !ok || Validate(k) != nil || strings.Count(k, "/")+1 < minSegments {
		return ErrInvalid
	}
	return nil
}

// Within reports whether the valid key k is under the valid prefix p.
func Within(k, p string) bool {
	return strings.HasPrefix(k, p) && len(k) > len(p)
}

func validSegment(s string) bool {
	if s == "" || len(s) > maxSegment || !alnum(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !alnum(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func alnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

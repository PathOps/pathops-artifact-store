// Package config reads the Artifact Store's runtime configuration from the
// environment. Every value is validated at start; an invalid configuration
// stops the process before it listens.
package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config is the runtime configuration.
type Config struct {
	ListenAddress  string        // LISTEN_ADDRESS, default :8443
	StoreName      string        // PATHOPS_ARTIFACT_STORE_NAME: name in references (the Cell id)
	DataDir        string        // PATHOPS_ARTIFACT_STORE_DATA_DIR, default /data (the PVC)
	Audience       string        // PATHOPS_ARTIFACT_STORE_AUDIENCE, default pathops-artifact-store
	Admins         []string      // PATHOPS_ARTIFACT_STORE_ADMINS: privileged ServiceAccount subjects, comma-separated
	TLSCertFile    string        // TLS_CERT_FILE
	TLSKeyFile     string        // TLS_KEY_FILE
	MaxObjectBytes int64         // PATHOPS_ARTIFACT_STORE_MAX_OBJECT_BYTES, default 4 GiB
	MaxTTL         time.Duration // PATHOPS_ARTIFACT_STORE_MAX_CAPABILITY_TTL, default 6h
	RequestTimeout time.Duration // PATHOPS_ARTIFACT_STORE_REQUEST_TIMEOUT, default 30m
}

var (
	nameRe    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	subjectRe = regexp.MustCompile(`^system:serviceaccount:[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?:[a-z0-9]([-.a-z0-9]{0,251}[a-z0-9])?$`)
)

// Load reads the configuration through getenv.
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		ListenAddress: or(getenv("LISTEN_ADDRESS"), ":8443"),
		StoreName:     getenv("PATHOPS_ARTIFACT_STORE_NAME"),
		DataDir:       or(getenv("PATHOPS_ARTIFACT_STORE_DATA_DIR"), "/data"),
		Audience:      or(getenv("PATHOPS_ARTIFACT_STORE_AUDIENCE"), "pathops-artifact-store"),
		TLSCertFile:   getenv("TLS_CERT_FILE"),
		TLSKeyFile:    getenv("TLS_KEY_FILE"),
	}
	var errs []error
	if !nameRe.MatchString(c.StoreName) {
		errs = append(errs, errors.New("PATHOPS_ARTIFACT_STORE_NAME must be a DNS label (the Cell id)"))
	}
	for _, a := range strings.Split(getenv("PATHOPS_ARTIFACT_STORE_ADMINS"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			if !subjectRe.MatchString(a) {
				errs = append(errs, fmt.Errorf("PATHOPS_ARTIFACT_STORE_ADMINS: %q is not system:serviceaccount:<namespace>:<name>", a))
			}
			c.Admins = append(c.Admins, a)
		}
	}
	if len(c.Admins) == 0 {
		errs = append(errs, errors.New("PATHOPS_ARTIFACT_STORE_ADMINS must name at least one privileged ServiceAccount"))
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		errs = append(errs, errors.New("TLS_CERT_FILE and TLS_KEY_FILE are required (the store serves HTTPS only)"))
	}
	var err error
	if c.MaxObjectBytes, err = bytesOr(getenv("PATHOPS_ARTIFACT_STORE_MAX_OBJECT_BYTES"), 4<<30); err != nil {
		errs = append(errs, err)
	}
	if c.MaxTTL, err = durationOr(getenv("PATHOPS_ARTIFACT_STORE_MAX_CAPABILITY_TTL"), 6*time.Hour); err != nil {
		errs = append(errs, err)
	}
	if c.RequestTimeout, err = durationOr(getenv("PATHOPS_ARTIFACT_STORE_REQUEST_TIMEOUT"), 30*time.Minute); err != nil {
		errs = append(errs, err)
	}
	return c, errors.Join(errs...)
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func bytesOr(v string, def int64) (int64, error) {
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid byte count %q", v)
	}
	return n, nil
}

func durationOr(v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", v)
	}
	return d, nil
}

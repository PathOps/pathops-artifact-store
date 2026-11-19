// Package config reads the Artifact Store's runtime configuration from the
// environment. Every value is validated at start; an invalid configuration
// stops the process before it listens.
package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
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
	TLSCertFile    string        // TLS_CERT_FILE
	TLSKeyFile     string        // TLS_KEY_FILE
	MaxObjectBytes int64         // PATHOPS_ARTIFACT_STORE_MAX_OBJECT_BYTES, default 4 GiB
	RequestTimeout time.Duration // PATHOPS_ARTIFACT_STORE_REQUEST_TIMEOUT, default 30m

	// Workload tokens (Dex workloadTokenExchange, output pathops-artifact-store).
	TokenIssuer        string // PATHOPS_ARTIFACT_STORE_TOKEN_ISSUER
	TokenAudience      string // PATHOPS_ARTIFACT_STORE_TOKEN_AUDIENCE, default pathops-artifact-store
	TokenKeyID         string // PATHOPS_ARTIFACT_STORE_TOKEN_KEY_ID
	TokenPublicKeyFile string // PATHOPS_ARTIFACT_STORE_TOKEN_PUBLIC_KEY_FILE (PEM, Ed25519)

	// People (Dex OIDC).
	PublicURL        string        // PATHOPS_ARTIFACT_STORE_PUBLIC_URL: https://<host>
	OIDCIssuer       string        // PATHOPS_ARTIFACT_STORE_OIDC_ISSUER: the Cell's Dex
	OIDCClientID     string        // PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_ID
	OIDCSecretFile   string        // PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_SECRET_FILE
	OIDCCAFile       string        // PATHOPS_ARTIFACT_STORE_OIDC_CA_FILE: optional roots for Dex (the Cell CA)
	AdminEmails      []string      // PATHOPS_ARTIFACT_STORE_ADMIN_EMAILS: the Cell admin, comma-separated
	OIDCHTTPSTimeout time.Duration // Dex requests, 10 s
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Load reads the configuration through getenv.
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		ListenAddress:      or(getenv("LISTEN_ADDRESS"), ":8443"),
		StoreName:          getenv("PATHOPS_ARTIFACT_STORE_NAME"),
		DataDir:            or(getenv("PATHOPS_ARTIFACT_STORE_DATA_DIR"), "/data"),
		TLSCertFile:        getenv("TLS_CERT_FILE"),
		TLSKeyFile:         getenv("TLS_KEY_FILE"),
		TokenIssuer:        getenv("PATHOPS_ARTIFACT_STORE_TOKEN_ISSUER"),
		TokenAudience:      or(getenv("PATHOPS_ARTIFACT_STORE_TOKEN_AUDIENCE"), "pathops-artifact-store"),
		TokenKeyID:         getenv("PATHOPS_ARTIFACT_STORE_TOKEN_KEY_ID"),
		TokenPublicKeyFile: getenv("PATHOPS_ARTIFACT_STORE_TOKEN_PUBLIC_KEY_FILE"),
		PublicURL:          strings.TrimSuffix(getenv("PATHOPS_ARTIFACT_STORE_PUBLIC_URL"), "/"),
		OIDCIssuer:         getenv("PATHOPS_ARTIFACT_STORE_OIDC_ISSUER"),
		OIDCClientID:       getenv("PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_ID"),
		OIDCSecretFile:     getenv("PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_SECRET_FILE"),
		OIDCCAFile:         getenv("PATHOPS_ARTIFACT_STORE_OIDC_CA_FILE"),
		OIDCHTTPSTimeout:   10 * time.Second,
	}
	var errs []error
	if !nameRe.MatchString(c.StoreName) {
		errs = append(errs, errors.New("PATHOPS_ARTIFACT_STORE_NAME must be a DNS label (the Cell id)"))
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		errs = append(errs, errors.New("TLS_CERT_FILE and TLS_KEY_FILE are required (the store serves HTTPS only)"))
	}
	for name, v := range map[string]string{"PATHOPS_ARTIFACT_STORE_TOKEN_ISSUER": c.TokenIssuer, "PATHOPS_ARTIFACT_STORE_OIDC_ISSUER": c.OIDCIssuer} {
		if !httpsURL(v) {
			errs = append(errs, fmt.Errorf("%s must be an https URL", name))
		}
	}
	if u, err := url.Parse(c.PublicURL); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
		errs = append(errs, errors.New("PATHOPS_ARTIFACT_STORE_PUBLIC_URL must be https://<host>"))
	}
	if c.TokenKeyID == "" || c.TokenPublicKeyFile == "" {
		errs = append(errs, errors.New("PATHOPS_ARTIFACT_STORE_TOKEN_KEY_ID and PATHOPS_ARTIFACT_STORE_TOKEN_PUBLIC_KEY_FILE are required"))
	}
	if c.OIDCClientID == "" || c.OIDCSecretFile == "" {
		errs = append(errs, errors.New("PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_ID and PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_SECRET_FILE are required"))
	}
	for _, e := range strings.Split(getenv("PATHOPS_ARTIFACT_STORE_ADMIN_EMAILS"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			if a, err := mail.ParseAddress(e); err != nil || a.Address != e {
				errs = append(errs, fmt.Errorf("PATHOPS_ARTIFACT_STORE_ADMIN_EMAILS: %q is not an email address", e))
			}
			c.AdminEmails = append(c.AdminEmails, e)
		}
	}
	if len(c.AdminEmails) == 0 {
		errs = append(errs, errors.New("PATHOPS_ARTIFACT_STORE_ADMIN_EMAILS must name the Cell admin"))
	}
	var err error
	if c.MaxObjectBytes, err = bytesOr(getenv("PATHOPS_ARTIFACT_STORE_MAX_OBJECT_BYTES"), 4<<30); err != nil {
		errs = append(errs, err)
	}
	if c.RequestTimeout, err = durationOr(getenv("PATHOPS_ARTIFACT_STORE_REQUEST_TIMEOUT"), 30*time.Minute); err != nil {
		errs = append(errs, err)
	}
	return c, errors.Join(errs...)
}

func httpsURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != ""
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

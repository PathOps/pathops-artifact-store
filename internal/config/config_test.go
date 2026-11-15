package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func valid() map[string]string {
	return map[string]string{
		"PATHOPS_ARTIFACT_STORE_NAME":                    "dev",
		"TLS_CERT_FILE":                                  "/tls/tls.crt",
		"TLS_KEY_FILE":                                   "/tls/tls.key",
		"PATHOPS_ARTIFACT_STORE_TOKEN_ISSUER":            "https://dex-dev.demo.pathops.io/artifacts",
		"PATHOPS_ARTIFACT_STORE_TOKEN_KEY_ID":            "artifact-1",
		"PATHOPS_ARTIFACT_STORE_TOKEN_PUBLIC_KEY_FILE":   "/keys/artifact.pub",
		"PATHOPS_ARTIFACT_STORE_PUBLIC_URL":              "https://artifacts-dev.demo.pathops.io",
		"PATHOPS_ARTIFACT_STORE_OIDC_ISSUER":             "https://dex-dev.demo.pathops.io",
		"PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_ID":          "pathops-artifact-store-web",
		"PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_SECRET_FILE": "/oidc/client-secret",
		"PATHOPS_ARTIFACT_STORE_ADMIN_EMAILS":            "admin-dev@demo.pathops.io",
	}
}

func TestLoad(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil || c.ListenAddress != ":8443" || c.DataDir != "/data" || c.TokenAudience != "pathops-artifact-store" ||
		len(c.AdminEmails) != 1 || c.MaxObjectBytes != 4<<30 || c.RequestTimeout != 30*time.Minute {
		t.Fatal(c, err)
	}
}

func TestLoadRejects(t *testing.T) {
	m := valid()
	m["PATHOPS_ARTIFACT_STORE_NAME"] = "Dev_Cell"
	m["PATHOPS_ARTIFACT_STORE_MAX_OBJECT_BYTES"] = "-1"
	m["PATHOPS_ARTIFACT_STORE_REQUEST_TIMEOUT"] = "soon"
	m["PATHOPS_ARTIFACT_STORE_TOKEN_ISSUER"] = "http://dex/artifacts"
	m["PATHOPS_ARTIFACT_STORE_PUBLIC_URL"] = "https://artifacts.example/path"
	m["PATHOPS_ARTIFACT_STORE_ADMIN_EMAILS"] = "not an email"
	delete(m, "TLS_CERT_FILE")
	delete(m, "PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_SECRET_FILE")
	_, err := Load(env(m))
	for _, want := range []string{"NAME", "TLS_CERT_FILE", "byte count", `duration "soon"`, "TOKEN_ISSUER must be an https URL",
		"PUBLIC_URL", "not an email", "CLIENT_SECRET_FILE"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	m = valid()
	delete(m, "PATHOPS_ARTIFACT_STORE_ADMIN_EMAILS")
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "the Cell admin") {
		t.Fatal(err)
	}
}

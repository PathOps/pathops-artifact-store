package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoad(t *testing.T) {
	c, err := Load(env(map[string]string{
		"PATHOPS_ARTIFACT_STORE_NAME":   "dev",
		"PATHOPS_ARTIFACT_STORE_ADMINS": "system:serviceaccount:artifacts:artifact-store-admin, system:serviceaccount:tcp:tenant-control-plane",
		"TLS_CERT_FILE":                 "/tls/tls.crt", "TLS_KEY_FILE": "/tls/tls.key",
	}))
	if err != nil || c.ListenAddress != ":8443" || c.DataDir != "/data" || c.Audience != "pathops-artifact-store" || len(c.Admins) != 2 ||
		c.MaxObjectBytes != 4<<30 || c.MaxTTL != 6*time.Hour || c.RequestTimeout != 30*time.Minute {
		t.Fatal(c, err)
	}
}

func TestLoadRejects(t *testing.T) {
	_, err := Load(env(map[string]string{
		"PATHOPS_ARTIFACT_STORE_NAME":             "Dev_Cell",
		"PATHOPS_ARTIFACT_STORE_ADMINS":           "alice@example.com",
		"PATHOPS_ARTIFACT_STORE_MAX_OBJECT_BYTES": "-1",
		"PATHOPS_ARTIFACT_STORE_REQUEST_TIMEOUT":  "soon",
	}))
	for _, want := range []string{"NAME", "alice@example.com", "TLS_CERT_FILE", "byte count", `duration "soon"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	if _, err := Load(env(map[string]string{"PATHOPS_ARTIFACT_STORE_NAME": "dev", "TLS_CERT_FILE": "c", "TLS_KEY_FILE": "k"})); err == nil ||
		!strings.Contains(err.Error(), "at least one privileged") {
		t.Fatal(err)
	}
}

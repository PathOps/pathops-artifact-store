package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PathOps/pathops-artifact-store/internal/auth"
	"github.com/PathOps/pathops-artifact-store/internal/capability"
	"github.com/PathOps/pathops-artifact-store/internal/store/fsstore"
)

const (
	tcp    = "system:serviceaccount:pathops-tcp:tenant-control-plane"
	appA   = "system:serviceaccount:app-a:app-a-build"
	appB   = "system:serviceaccount:app-b:app-b-build"
	prefA  = "applications/app-a/runs/run-1/steps/WAIT_BUILD/attempts/1/"
	prefB  = "applications/app-b/runs/run-9/steps/WAIT_BUILD/attempts/1/"
	bundle = "bundle.tar.gz"
)

// fakeAuth maps tokens to subjects; "down" means the API server is unreachable.
type fakeAuth map[string]string

func (f fakeAuth) Authenticate(_ context.Context, tok string) (auth.Principal, error) {
	if tok == "down" {
		return auth.Principal{}, auth.ErrUnavailable
	}
	if s, ok := f[tok]; ok {
		return auth.Principal{Subject: s}, nil
	}
	return auth.Principal{}, auth.ErrUnauthenticated
}

type env struct {
	t   *testing.T
	srv *httptest.Server
	log bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := fsstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	signer, _ := capability.NewSigner(bytes.Repeat([]byte{1}, 32))
	e := &env{t: t}
	s := &Server{Name: "dev", Store: st, Auth: fakeAuth{"tcp": tcp, "a": appA, "b": appB}, Signer: signer,
		Admins: map[string]bool{tcp: true}, MaxObjectBytes: 1 << 20, MaxTTL: time.Hour, RequestTimeout: time.Minute,
		Log: slog.New(slog.NewJSONHandler(&e.log, nil))}
	e.srv = httptest.NewTLSServer(s)
	t.Cleanup(e.srv.Close)
	return e
}

// do sends a request; path is sent as written (no cleaning).
func (e *env) do(method, path, token, capab string, body []byte, hdr ...string) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if body == nil {
		req.Body = nil
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if capab != "" {
		req.Header.Set(HeaderCapability, capab)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

func (e *env) capability(subject, prefix string, ttl int64, ops ...string) string {
	e.t.Helper()
	body, _ := json.Marshal(CapabilityRequest{Subject: subject, Prefix: prefix, Operations: ops, TTLSeconds: ttl})
	resp, b := e.do(http.MethodPost, "/v1/capabilities", "tcp", "", body)
	if resp.StatusCode != http.StatusCreated {
		e.t.Fatalf("issue: %d %s", resp.StatusCode, b)
	}
	var c CapabilityResponse
	_ = json.Unmarshal(b, &c)
	return c.Capability
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestAttemptScopedFlow(t *testing.T) {
	e := newEnv(t)
	content := bytes.Repeat([]byte("evidence "), 1000)
	capA := e.capability(appA, prefA, 600, capability.OpPut, capability.OpGet)

	resp, b := e.do(http.MethodPut, "/v1/objects/"+prefA+bundle, "a", capA, content,
		"Content-Type", "application/gzip", HeaderSHA256, sum(content), HeaderMetadata, `{"producer":"tekton"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var put PutResponse
	_ = json.Unmarshal(b, &put)
	if put.Ref != "pathops-artifact://dev/"+prefA+bundle || put.SHA256 != sum(content) || put.Size != int64(len(content)) || put.CreatedBy != appA {
		t.Fatalf("%s", b)
	}

	resp, got := e.do(http.MethodGet, "/v1/objects/"+prefA+bundle, "a", capA, nil)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, content) || resp.Header.Get(HeaderSHA256) != sum(content) ||
		resp.Header.Get("Content-Type") != "application/gzip" || resp.Header.Get(HeaderMetadata) != `{"producer":"tekton"}` {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	// HEAD needs no body and is allowed by get.
	if resp, b := e.do(http.MethodHead, "/v1/objects/"+prefA+bundle, "a", capA, nil); resp.StatusCode != http.StatusOK || len(b) != 0 ||
		resp.ContentLength != int64(len(content)) {
		t.Fatal(resp.StatusCode)
	}
	// The privileged identity reads by the stored reference, with no capability.
	key := strings.TrimPrefix(put.Ref, "pathops-artifact://dev/")
	if resp, got := e.do(http.MethodGet, "/v1/objects/"+key, "tcp", "", nil); resp.StatusCode != http.StatusOK || !bytes.Equal(got, content) {
		t.Fatal(resp.StatusCode)
	}
	// A retry with the same content is the same object; other content is a conflict.
	if resp, _ := e.do(http.MethodPut, "/v1/objects/"+prefA+bundle, "a", capA, content); resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(http.MethodPut, "/v1/objects/"+prefA+bundle, "a", capA, []byte("other")); resp.StatusCode != http.StatusConflict {
		t.Fatal(resp.StatusCode)
	}
	// Only the privileged identity deletes.
	if resp, _ := e.do(http.MethodDelete, "/v1/objects/"+prefA+bundle, "a", capA, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(http.MethodDelete, "/v1/objects/"+prefA+bundle, "tcp", "", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(http.MethodGet, "/v1/objects/"+prefA+bundle, "tcp", "", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatal(resp.StatusCode)
	}

	// Nothing a client sent as a secret reaches the log.
	if strings.Contains(e.log.String(), capA) || strings.Contains(e.log.String(), "Bearer") {
		t.Fatal("a credential was logged")
	}
}

func TestIsolation(t *testing.T) {
	e := newEnv(t)
	capA := e.capability(appA, prefA, 600, capability.OpPut, capability.OpGet)
	capB := e.capability(appB, prefB, 600, capability.OpPut, capability.OpGet)
	if resp, _ := e.do(http.MethodPut, "/v1/objects/"+prefB+bundle, "b", capB, []byte("b's evidence")); resp.StatusCode != http.StatusCreated {
		t.Fatal(resp.StatusCode)
	}
	for name, c := range map[string]struct {
		method, path, token, capab string
		want                       int
	}{
		"A reads B's object":                    {http.MethodGet, prefB + bundle, "a", capA, 403},
		"A writes under B's prefix":             {http.MethodPut, prefB + "x", "a", capA, 403},
		"A uses B's (stolen) capability":        {http.MethodGet, prefB + bundle, "a", capB, 403},
		"A writes to another attempt":           {http.MethodPut, "applications/app-a/runs/run-1/steps/WAIT_BUILD/attempts/2/x", "a", capA, 403},
		"A writes to attempt 10 (prefix trick)": {http.MethodPut, "applications/app-a/runs/run-1/steps/WAIT_BUILD/attempts/10/x", "a", capA, 403},
		"A without a capability":                {http.MethodPut, prefA + bundle, "a", "", 403},
		"A with a garbage capability":           {http.MethodPut, prefA + bundle, "a", "v1.e30.AAAA", 403},
		"no token":                              {http.MethodGet, prefB + bundle, "", capB, 401},
		"unknown token":                         {http.MethodGet, prefB + bundle, "forged", capB, 401},
		"API server unavailable":                {http.MethodGet, prefB + bundle, "down", capB, 503},
	} {
		if resp, b := e.do(c.method, "/v1/objects/"+c.path, c.token, c.capab, []byte("x")); resp.StatusCode != c.want {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
	// A get-only capability does not allow put.
	ro := e.capability(appA, prefA, 600, capability.OpGet)
	if resp, _ := e.do(http.MethodPut, "/v1/objects/"+prefA+bundle, "a", ro, []byte("x")); resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
}

func TestCapabilityIssuing(t *testing.T) {
	e := newEnv(t)
	// Only the privileged identity issues.
	body, _ := json.Marshal(CapabilityRequest{Subject: appA, Prefix: prefB, Operations: []string{"put"}, TTLSeconds: 60})
	if resp, _ := e.do(http.MethodPost, "/v1/capabilities", "a", "", body); resp.StatusCode != http.StatusForbidden {
		t.Fatal(resp.StatusCode)
	}
	for name, req := range map[string]CapabilityRequest{
		"human subject":       {Subject: "alice@example.com", Prefix: prefA, Operations: []string{"put"}, TTLSeconds: 60},
		"whole store":         {Subject: appA, Prefix: "applications/", Operations: []string{"put"}, TTLSeconds: 60},
		"traversal prefix":    {Subject: appA, Prefix: "applications/../", Operations: []string{"put"}, TTLSeconds: 60},
		"delete operation":    {Subject: appA, Prefix: prefA, Operations: []string{"delete"}, TTLSeconds: 60},
		"too long":            {Subject: appA, Prefix: prefA, Operations: []string{"put"}, TTLSeconds: 7200},
		"privileged subject":  {Subject: tcp, Prefix: prefA, Operations: []string{"put"}, TTLSeconds: 60},
		"no operations":       {Subject: appA, Prefix: prefA, TTLSeconds: 60},
		"prefix without root": {Subject: appA, Prefix: "applications/app-a", Operations: []string{"put"}, TTLSeconds: 60},
	} {
		body, _ := json.Marshal(req)
		if resp, b := e.do(http.MethodPost, "/v1/capabilities", "tcp", "", body); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
	// An expired capability is refused.
	short := e.capability(appA, prefA, 1, capability.OpPut)
	time.Sleep(1100 * time.Millisecond)
	if resp, b := e.do(http.MethodPut, "/v1/objects/"+prefA+bundle, "a", short, []byte("x")); resp.StatusCode != 403 ||
		!strings.Contains(string(b), "expired") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

func TestKeyEscapes(t *testing.T) {
	e := newEnv(t)
	capA := e.capability(appA, prefA, 600, capability.OpPut, capability.OpGet)
	for _, p := range []string{
		prefA + "../../../../../../app-b/runs/run-9/steps/WAIT_BUILD/attempts/1/x",
		prefA + "..%2f..%2fx",
		prefA + "%2e%2e/x",
		prefA + "a//b",
		prefA + "./x",
		prefA + "x?y=1",
		prefA + "@data",
		prefA + ".hidden",
		prefA,
	} {
		if resp, b := e.do(http.MethodPut, "/v1/objects/"+p, "a", capA, []byte("x")); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q: %d %s", p, resp.StatusCode, b)
		}
	}
}

func TestPutLimitsAndValidation(t *testing.T) {
	e := newEnv(t)
	capA := e.capability(appA, prefA, 600, capability.OpPut)
	for name, c := range map[string]struct {
		body []byte
		hdr  []string
		want int
	}{
		"too large":            {make([]byte, 1<<20+1), nil, http.StatusRequestEntityTooLarge},
		"digest mismatch":      {[]byte("x"), []string{HeaderSHA256, sum([]byte("y"))}, http.StatusUnprocessableEntity},
		"bad digest":           {[]byte("x"), []string{HeaderSHA256, "ABC"}, http.StatusBadRequest},
		"bad content type":     {[]byte("x"), []string{"Content-Type", "not a type;;"}, http.StatusBadRequest},
		"bad metadata":         {[]byte("x"), []string{HeaderMetadata, `{"a":1}`}, http.StatusBadRequest},
		"bad metadata key":     {[]byte("x"), []string{HeaderMetadata, `{"a b":"c"}`}, http.StatusBadRequest},
		"metadata not an obj.": {[]byte("x"), []string{HeaderMetadata, `[1]`}, http.StatusBadRequest},
	} {
		if resp, b := e.do(http.MethodPut, "/v1/objects/"+prefA+strings.ReplaceAll(name, " ", "-"), "a", capA, c.body, c.hdr...); resp.StatusCode != c.want {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
	if resp, _ := e.do(http.MethodPost, "/v1/objects/"+prefA+"x", "a", capA, nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(http.MethodGet, "/healthz", "", "", nil); resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
}

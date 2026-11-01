// Package server is the HTTP API of the Artifact Store.
//
//	GET    /healthz                  liveness (no authentication, no API server call)
//	POST   /v1/capabilities          privileged: issue an attempt-scoped capability
//	PUT    /v1/objects/{key}         stream an object in (immutable)
//	GET    /v1/objects/{key}         stream an object out
//	HEAD   /v1/objects/{key}         describe an object
//	DELETE /v1/objects/{key}         privileged: remove an object
//
// Every /v1 request carries "Authorization: Bearer <ServiceAccount token for
// the store's audience>". A privileged subject (the Tenant Control Plane) may
// do everything. Any other workload also needs "X-PathOps-Capability", issued
// for exactly its own subject, whose prefix contains the key and whose
// operations include the request's (put, get, or stat for HEAD).
//
// Keys are taken from the raw request path, never from a cleaned one, so
// "..", "//" and percent-encoding are rejected (400) rather than resolved.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PathOps/pathops-artifact-store/internal/auth"
	"github.com/PathOps/pathops-artifact-store/internal/capability"
	"github.com/PathOps/pathops-artifact-store/internal/key"
	"github.com/PathOps/pathops-artifact-store/internal/store"
)

// Request and response headers.
const (
	HeaderCapability = "X-PathOps-Capability"
	HeaderSHA256     = "X-PathOps-SHA256"
	HeaderMetadata   = "X-PathOps-Metadata"
	HeaderCreatedAt  = "X-PathOps-Created-At"
	objectsPath      = "/v1/objects/"
	maxMetadata      = 2048
	maxMetaEntries   = 16
)

var (
	subjectRe = regexp.MustCompile(`^system:serviceaccount:[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?:[a-z0-9]([-.a-z0-9]{0,251}[a-z0-9])?$`)
	sha256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	metaKeyRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// Server serves the API.
type Server struct {
	Name           string // the store's name in references: pathops-artifact://<Name>/<key>
	Store          store.ArtifactStore
	Auth           auth.Authenticator
	Signer         *capability.Signer
	Admins         map[string]bool // privileged ServiceAccount subjects
	MaxObjectBytes int64
	MaxTTL         time.Duration
	RequestTimeout time.Duration
	Log            *slog.Logger
}

// Ref is the reference of an object: what a caller persists and later reads by.
func (s *Server) Ref(k string) string { return "pathops-artifact://" + s.Name + "/" + k }

// PutResponse is the body of a successful PUT.
type PutResponse struct {
	Ref string `json:"ref"`
	store.Info
}

// CapabilityRequest is the body of POST /v1/capabilities.
type CapabilityRequest struct {
	Subject    string   `json:"subject"`
	Prefix     string   `json:"prefix"`
	Operations []string `json:"operations"`
	TTLSeconds int64    `json:"ttlSeconds"`
}

// CapabilityResponse is its answer.
type CapabilityResponse struct {
	Capability string    `json:"capability"`
	Subject    string    `json:"subject"`
	Prefix     string    `json:"prefix"`
	Operations []string  `json:"operations"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// reqLog collects what one request log line says. It never holds a token or
// a capability.
type reqLog struct {
	op, key, subject, err string
	in                    int64
}

func (s *Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w := &statusWriter{ResponseWriter: rw}
	w.Header().Set("Cache-Control", "no-store")
	l := &reqLog{}
	s.route(w, r, l)
	if r.URL.Path == "/healthz" {
		return
	}
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	s.Log.Info("request", "method", r.Method, "op", l.op, "key", l.key, "subject", l.subject, "status", w.status,
		"bytesIn", l.in, "bytesOut", w.bytes, "durationMs", time.Since(start).Milliseconds(), "error", l.err,
		"processMaxRssKiB", ru.Maxrss, "processCpuMs", (ru.Utime.Nano()+ru.Stime.Nano())/1e6)
}

func (s *Server) route(w *statusWriter, r *http.Request, l *reqLog) {
	p := r.URL.EscapedPath()
	switch {
	case p == "/healthz" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case p == "/v1/capabilities":
		l.op = "issue"
		if r.Method != http.MethodPost {
			s.fail(w, l, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.issue(w, r, l)
	case strings.HasPrefix(p, objectsPath):
		s.object(w, r, l, strings.TrimPrefix(p, objectsPath))
	default:
		s.fail(w, l, http.StatusNotFound, "not found")
	}
}

func (s *Server) fail(w http.ResponseWriter, l *reqLog, status int, msg string) {
	l.err = msg
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// authenticate returns the caller, or writes 401/503.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, l *reqLog) (auth.Principal, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pathops-artifact-store"`)
		s.fail(w, l, http.StatusUnauthorized, "a ServiceAccount bearer token for the store's audience is required")
		return auth.Principal{}, false
	}
	p, err := s.Auth.Authenticate(r.Context(), tok)
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", `Bearer realm="pathops-artifact-store", error="invalid_token"`)
		s.fail(w, l, http.StatusUnauthorized, "invalid, expired or wrong-audience token")
		return auth.Principal{}, false
	case err != nil:
		s.Log.Error("token review failed", "error", err)
		s.fail(w, l, http.StatusServiceUnavailable, "cannot verify the token now")
		return auth.Principal{}, false
	}
	l.subject = p.Subject
	return p, true
}

// authorize decides op on k for p, or writes 403.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, l *reqLog, p auth.Principal, op, k string) bool {
	if s.Admins[p.Subject] {
		return true
	}
	enc := r.Header.Get(HeaderCapability)
	if enc == "" || op == "delete" {
		s.fail(w, l, http.StatusForbidden, "not allowed")
		return false
	}
	c, err := s.Signer.Verify(enc)
	switch {
	case errors.Is(err, capability.ErrExpired):
		s.fail(w, l, http.StatusForbidden, "capability expired")
		return false
	case err != nil:
		s.fail(w, l, http.StatusForbidden, "invalid capability")
		return false
	case c.Subject != p.Subject:
		s.fail(w, l, http.StatusForbidden, "capability issued for another identity")
		return false
	case !key.Within(k, c.Prefix) || !(c.Allows(op) || op == capability.OpStat && c.Allows(capability.OpGet)):
		s.fail(w, l, http.StatusForbidden, "capability does not allow this operation on this key")
		return false
	}
	return true
}

func (s *Server) issue(w http.ResponseWriter, r *http.Request, l *reqLog) {
	p, ok := s.authenticate(w, r, l)
	if !ok {
		return
	}
	if !s.Admins[p.Subject] {
		s.fail(w, l, http.StatusForbidden, "only a privileged identity may issue capabilities")
		return
	}
	var req CapabilityRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.fail(w, l, http.StatusBadRequest, "invalid capability request")
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	switch {
	case !subjectRe.MatchString(req.Subject):
		s.fail(w, l, http.StatusBadRequest, "subject must be system:serviceaccount:<namespace>:<name>")
		return
	case s.Admins[req.Subject]:
		s.fail(w, l, http.StatusBadRequest, "a privileged identity needs no capability")
		return
	case key.ValidatePrefix(req.Prefix, 2) != nil:
		s.fail(w, l, http.StatusBadRequest, "prefix must be at least two key segments followed by /")
		return
	case !capability.ValidOperations(req.Operations):
		s.fail(w, l, http.StatusBadRequest, "operations must be a set of put, get, stat")
		return
	case ttl <= 0 || ttl > s.MaxTTL:
		s.fail(w, l, http.StatusBadRequest, fmt.Sprintf("ttlSeconds must be between 1 and %d", int64(s.MaxTTL/time.Second)))
		return
	}
	enc, c, err := s.Signer.Issue(req.Subject, req.Prefix, req.Operations, ttl)
	if err != nil {
		s.fail(w, l, http.StatusInternalServerError, "cannot issue")
		return
	}
	l.key = req.Prefix
	s.Log.Info("capability issued", "by", p.Subject, "subject", c.Subject, "prefix", c.Prefix, "operations", c.Operations,
		"expiresAt", time.Unix(c.Expires, 0).UTC())
	writeJSON(w, http.StatusCreated, CapabilityResponse{Capability: enc, Subject: c.Subject, Prefix: c.Prefix,
		Operations: c.Operations, ExpiresAt: time.Unix(c.Expires, 0).UTC()})
}

func (s *Server) object(w *statusWriter, r *http.Request, l *reqLog, raw string) {
	var op string
	switch r.Method {
	case http.MethodPut:
		op = capability.OpPut
	case http.MethodGet:
		op = capability.OpGet
	case http.MethodHead:
		op = capability.OpStat
	case http.MethodDelete:
		op = "delete"
	default:
		l.op = strings.ToLower(r.Method)
		s.fail(w, l, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	l.op = op
	p, ok := s.authenticate(w, r, l)
	if !ok {
		return
	}
	if strings.Contains(raw, "%") || key.Validate(raw) != nil || r.URL.RawQuery != "" {
		s.fail(w, l, http.StatusBadRequest, "invalid key")
		return
	}
	l.key = raw
	if !s.authorize(w, r, l, p, op, raw) {
		return
	}
	rc := http.NewResponseController(w)
	switch op {
	case capability.OpPut:
		_ = rc.SetReadDeadline(time.Now().Add(s.RequestTimeout))
		s.put(w, r, l, p, raw)
	case capability.OpGet, capability.OpStat:
		_ = rc.SetWriteDeadline(time.Now().Add(s.RequestTimeout))
		s.get(w, r, l, raw, op == capability.OpGet)
	case "delete":
		switch err := s.Store.Delete(r.Context(), raw); {
		case errors.Is(err, store.ErrNotFound):
			s.fail(w, l, http.StatusNotFound, "not found")
		case err != nil:
			s.Log.Error("delete failed", "key", raw, "error", err)
			s.fail(w, l, http.StatusInternalServerError, "delete failed")
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

func (s *Server) put(w http.ResponseWriter, r *http.Request, l *reqLog, p auth.Principal, k string) {
	mt := r.Header.Get("Content-Type")
	if mt == "" {
		mt = "application/octet-stream"
	}
	if _, _, err := mime.ParseMediaType(mt); err != nil || len(mt) > 255 {
		s.fail(w, l, http.StatusBadRequest, "invalid Content-Type")
		return
	}
	sum := r.Header.Get(HeaderSHA256)
	if sum != "" && !sha256Re.MatchString(sum) {
		s.fail(w, l, http.StatusBadRequest, "X-PathOps-SHA256 must be 64 lowercase hex characters")
		return
	}
	meta, err := parseMetadata(r.Header.Get(HeaderMetadata))
	if err != nil {
		s.fail(w, l, http.StatusBadRequest, err.Error())
		return
	}
	if r.ContentLength > s.MaxObjectBytes {
		s.fail(w, l, http.StatusRequestEntityTooLarge, "object too large")
		return
	}
	body := &countingReader{r: http.MaxBytesReader(w, r.Body, s.MaxObjectBytes)}
	info, created, err := s.Store.Put(r.Context(), store.PutRequest{Key: k, MediaType: mt, Metadata: meta, CreatedBy: p.Subject, SHA256: sum}, body)
	l.in = body.n
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		s.fail(w, l, http.StatusRequestEntityTooLarge, "object too large")
	case errors.Is(err, store.ErrDigestMismatch):
		s.fail(w, l, http.StatusUnprocessableEntity, "content does not match X-PathOps-SHA256")
	case errors.Is(err, store.ErrExists):
		s.fail(w, l, http.StatusConflict, "the key holds different content (objects are immutable)")
	case err != nil:
		s.Log.Error("put failed", "key", k, "error", err)
		s.fail(w, l, http.StatusInternalServerError, "upload failed")
	case created:
		writeJSON(w, http.StatusCreated, PutResponse{Ref: s.Ref(k), Info: info})
	default:
		writeJSON(w, http.StatusOK, PutResponse{Ref: s.Ref(k), Info: info})
	}
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, l *reqLog, k string, body bool) {
	var (
		info store.Info
		rc   io.ReadCloser
		err  error
	)
	if body {
		info, rc, err = s.Store.Get(r.Context(), k)
	} else {
		info, err = s.Store.Stat(r.Context(), k)
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, l, http.StatusNotFound, "not found")
		return
	case err != nil:
		s.Log.Error("read failed", "key", k, "error", err)
		s.fail(w, l, http.StatusInternalServerError, "read failed")
		return
	}
	h := w.Header()
	h.Set("Content-Type", info.MediaType)
	h.Set("Content-Length", strconv.FormatInt(info.Size, 10))
	h.Set(HeaderSHA256, info.SHA256)
	h.Set("ETag", `"sha256:`+info.SHA256+`"`)
	h.Set(HeaderCreatedAt, info.CreatedAt.Format(time.RFC3339Nano))
	if len(info.Metadata) > 0 {
		b, _ := json.Marshal(info.Metadata)
		h.Set(HeaderMetadata, string(b))
	}
	w.WriteHeader(http.StatusOK)
	if rc == nil {
		return
	}
	defer rc.Close()
	if _, err := io.CopyBuffer(w, rc, make([]byte, 32<<10)); err != nil {
		l.err = "client stopped reading"
	}
}

func parseMetadata(h string) (map[string]string, error) {
	if h == "" {
		return nil, nil
	}
	errBad := errors.New("X-PathOps-Metadata must be a JSON object of at most 16 short string values")
	if len(h) > maxMetadata {
		return nil, errBad
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(h), &m); err != nil || len(m) > maxMetaEntries {
		return nil, errBad
	}
	for k, v := range m {
		if !metaKeyRe.MatchString(k) || len(v) > 256 {
			return nil, errBad
		}
	}
	return m, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

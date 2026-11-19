// Package server is the HTTP API of the Artifact Store (Decisions 0047, 0061).
//
//	GET  /healthz              liveness (no authentication)
//	PUT  /v1/objects/{key}     workload: stream an object in (immutable)
//	GET  /v1/objects/{key}     workload: stream an object out
//	HEAD /v1/objects/{key}     workload: describe an object
//	GET  /objects/{key}        human: download, after Dex SSO
//	HEAD /objects/{key}        human: describe
//	GET  /oauth2/callback      human: the end of a Dex sign-in
//
// Workload requests carry "Authorization: Bearer <Artifact Store token>", a
// JWT the Cell's Dex issues through its workload token exchange with the
// Tenant CP's authorization (internal/workload). The token names exactly one
// Application and one key prefix inside it; a request names neither:
//
//   - PUT needs the write operation and a key under the token's key prefix
//     (itself under applications/<the token's Application>/); the object
//     records that Application;
//   - GET and HEAD need the read operation, a key under the token's key
//     prefix and an object that recorded the token's Application. The
//     recorded Application is the boundary; the prefixes are a second
//     defense and the token's scope.
//
// Human requests carry no token: the store signs the person in with the
// Cell's Dex (internal/human) and keeps a session cookie. An object is
// returned to the Cell admin (a configured, verified email) and to the
// owner of the object's Application (the Dex subject its writer recorded);
// anyone else signed in gets 403.
//
// Keys are taken from the raw request path, never from a cleaned one, so
// "..", "//" and percent-encoding are rejected (400) rather than resolved.
// There is no LIST and no DELETE.
package server

import (
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PathOps/pathops-artifact-store/internal/human"
	"github.com/PathOps/pathops-artifact-store/internal/key"
	"github.com/PathOps/pathops-artifact-store/internal/store"
	"github.com/PathOps/pathops-artifact-store/internal/workload"
)

// Request and response headers.
const (
	HeaderSHA256    = "X-PathOps-SHA256"
	HeaderMetadata  = "X-PathOps-Metadata"
	HeaderCreatedAt = "X-PathOps-Created-At"
	// HeaderOwner is the Dex subject of the Application's owner, declared by
	// the writer on PUT.
	HeaderOwner     = "X-PathOps-Owner"
	HeaderApp       = "X-PathOps-Application"
	apiObjectsPath  = "/v1/objects/"
	humanObjectPath = "/objects/"
	maxMetadata     = 2048
	maxMetaEntries  = 16
	maxOwner        = 256
)

var (
	sha256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	metaKeyRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	ownerRe   = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// Server serves the API.
type Server struct {
	Name     string // the store's name in references: pathops-artifact://<Name>/<key>
	Store    store.ArtifactStore
	Workload *workload.Verifier
	Human    *human.Auth
	// Admins are the Cell admin's emails: they read every object.
	Admins         []string
	MaxObjectBytes int64
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

// reqLog collects what one request log line says. It never holds a token, a
// code or a cookie.
type reqLog struct {
	op, key, subject, application, err string
	in                                 int64
}

func (s *Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w := &statusWriter{ResponseWriter: rw}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	l := &reqLog{}
	s.route(w, r, l)
	if r.URL.Path == "/healthz" {
		return
	}
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	s.Log.Info("request", "method", r.Method, "op", l.op, "key", l.key, "subject", l.subject, "application", l.application,
		"status", w.status, "bytesIn", l.in, "bytesOut", w.bytes, "durationMs", time.Since(start).Milliseconds(), "error", l.err,
		"processMaxRssKiB", ru.Maxrss)
}

func (s *Server) route(w *statusWriter, r *http.Request, l *reqLog) {
	p := r.URL.EscapedPath()
	switch {
	case p == "/healthz" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case strings.HasPrefix(p, apiObjectsPath):
		s.apiObject(w, r, l, strings.TrimPrefix(p, apiObjectsPath))
	case strings.HasPrefix(p, humanObjectPath):
		s.humanObject(w, r, l, strings.TrimPrefix(p, humanObjectPath))
	case p == human.CallbackPath && r.Method == http.MethodGet:
		s.callback(w, r, l)
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

// validKey: raw is a key as the path spelled it, with nothing to resolve.
func validKey(r *http.Request, raw string) bool {
	return !strings.Contains(raw, "%") && key.Validate(raw) == nil && r.URL.RawQuery == ""
}

// applicationOf is the Application segment of an applications/<id>/... key.
func applicationOf(k string) string {
	seg := strings.Split(k, "/")
	if len(seg) < 3 || seg[0] != "applications" {
		return ""
	}
	return seg[1]
}

// ---------------------------------------------------------------- workloads

func (s *Server) apiObject(w *statusWriter, r *http.Request, l *reqLog, raw string) {
	var op string
	switch r.Method {
	case http.MethodPut:
		l.op, op = "put", workload.OpWrite
	case http.MethodGet:
		l.op, op = "get", workload.OpRead
	case http.MethodHead:
		l.op, op = "stat", workload.OpRead
	default:
		l.op = strings.ToLower(r.Method)
		s.fail(w, l, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pathops-artifact-store"`)
		s.fail(w, l, http.StatusUnauthorized, "an Artifact Store token is required")
		return
	}
	p, err := s.Workload.Verify(tok)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pathops-artifact-store", error="invalid_token"`)
		s.Log.Warn("token refused", "reason", err.Error())
		s.fail(w, l, http.StatusUnauthorized, "invalid, expired, wrong-issuer or wrong-audience token")
		return
	}
	l.subject, l.application = p.Subject, p.Application
	if !validKey(r, raw) {
		s.fail(w, l, http.StatusBadRequest, "invalid key")
		return
	}
	l.key = raw
	switch {
	case !p.Allows(op):
		s.fail(w, l, http.StatusForbidden, "the token does not allow this operation")
		return
	case applicationOf(raw) != p.Application:
		s.fail(w, l, http.StatusForbidden, "the key is not under the token's Application")
		return
	case !p.Covers(raw):
		s.fail(w, l, http.StatusForbidden, "the key is outside the token's scope")
		return
	}
	rc := http.NewResponseController(w)
	if op == workload.OpWrite {
		_ = rc.SetReadDeadline(time.Now().Add(s.RequestTimeout))
		s.put(w, r, l, p, raw)
		return
	}
	_ = rc.SetWriteDeadline(time.Now().Add(s.RequestTimeout))
	s.serve(w, r, l, raw, func(info store.Info) bool { return info.Application == p.Application }, false)
}

func (s *Server) put(w http.ResponseWriter, r *http.Request, l *reqLog, p workload.Principal, k string) {
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
	owner := r.Header.Get(HeaderOwner)
	if owner != "" && (len(owner) > maxOwner || !ownerRe.MatchString(owner)) {
		s.fail(w, l, http.StatusBadRequest, "invalid X-PathOps-Owner")
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
	info, created, err := s.Store.Put(r.Context(), store.PutRequest{Key: k, MediaType: mt, Metadata: meta, CreatedBy: p.Subject,
		Application: p.Application, Owner: owner, SHA256: sum}, body)
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

// serve answers GET or HEAD of k when allowed(info). Otherwise a workload
// gets 404, as for an object that does not exist (no existence oracle across
// Applications), and a signed-in person 403. download: a person's request
// (Content-Disposition attachment).
func (s *Server) serve(w http.ResponseWriter, r *http.Request, l *reqLog, k string, allowed func(store.Info) bool, download bool) {
	var (
		info store.Info
		rc   io.ReadCloser
		err  error
	)
	if r.Method == http.MethodGet {
		info, rc, err = s.Store.Get(r.Context(), k)
	} else {
		info, err = s.Store.Stat(r.Context(), k)
	}
	if rc != nil {
		defer rc.Close()
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, l, http.StatusNotFound, "not found")
		return
	case err != nil:
		s.Log.Error("read failed", "key", k, "error", err)
		s.fail(w, l, http.StatusInternalServerError, "read failed")
		return
	case !allowed(info) && download:
		s.page(w, l, http.StatusForbidden, "Not allowed", "This artifact belongs to an Application you do not own.")
		return
	case !allowed(info):
		l.err = "not this identity's object"
		s.fail(w, l, http.StatusNotFound, "not found")
		return
	}
	h := w.Header()
	h.Set("Content-Type", info.MediaType)
	h.Set("Content-Length", strconv.FormatInt(info.Size, 10))
	h.Set(HeaderSHA256, info.SHA256)
	h.Set("ETag", `"sha256:`+info.SHA256+`"`)
	h.Set(HeaderCreatedAt, info.CreatedAt.Format(time.RFC3339Nano))
	h.Set(HeaderApp, info.Application)
	if len(info.Metadata) > 0 {
		b, _ := json.Marshal(info.Metadata)
		h.Set(HeaderMetadata, string(b))
	}
	if download {
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(k)}))
	}
	w.WriteHeader(http.StatusOK)
	if rc == nil {
		return
	}
	if _, err := io.CopyBuffer(w, rc, make([]byte, 32<<10)); err != nil {
		l.err = "client stopped reading"
	}
}

// ---------------------------------------------------------------- humans

func (s *Server) humanObject(w *statusWriter, r *http.Request, l *reqLog, raw string) {
	l.op = "download"
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.fail(w, l, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !validKey(r, raw) || applicationOf(raw) == "" {
		s.fail(w, l, http.StatusBadRequest, "invalid key")
		return
	}
	l.key = raw
	id, ok := s.Human.Session(r)
	if !ok {
		l.op = "sign-in"
		if err := s.Human.Login(r.Context(), w, humanObjectPath+raw); err != nil {
			s.Log.Error("sign-in unavailable", "error", err)
			s.page(w, l, http.StatusServiceUnavailable, "Sign-in is unavailable", "The Cell's identity provider cannot be reached now. Try again later.")
		}
		return
	}
	l.subject = id.Subject
	admin := id.EmailVerified && slices.Contains(s.Admins, id.Email)
	s.serve(w, r, l, raw, func(info store.Info) bool {
		l.application = info.Application
		return admin || (info.Owner != "" && info.Owner == id.Subject)
	}, true)
}

func (s *Server) callback(w *statusWriter, r *http.Request, l *reqLog) {
	l.op = "sign-in"
	next, err := s.Human.Callback(r.Context(), w, r)
	switch {
	case errors.Is(err, human.ErrUnavailable):
		s.Log.Error("sign-in unavailable", "error", err)
		s.page(w, l, http.StatusServiceUnavailable, "Sign-in is unavailable", "The Cell's identity provider cannot be reached now. Try again later.")
		return
	case err != nil:
		s.Log.Warn("sign-in refused", "reason", err.Error())
		s.page(w, l, http.StatusUnauthorized, "Sign-in failed", "Open the artifact link again to sign in.")
		return
	}
	if !strings.HasPrefix(next, humanObjectPath) {
		next = "/"
	}
	w.Header().Set("Location", next)
	w.WriteHeader(http.StatusFound)
}

// page is a minimal HTML answer for a browser.
func (s *Server) page(w http.ResponseWriter, l *reqLog, status int, title, text string) {
	l.err = title
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "<!doctype html><meta charset=utf-8><title>PathOps artifacts</title><h1>"+
		html.EscapeString(title)+"</h1><p>"+html.EscapeString(text)+"</p>")
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

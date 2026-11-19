package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/PathOps/pathops-artifact-store/internal/human"
	"github.com/PathOps/pathops-artifact-store/internal/store/fsstore"
	"github.com/PathOps/pathops-artifact-store/internal/workload"
)

const (
	appA     = "11111111-1111-4111-8111-111111111111"
	appB     = "22222222-2222-4222-8222-222222222222"
	tokenIss = "https://dex.cell.example/artifacts"
	// tcpSubject is the Tenant CP's own ServiceAccount, the subject of its tokens.
	tcpSubject = "system:serviceaccount:pathops-system:tenant-control-plane"
	tokenAud   = "pathops-artifact-store"
	clientID   = "pathops-artifact-store-web"
	secret     = "client-secret"
	ownerA     = "owner-a-subject"
	ownerB     = "owner-b-subject"
	admin      = "admin-cell@demo.pathops.io"
)

var (
	keyA = "applications/" + appA + "/deliveries/33333333-3333-4333-8333-333333333333/build-failure.tar.gz"
	keyB = "applications/" + appB + "/deliveries/44444444-4444-4444-8444-444444444444/build-failure.tar.gz"
)

// dex is a fake Dex: discovery, JWKS, and an authorization code flow whose
// codes the test mints (code -> the ID token claims it redeems to).
type dex struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	kid   string
	mu    sync.Mutex
	codes map[string]dexCode
}

type dexCode struct {
	challenge string
	claims    map[string]any
	signer    *rsa.PrivateKey
}

func newDex(t *testing.T) *dex {
	d := &dex{kid: "oidc-1", codes: map[string]dexCode{}}
	d.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": d.srv.URL, "authorization_endpoint": d.srv.URL + "/auth",
			"token_endpoint": d.srv.URL + "/token", "jwks_uri": d.srv.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &d.key.PublicKey, KeyID: d.kid, Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		id, sec, ok := r.BasicAuth()
		_ = r.ParseForm()
		d.mu.Lock()
		c, found := d.codes[r.Form.Get("code")]
		delete(d.codes, r.Form.Get("code"))
		d.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || id != clientID || sec != secret || !found || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge ||
			r.Form.Get("grant_type") != "authorization_code" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": d.sign(c.signer, c.claims), "token_type": "bearer"})
	})
	d.srv = httptest.NewTLSServer(mux)
	t.Cleanup(d.srv.Close)
	return d
}

func (d *dex) sign(k *rsa.PrivateKey, claims map[string]any) string {
	s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k}, (&jose.SignerOptions{}).WithHeader("kid", d.kid))
	b, _ := json.Marshal(claims)
	o, _ := s.Sign(b)
	out, _ := o.CompactSerialize()
	return out
}

type env struct {
	t        *testing.T
	srv      *httptest.Server
	dex      *dex
	tokenKey ed25519.PrivateKey
}

func newEnv(t *testing.T) *env {
	st, err := fsstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	d := newDex(t)
	e := &env{t: t, dex: d, tokenKey: key}
	s := &Server{Name: "dev", Store: st, Admins: []string{admin}, MaxObjectBytes: 1 << 20, RequestTimeout: time.Minute,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Workload: &workload.Verifier{Issuer: tokenIss, Audience: tokenAud, KeyID: "artifact-1", Key: pub, Now: time.Now}}
	e.srv = httptest.NewTLSServer(s)
	t.Cleanup(e.srv.Close)
	s.Human, err = human.New(human.Config{Issuer: d.srv.URL, ClientID: clientID, ClientSecret: secret, PublicURL: e.srv.URL,
		HTTP: d.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// token is an Artifact Store token of app as Dex issues it for the Tenant CP:
// scoped to app's deliveries.
func (e *env) token(app string, ops ...string) string {
	return e.tokenWith(map[string]any{"pathops_application": app, "pathops_operations": ops,
		"pathops_key_prefix": "applications/" + app + "/deliveries/"})
}

// scoped is a read/write token of app limited to prefix.
func (e *env) scoped(app, prefix string) string {
	return e.tokenWith(map[string]any{"pathops_application": app, "pathops_key_prefix": prefix})
}

func (e *env) tokenWith(over map[string]any) string {
	now := time.Now().Unix()
	c := map[string]any{"iss": tokenIss, "aud": tokenAud, "sub": tcpSubject,
		"iat": now, "nbf": now, "exp": now + 300, "pathops_application": appA, "pathops_operations": []string{"read", "write"},
		"pathops_key_prefix": "applications/" + appA + "/deliveries/"}
	for k, v := range over {
		c[k] = v
	}
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "artifact-1"})
	b, _ := json.Marshal(c)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(e.tokenKey, []byte(in)))
}

func (e *env) api(method, key, token string, body []byte, hdr ...string) (*http.Response, []byte) {
	req, _ := http.NewRequest(method, e.srv.URL+"/v1/objects/"+key, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// put stores body at key as app (owner recorded) and fails the test otherwise.
func (e *env) put(app, key, owner string, body []byte) {
	e.t.Helper()
	if resp, b := e.api(http.MethodPut, key, e.token(app, "read", "write"), body, "Content-Type", "application/gzip",
		HeaderSHA256, sum(body), HeaderOwner, owner); resp.StatusCode != http.StatusCreated {
		e.t.Fatalf("put %s: %d %s", key, resp.StatusCode, b)
	}
}

func TestWorkloadApplicationIsolation(t *testing.T) {
	e := newEnv(t)
	bundle := []byte("bundle of A")
	resp, b := e.api(http.MethodPut, keyA, e.token(appA, "read", "write"), bundle, "Content-Type", "application/gzip",
		HeaderSHA256, sum(bundle), HeaderOwner, ownerA, HeaderMetadata, `{"type":"BUILD_FAILURE_LOGS"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatal(resp.StatusCode, string(b))
	}
	var put PutResponse
	_ = json.Unmarshal(b, &put)
	if put.Ref != "pathops-artifact://dev/"+keyA || put.SHA256 != sum(bundle) || put.Size != int64(len(bundle)) || put.Application != appA ||
		put.Owner != ownerA || put.CreatedBy != tcpSubject {
		t.Fatalf("%+v", put)
	}
	e.put(appB, keyB, ownerB, []byte("bundle of B"))

	// App A token: get A ALLOW, with the recorded facts.
	resp, b = e.api(http.MethodGet, keyA, e.token(appA, "read", "write"), nil)
	if resp.StatusCode != http.StatusOK || string(b) != string(bundle) || resp.Header.Get(HeaderSHA256) != sum(bundle) ||
		resp.Header.Get(HeaderApp) != appA || resp.Header.Get("Content-Length") != "11" {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	if resp, _ := e.api(http.MethodHead, keyA, e.token(appA, "read"), nil); resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	// App A token: get or put B DENY; App B token: A DENY.
	for name, c := range map[string]struct {
		method, key, token string
	}{
		"A gets B":  {http.MethodGet, keyB, e.token(appA, "read", "write")},
		"A heads B": {http.MethodHead, keyB, e.token(appA, "read", "write")},
		"A puts B":  {http.MethodPut, "applications/" + appB + "/deliveries/x/evil.tar.gz", e.token(appA, "read", "write")},
		"B gets A":  {http.MethodGet, keyA, e.token(appB, "read", "write")},
		"B puts A":  {http.MethodPut, "applications/" + appA + "/deliveries/x/evil.tar.gz", e.token(appB, "read", "write")},
		// A key outside applications/<id>/ belongs to no Application.
		"A puts outside":  {http.MethodPut, "shared/evil.tar.gz", e.token(appA, "read", "write")},
		"A puts at root":  {http.MethodPut, "applications/" + appA, e.token(appA, "read", "write")},
		"read-only puts":  {http.MethodPut, "applications/" + appA + "/deliveries/x/y.tar.gz", e.token(appA, "read")},
		"write-only gets": {http.MethodGet, keyA, e.token(appA, "write")},
	} {
		if resp, b := e.api(c.method, c.key, c.token, []byte("evil")); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
	// B's object is unchanged.
	if resp, b := e.api(http.MethodGet, keyB, e.token(appB, "read"), nil); resp.StatusCode != http.StatusOK || string(b) != "bundle of B" {
		t.Fatal(resp.StatusCode, string(b))
	}
}

// A token is limited to its key prefix (Decision 0065: the Tenant CP scopes
// it to one DeliveryRun): the run's own objects only, never another run of
// the same Application, never another Application.
func TestWorkloadKeyPrefixScope(t *testing.T) {
	e := newEnv(t)
	run := "applications/" + appA + "/deliveries/33333333-3333-4333-8333-333333333333/"
	other := "applications/" + appA + "/deliveries/55555555-5555-4555-8555-555555555555/build-failure.tar.gz"
	e.put(appA, other, ownerA, []byte("another run"))
	tok := e.scoped(appA, run)
	if resp, b := e.api(http.MethodPut, keyA, tok, []byte("mine"), "Content-Type", "application/gzip"); resp.StatusCode != http.StatusCreated {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, _ := e.api(http.MethodGet, keyA, tok, nil); resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	for name, c := range map[string]struct{ method, key string }{
		"get another run":           {http.MethodGet, other},
		"head another run":          {http.MethodHead, other},
		"put in another run":        {http.MethodPut, "applications/" + appA + "/deliveries/55555555-5555-4555-8555-555555555555/x.tar.gz"},
		"put beside the run":        {http.MethodPut, "applications/" + appA + "/deliveries/x.tar.gz"},
		"put in B's same-named run": {http.MethodPut, "applications/" + appB + "/deliveries/33333333-3333-4333-8333-333333333333/x.tar.gz"},
	} {
		if resp, b := e.api(c.method, c.key, tok, []byte("evil")); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
	if resp, b := e.api(http.MethodGet, other, e.token(appA, "read"), nil); resp.StatusCode != http.StatusOK || string(b) != "another run" {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestWorkloadTokensRefused(t *testing.T) {
	e := newEnv(t)
	e.put(appA, keyA, ownerA, []byte("x"))
	now := time.Now().Unix()
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "artifact-1"})
	b, _ := json.Marshal(map[string]any{"iss": tokenIss, "aud": tokenAud, "sub": "x", "iat": now, "exp": now + 300,
		"pathops_application": appA, "pathops_operations": []string{"read"}})
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	forged := in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(otherKey, []byte(in)))
	valid := e.token(appA, "read")
	parts := strings.Split(valid, ".")
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	widened := base64.RawURLEncoding.EncodeToString(bytes.Replace(claims, []byte(appA), []byte(appB), 1))
	for name, tok := range map[string]string{
		"missing":             "",
		"expired":             e.tokenWith(map[string]any{"iat": now - 400, "nbf": now - 400, "exp": now - 100}),
		"wrong audience":      e.tokenWith(map[string]any{"aud": "zot"}),
		"wrong issuer":        e.tokenWith(map[string]any{"iss": "https://dex.other-cell.example/artifacts"}),
		"missing application": e.tokenWith(map[string]any{"pathops_application": nil}),
		"missing key prefix":  e.tokenWith(map[string]any{"pathops_key_prefix": nil}),
		"B's key prefix":      e.scoped(appA, "applications/"+appB+"/deliveries/"),
		"Application root":    e.scoped(appA, "applications/"+appA+"/"),
		"prefix not a dir":    e.scoped(appA, "applications/"+appA+"/deliveries"),
		"prefix escapes":      e.scoped(appA, "applications/"+appA+"/../"+appB+"/"),
		"wrong operation":     e.tokenWith(map[string]any{"pathops_operations": []string{"admin"}}),
		"forged":              forged,
		"tampered":            parts[0] + "." + widened + "." + parts[2],
	} {
		if resp, b := e.api(http.MethodGet, keyA, tok, nil); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
	// A Dex OIDC token (RS256, another key) is no workload credential.
	idToken := e.dex.sign(e.dex.key, map[string]any{"iss": e.dex.srv.URL, "aud": tokenAud, "sub": ownerA, "exp": now + 300})
	if resp, _ := e.api(http.MethodGet, keyA, idToken, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Error("OIDC token accepted:", resp.StatusCode)
	}
}

func TestImmutability(t *testing.T) {
	e := newEnv(t)
	e.put(appA, keyA, ownerA, []byte("one"))
	tok := e.token(appA, "read", "write")
	if resp, _ := e.api(http.MethodPut, keyA, tok, []byte("one"), HeaderOwner, ownerA); resp.StatusCode != http.StatusOK {
		t.Fatal("identical retry:", resp.StatusCode)
	}
	if resp, _ := e.api(http.MethodPut, keyA, tok, []byte("two")); resp.StatusCode != http.StatusConflict {
		t.Fatal("different content:", resp.StatusCode)
	}
	if resp, b := e.api(http.MethodGet, keyA, tok, nil); string(b) != "one" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, _ := e.api(http.MethodDelete, keyA, tok, nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("delete:", resp.StatusCode)
	}
}

func TestKeyEscapes(t *testing.T) {
	e := newEnv(t)
	tok := e.token(appA, "read", "write")
	prefA := "applications/" + appA + "/"
	for _, p := range []string{
		prefA + "../../applications/" + appB + "/x",
		prefA + "..%2f..%2fx",
		prefA + "%2e%2e/x",
		prefA + "a//b",
		prefA + "./x",
		prefA + "x?y=1",
		prefA + "@data",
		prefA + ".hidden",
		prefA,
	} {
		if resp, b := e.api(http.MethodPut, p, tok, []byte("x")); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q: %d %s", p, resp.StatusCode, b)
		}
	}
}

func TestPutLimitsAndValidation(t *testing.T) {
	e := newEnv(t)
	tok := e.token(appA, "write")
	for name, c := range map[string]struct {
		body []byte
		hdr  []string
		want int
	}{
		"too large":        {make([]byte, 1<<20+1), nil, http.StatusRequestEntityTooLarge},
		"digest mismatch":  {[]byte("x"), []string{HeaderSHA256, sum([]byte("y"))}, http.StatusUnprocessableEntity},
		"bad digest":       {[]byte("x"), []string{HeaderSHA256, "ABC"}, http.StatusBadRequest},
		"bad content type": {[]byte("x"), []string{"Content-Type", "not a type;;"}, http.StatusBadRequest},
		"bad metadata":     {[]byte("x"), []string{HeaderMetadata, `{"a":1}`}, http.StatusBadRequest},
		"bad owner":        {[]byte("x"), []string{HeaderOwner, "two words"}, http.StatusBadRequest},
	} {
		if resp, b := e.api(http.MethodPut, "applications/"+appA+"/deliveries/"+strings.ReplaceAll(name, " ", "-"), tok, c.body, c.hdr...); resp.StatusCode != c.want {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
	resp, err := e.srv.Client().Get(e.srv.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatal(resp, err)
	}
}

// ---------------------------------------------------------------- humans

// browser follows the store's redirects up to Dex's authorization endpoint
// and returns its query (state, nonce, PKCE challenge).
type browser struct {
	t      *testing.T
	e      *env
	client *http.Client
}

func newBrowser(e *env) *browser {
	jar, _ := cookiejar.New(nil)
	c := e.srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{t: e.t, e: e, client: c}
}

func (b *browser) get(u string) (*http.Response, string) {
	resp, err := b.client.Get(u)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// signIn opens the object URL, "signs in" at Dex with claims (nil: the
// defaults for subject) and follows the callback; it returns the final answer.
func (b *browser) signIn(object, subject, email string, over map[string]any) (*http.Response, string) {
	b.t.Helper()
	resp, _ := b.get(b.e.srv.URL + "/objects/" + object)
	if resp.StatusCode != http.StatusFound {
		b.t.Fatalf("no redirect to Dex: %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if loc.Path != "/auth" || q.Get("client_id") != clientID || q.Get("code_challenge_method") != "S256" ||
		q.Get("redirect_uri") != b.e.srv.URL+"/oauth2/callback" || q.Get("state") == "" || q.Get("nonce") == "" ||
		!strings.Contains(q.Get("scope"), "openid") {
		b.t.Fatalf("authorization request: %s", loc)
	}
	claims := map[string]any{"iss": b.e.dex.srv.URL, "aud": clientID, "sub": subject, "email": email, "email_verified": true,
		"exp": time.Now().Unix() + 600, "nonce": q.Get("nonce")}
	signer := b.e.dex.key
	for k, v := range over {
		if k == "signer" {
			signer = v.(*rsa.PrivateKey)
			continue
		}
		claims[k] = v
	}
	code := "code-" + subject + q.Get("state")[:8]
	b.e.dex.mu.Lock()
	b.e.dex.codes[code] = dexCode{challenge: q.Get("code_challenge"), claims: claims, signer: signer}
	b.e.dex.mu.Unlock()
	resp, body := b.get(b.e.srv.URL + "/oauth2/callback?code=" + code + "&state=" + url.QueryEscape(q.Get("state")))
	if resp.StatusCode != http.StatusFound {
		return resp, body
	}
	if resp.Header.Get("Location") != "/objects/"+object {
		b.t.Fatalf("callback goes to %q", resp.Header.Get("Location"))
	}
	for _, c := range resp.Cookies() {
		if c.Name == human.SessionCookie && (!c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || strings.Contains(c.Value, ".")) {
			b.t.Fatalf("session cookie %+v", c)
		}
	}
	return b.get(b.e.srv.URL + resp.Header.Get("Location"))
}

func TestHumanUnauthenticatedRedirectsToDex(t *testing.T) {
	e := newEnv(t)
	e.put(appA, keyA, ownerA, []byte("A"))
	resp, body := newBrowser(e).get(e.srv.URL + "/objects/" + keyA)
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), e.dex.srv.URL+"/auth?") || body == "A" {
		t.Fatal(resp.StatusCode, resp.Header.Get("Location"))
	}
	// The API path never redirects: 401 without a bearer token.
	if resp, _ := e.api(http.MethodGet, keyA, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal(resp.StatusCode)
	}
}

func TestHumanOwnerAndAdminDownload(t *testing.T) {
	e := newEnv(t)
	e.put(appA, keyA, ownerA, []byte("bundle A"))
	e.put(appB, keyB, ownerB, []byte("bundle B"))

	// The owner of A: A downloads; B is forbidden.
	owner := newBrowser(e)
	resp, body := owner.signIn(keyA, ownerA, "owner-a@e2e.pathops.test", nil)
	if resp.StatusCode != http.StatusOK || body != "bundle A" || resp.Header.Get(HeaderSHA256) != sum([]byte("bundle A")) ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), `attachment; filename=build-failure.tar.gz`) {
		t.Fatal(resp.StatusCode, body, resp.Header)
	}
	if resp, _ := owner.get(e.srv.URL + "/objects/" + keyB); resp.StatusCode != http.StatusForbidden {
		t.Fatal("owner of A reads B:", resp.StatusCode)
	}
	// The session is reused: no new sign-in for A.
	if resp, body := owner.get(e.srv.URL + "/objects/" + keyA); resp.StatusCode != http.StatusOK || body != "bundle A" {
		t.Fatal(resp.StatusCode)
	}

	// The Cell admin reads both.
	adm := newBrowser(e)
	if resp, body := adm.signIn(keyB, "admin-subject", admin, nil); resp.StatusCode != http.StatusOK || body != "bundle B" {
		t.Fatal(resp.StatusCode, body)
	}
	if resp, _ := adm.get(e.srv.URL + "/objects/" + keyA); resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}

	// Another signed-in person: forbidden. The admin's email unverified: too.
	if resp, body := newBrowser(e).signIn(keyA, "someone-else", "x@e2e.pathops.test", nil); resp.StatusCode != http.StatusForbidden || body == "bundle A" {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := newBrowser(e).signIn(keyA, "admin-subject", admin, map[string]any{"email_verified": false}); resp.StatusCode != http.StatusForbidden {
		t.Fatal(resp.StatusCode)
	}
}

func TestHumanSignInRefused(t *testing.T) {
	e := newEnv(t)
	e.put(appA, keyA, ownerA, []byte("bundle A"))
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, over := range map[string]map[string]any{
		"wrong issuer":   {"iss": "https://dex.other-cell.example"},
		"wrong audience": {"aud": "pathops-ui"},
		"wrong nonce":    {"nonce": "replayed"},
		"expired":        {"exp": time.Now().Unix() - 10},
		"another key":    {"signer": otherKey},
	} {
		resp, body := newBrowser(e).signIn(keyA, ownerA, "owner-a@e2e.pathops.test", over)
		if resp.StatusCode != http.StatusUnauthorized || body == "bundle A" {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	// A callback with an unknown state, or from another browser than the one
	// that started the sign-in, is refused.
	b := newBrowser(e)
	if resp, _ := b.get(e.srv.URL + "/oauth2/callback?code=x&state=unknown"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal(resp.StatusCode)
	}
	resp, _ := b.get(e.srv.URL + "/objects/" + keyA)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp, _ := newBrowser(e).get(e.srv.URL + "/oauth2/callback?code=x&state=" + url.QueryEscape(loc.Query().Get("state"))); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("callback from another browser:", resp.StatusCode)
	}
	// A forged session cookie is no session.
	f := newBrowser(e)
	u, _ := url.Parse(e.srv.URL)
	f.client.Jar.SetCookies(u, []*http.Cookie{{Name: human.SessionCookie, Value: "forged"}})
	if resp, _ := f.get(e.srv.URL + "/objects/" + keyA); resp.StatusCode != http.StatusFound {
		t.Fatal("forged session:", resp.StatusCode)
	}
}

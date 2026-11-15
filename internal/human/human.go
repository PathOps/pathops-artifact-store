// Package human signs people in to the Artifact Store with the Cell's Dex
// (Decision 0061): OpenID Connect Authorization Code with PKCE (S256), state
// and nonce, as the confidential client of the store's public URL. A
// successful sign-in becomes a server-side session named by a random cookie;
// no token ever appears in a URL or a cookie.
//
//	GET <object URL>          no session: 302 to Dex's authorization endpoint
//	GET /oauth2/callback      code + state: token request, ID token checks,
//	                          session, 302 back to the object URL
//
// The ID token is verified with Dex's JWKS (OIDC discovery of the issuer):
// signature (RS256 or ES256), issuer, audience (the client id), expiry and
// the nonce of this sign-in. Sessions live in memory: a restart only means
// the next request goes through Dex again, which an existing Dex session
// answers without a password.
package human

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// SessionCookie names a session; LoginCookie binds a pending sign-in to
	// the browser that started it. __Host-: Secure, Path=/, no Domain.
	SessionCookie = "__Host-pathops-artifacts"
	LoginCookie   = "__Host-pathops-artifacts-login"
	CallbackPath  = "/oauth2/callback"
	// SessionLifetime bounds a session (and the ID token's own expiry is not
	// required to outlive it: the Dex session decides re-authentication).
	SessionLifetime = 8 * time.Hour
	loginLifetime   = 10 * time.Minute
	maxPending      = 1024
	maxDocument     = 1 << 20
	keysMaxAge      = 10 * time.Minute
)

// ErrUnavailable: Dex cannot be reached now.
var ErrUnavailable = errors.New("the identity provider is unavailable")

// Identity is a signed-in person.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// Config is the store's OIDC client.
type Config struct {
	Issuer       string // the Cell's Dex issuer URL
	ClientID     string
	ClientSecret string
	PublicURL    string // https://artifacts-<cell>.<domain>, no path
	HTTP         *http.Client
	Now          func() time.Time
}

// Auth runs sign-ins and keeps sessions.
type Auth struct {
	c Config

	mu       sync.Mutex
	pending  map[string]pending // by state
	sessions map[string]session // by sha256(cookie value)
	disc     *discovery
	keys     jose.JSONWebKeySet
	fetched  time.Time
}

type pending struct {
	nonce, verifier, binding, returnTo string
	expires                            time.Time
}

type session struct {
	id      Identity
	expires time.Time
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// New returns an Auth for c.
func New(c Config) (*Auth, error) {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("the public URL must be https://<host>")
	}
	c.PublicURL = strings.TrimSuffix(c.PublicURL, "/")
	if c.ClientID == "" || c.ClientSecret == "" || c.Issuer == "" {
		return nil, errors.New("the OIDC issuer, client id and client secret are required")
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Auth{c: c, pending: map[string]pending{}, sessions: map[string]session{}}, nil
}

// Session returns the identity of r's session cookie, if any.
func (a *Auth) Session(r *http.Request) (Identity, bool) {
	ck, err := r.Cookie(SessionCookie)
	if err != nil || ck.Value == "" {
		return Identity{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[digest(ck.Value)]
	if !ok || a.c.Now().After(s.expires) {
		delete(a.sessions, digest(ck.Value))
		return Identity{}, false
	}
	return s.id, true
}

// Login redirects the browser to Dex to sign in, returning to returnTo (a
// path of this store) afterwards.
func (a *Auth) Login(ctx context.Context, w http.ResponseWriter, returnTo string) error {
	d, err := a.discover(ctx)
	if err != nil {
		return err
	}
	state, nonce, verifier, binding := random(), random(), random(), random()
	a.mu.Lock()
	a.expire()
	if len(a.pending) >= maxPending {
		a.mu.Unlock()
		return fmt.Errorf("%w: too many sign-ins in progress", ErrUnavailable)
	}
	a.pending[state] = pending{nonce: nonce, verifier: verifier, binding: binding, returnTo: returnTo,
		expires: a.c.Now().Add(loginLifetime)}
	a.mu.Unlock()
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {a.c.ClientID},
		"redirect_uri":          {a.c.PublicURL + CallbackPath},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	http.SetCookie(w, &http.Cookie{Name: LoginCookie, Value: binding, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(loginLifetime / time.Second)})
	w.Header().Set("Location", d.AuthorizationEndpoint+"?"+q.Encode())
	w.WriteHeader(http.StatusFound)
	return nil
}

// ErrSignIn: the callback is not a valid end of a sign-in this browser
// started (unknown or expired state, another browser, a refused or forged
// token).
var ErrSignIn = errors.New("sign-in failed")

// Callback completes a sign-in: it returns where to go next after setting the
// session cookie.
func (a *Auth) Callback(ctx context.Context, w http.ResponseWriter, r *http.Request) (string, error) {
	q := r.URL.Query()
	state, code := q.Get("state"), q.Get("code")
	a.mu.Lock()
	p, ok := a.pending[state]
	delete(a.pending, state) // a state is used once
	a.mu.Unlock()
	ck, err := r.Cookie(LoginCookie)
	http.SetCookie(w, &http.Cookie{Name: LoginCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
	switch {
	case state == "" || !ok || a.c.Now().After(p.expires):
		return "", fmt.Errorf("%w: unknown or expired state", ErrSignIn)
	case err != nil || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(p.binding)) != 1:
		return "", fmt.Errorf("%w: the sign-in was started by another browser", ErrSignIn)
	case q.Get("error") != "":
		return "", fmt.Errorf("%w: Dex answered %s", ErrSignIn, q.Get("error"))
	case code == "":
		return "", fmt.Errorf("%w: no code", ErrSignIn)
	}
	raw, err := a.exchange(ctx, code, p.verifier)
	if err != nil {
		return "", err
	}
	id, err := a.verify(ctx, raw, p.nonce)
	if err != nil {
		return "", err
	}
	value := random()
	a.mu.Lock()
	a.sessions[digest(value)] = session{id: id, expires: a.c.Now().Add(SessionLifetime)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: value, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(SessionLifetime / time.Second)})
	return p.returnTo, nil
}

// exchange redeems code at Dex's token endpoint (client secret and PKCE
// verifier) and returns the ID token.
func (a *Auth) exchange(ctx context.Context, code, verifier string) (string, error) {
	d, err := a.discover(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {a.c.PublicURL + CallbackPath},
		"code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(url.QueryEscape(a.c.ClientID), url.QueryEscape(a.c.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: token request: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxDocument))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: the token request was refused (HTTP %d)", ErrSignIn, resp.StatusCode)
	}
	if err := json.Unmarshal(body, &out); err != nil || out.IDToken == "" {
		return "", fmt.Errorf("%w: no ID token", ErrSignIn)
	}
	return out.IDToken, nil
}

// verify checks the ID token: Dex's signature, issuer, audience, expiry and
// nonce.
func (a *Auth) verify(ctx context.Context, raw, nonce string) (Identity, error) {
	tok, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil || len(tok.Signatures) != 1 {
		return Identity{}, fmt.Errorf("%w: malformed ID token", ErrSignIn)
	}
	key, err := a.key(ctx, tok.Signatures[0].Header.KeyID)
	if err != nil {
		return Identity{}, err
	}
	payload, err := tok.Verify(key)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: ID token signature", ErrSignIn)
	}
	var c struct {
		Issuer        string          `json:"iss"`
		Subject       string          `json:"sub"`
		Audience      json.RawMessage `json:"aud"`
		Expiry        int64           `json:"exp"`
		Nonce         string          `json:"nonce"`
		Email         string          `json:"email"`
		EmailVerified bool            `json:"email_verified"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return Identity{}, fmt.Errorf("%w: ID token claims", ErrSignIn)
	}
	var aud []string
	if json.Unmarshal(c.Audience, &aud) != nil {
		var one string
		_ = json.Unmarshal(c.Audience, &one)
		aud = []string{one}
	}
	switch {
	case c.Issuer != a.c.Issuer:
		return Identity{}, fmt.Errorf("%w: ID token issuer", ErrSignIn)
	case !slices.Contains(aud, a.c.ClientID):
		return Identity{}, fmt.Errorf("%w: ID token audience", ErrSignIn)
	case a.c.Now().After(time.Unix(c.Expiry, 0)):
		return Identity{}, fmt.Errorf("%w: ID token expired", ErrSignIn)
	case subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1:
		return Identity{}, fmt.Errorf("%w: ID token nonce", ErrSignIn)
	case c.Subject == "":
		return Identity{}, fmt.Errorf("%w: ID token subject", ErrSignIn)
	}
	return Identity{Subject: c.Subject, Email: c.Email, EmailVerified: c.EmailVerified}, nil
}

func (a *Auth) discover(ctx context.Context) (*discovery, error) {
	a.mu.Lock()
	d := a.disc
	a.mu.Unlock()
	if d != nil {
		return d, nil
	}
	var got discovery
	if err := a.get(ctx, strings.TrimSuffix(a.c.Issuer, "/")+"/.well-known/openid-configuration", &got); err != nil {
		return nil, err
	}
	if got.Issuer != a.c.Issuer || got.AuthorizationEndpoint == "" || got.TokenEndpoint == "" || got.JWKSURI == "" {
		return nil, fmt.Errorf("%w: discovery document of another issuer or incomplete", ErrUnavailable)
	}
	a.mu.Lock()
	a.disc = &got
	a.mu.Unlock()
	return &got, nil
}

// key returns Dex's signing key kid, refreshing the JWKS when it is unknown
// or the cache is old.
func (a *Auth) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	a.mu.Lock()
	fresh := !a.fetched.IsZero() && a.c.Now().Sub(a.fetched) < keysMaxAge
	keys := a.keys.Key(kid)
	a.mu.Unlock()
	if fresh && len(keys) == 1 {
		return &keys[0], nil
	}
	d, err := a.discover(ctx)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := a.get(ctx, d.JWKSURI, &set); err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.keys, a.fetched = set, a.c.Now()
	a.mu.Unlock()
	if keys = set.Key(kid); len(keys) != 1 {
		return nil, fmt.Errorf("%w: unknown signing key", ErrSignIn)
	}
	return &keys[0], nil
}

func (a *Auth) get(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := a.c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: GET %s: HTTP %d", ErrUnavailable, u, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDocument)).Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

// expire drops expired pending sign-ins and sessions (a.mu held).
func (a *Auth) expire() {
	now := a.c.Now()
	for k, p := range a.pending {
		if now.After(p.expires) {
			delete(a.pending, k)
		}
	}
	for k, s := range a.sessions {
		if now.After(s.expires) {
			delete(a.sessions, k)
		}
	}
}

func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func digest(v string) string {
	s := sha256.Sum256([]byte(v))
	return hex.EncodeToString(s[:])
}

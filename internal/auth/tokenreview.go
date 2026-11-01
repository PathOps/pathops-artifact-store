// Package auth authenticates workloads by their Kubernetes ServiceAccount
// token.
//
// A workload presents a projected ServiceAccount token whose audience is the
// store's (pathops-artifact-store). The store asks the Kubernetes API server
// (TokenReview, with that audience) whether the token is valid: the API
// server checks signature, expiry, audience and, for a Pod-bound token, that
// the Pod still exists (a token of a deleted Pod is rejected once the API
// server's short authentication cache expires). Only ServiceAccount
// identities are accepted. Human OIDC tokens are not workload credentials and
// are not accepted here.
package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// MaxTokenLength bounds a presented token.
const MaxTokenLength = 8192

var (
	// ErrUnauthenticated: the token is not a valid ServiceAccount token for the audience.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrUnavailable: the API server could not be asked.
	ErrUnavailable = errors.New("token review unavailable")
)

// Principal is an authenticated workload.
type Principal struct {
	// Subject is the ServiceAccount username, system:serviceaccount:<ns>:<name>.
	Subject string
	// Pod is the Pod a bound token belongs to, if any.
	Pod string
}

// Authenticator authenticates a bearer token.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (Principal, error)
}

// TokenReview is an Authenticator backed by the Kubernetes TokenReview API.
type TokenReview struct {
	APIServer string // https://host:port
	Audience  string
	TokenFile string // the store's own API token (re-read on every call: the kubelet rotates it)
	Client    *http.Client
}

// InCluster configures a TokenReview from the Pod's environment.
func InCluster(audience string) (*TokenReview, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not running in a Kubernetes Pod (KUBERNETES_SERVICE_HOST/PORT unset)")
	}
	const sa = "/var/run/secrets/kubernetes.io/serviceaccount/"
	ca, err := os.ReadFile(sa + "ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("no CA certificate in the ServiceAccount ca.crt")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return &TokenReview{APIServer: "https://" + joinHostPort(host, port), Audience: audience, TokenFile: sa + "token",
		Client: &http.Client{Transport: tr, Timeout: 10 * time.Second}}, nil
}

func joinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

type tokenReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Token     string   `json:"token"`
		Audiences []string `json:"audiences"`
	} `json:"spec"`
	Status struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			Username string              `json:"username"`
			Extra    map[string][]string `json:"extra"`
		} `json:"user"`
		Audiences []string `json:"audiences"`
	} `json:"status"`
}

// Authenticate implements Authenticator.
func (t *TokenReview) Authenticate(ctx context.Context, token string) (Principal, error) {
	if token == "" || len(token) > MaxTokenLength {
		return Principal{}, ErrUnauthenticated
	}
	own, err := os.ReadFile(t.TokenFile)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var req tokenReview
	req.APIVersion, req.Kind = "authentication.k8s.io/v1", "TokenReview"
	req.Spec.Token, req.Spec.Audiences = token, []string{t.Audience}
	body, _ := json.Marshal(req)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, t.APIServer+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return Principal{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(own)))
	resp, err := t.Client.Do(r)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return Principal{}, fmt.Errorf("%w: TokenReview answered %d", ErrUnavailable, resp.StatusCode)
	}
	var res tokenReview
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&res); err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	st := res.Status
	if !st.Authenticated || !slices.Contains(st.Audiences, t.Audience) || !strings.HasPrefix(st.User.Username, "system:serviceaccount:") ||
		strings.Count(st.User.Username, ":") != 3 {
		return Principal{}, ErrUnauthenticated
	}
	p := Principal{Subject: st.User.Username}
	if pods := st.User.Extra["authentication.kubernetes.io/pod-name"]; len(pods) == 1 {
		p.Pod = pods[0]
	}
	return p, nil
}

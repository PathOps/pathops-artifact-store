package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// fakeAPIServer answers TokenReviews: "good" is app-a's token for the store's
// audience, "other-aud" is valid for another audience only, "user" is a
// non-ServiceAccount identity.
func fakeAPIServer(t *testing.T) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" || r.Header.Get("Authorization") != "Bearer store-own-token" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var req tokenReview
		_ = json.NewDecoder(r.Body).Decode(&req)
		var res tokenReview
		res.APIVersion, res.Kind = req.APIVersion, req.Kind
		aud := len(req.Spec.Audiences) == 1 && req.Spec.Audiences[0] == "pathops-artifact-store"
		switch {
		case req.Spec.Token == "good" && aud:
			res.Status.Authenticated = true
			res.Status.User.Username = "system:serviceaccount:app-a:app-a-build"
			res.Status.User.Extra = map[string][]string{"authentication.kubernetes.io/pod-name": {"build-pod"}}
			res.Status.Audiences = req.Spec.Audiences
		case req.Spec.Token == "user" && aud:
			res.Status.Authenticated = true
			res.Status.User.Username = "alice@example.com"
			res.Status.Audiences = req.Spec.Audiences
		case req.Spec.Token == "down":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(res)
	}))
}

func TestTokenReview(t *testing.T) {
	srv := fakeAPIServer(t)
	defer srv.Close()
	own := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(own, []byte("store-own-token\n"), 0o600)
	a := &TokenReview{APIServer: srv.URL, Audience: "pathops-artifact-store", TokenFile: own, Client: srv.Client()}
	ctx := context.Background()

	p, err := a.Authenticate(ctx, "good")
	if err != nil || p.Subject != "system:serviceaccount:app-a:app-a-build" || p.Pod != "build-pod" {
		t.Fatal(p, err)
	}
	for _, tok := range []string{"", "other-aud", "user", "forged", string(make([]byte, MaxTokenLength+1))} {
		if _, err := a.Authenticate(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%.20q: %v", tok, err)
		}
	}
	if _, err := a.Authenticate(ctx, "down"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	// The store's own credential is wrong: unavailable, never "authenticated".
	_ = os.WriteFile(own, []byte("stale"), 0o600)
	if _, err := a.Authenticate(ctx, "good"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

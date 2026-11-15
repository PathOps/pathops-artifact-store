// Command artifact-store runs the PathOps Artifact Store: a Cell tool, served
// over HTTPS, that stores immutable, opaque artifact bundles behind the
// ArtifactStore abstraction (internal/store), with the filesystem backend
// (internal/store/fsstore) on the Cell's persistent volume. Workloads present
// Application-scoped tokens Dex issues (internal/workload); people sign in
// with the Cell's Dex (internal/human). The configuration comes from the
// environment (internal/config).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/PathOps/pathops-artifact-store/internal/config"
	"github.com/PathOps/pathops-artifact-store/internal/human"
	"github.com/PathOps/pathops-artifact-store/internal/server"
	"github.com/PathOps/pathops-artifact-store/internal/store/fsstore"
	"github.com/PathOps/pathops-artifact-store/internal/workload"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("artifact store failed", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	shutdownTimeout := flag.Duration("shutdown-timeout", 30*time.Second, "graceful shutdown timeout")
	flag.Parse()

	st, err := fsstore.Open(filepath.Join(cfg.DataDir, "store"))
	if err != nil {
		return err
	}
	defer st.Close()
	pub, err := workload.LoadPublicKey(cfg.TokenPublicKeyFile)
	if err != nil {
		return err
	}
	secret, err := os.ReadFile(cfg.OIDCSecretFile)
	if err != nil {
		return err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.OIDCCAFile != "" {
		ca, err := os.ReadFile(cfg.OIDCCAFile)
		if err != nil {
			return err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(ca) {
			return errors.New("PATHOPS_ARTIFACT_STORE_OIDC_CA_FILE holds no certificate")
		}
		tr.TLSClientConfig.RootCAs = roots
	}
	people, err := human.New(human.Config{Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID,
		ClientSecret: strings.TrimSpace(string(secret)), PublicURL: cfg.PublicURL,
		HTTP: &http.Client{Timeout: cfg.OIDCHTTPSTimeout, Transport: tr}})
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return err
	}
	handler := &server.Server{Name: cfg.StoreName, Store: st,
		Workload: &workload.Verifier{Issuer: cfg.TokenIssuer, Audience: cfg.TokenAudience, KeyID: cfg.TokenKeyID, Key: pub, Now: time.Now},
		Human:    people, Admins: cfg.AdminEmails,
		MaxObjectBytes: cfg.MaxObjectBytes, RequestTimeout: cfg.RequestTimeout, Log: log}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("configuration", "name", cfg.StoreName, "dataDir", cfg.DataDir, "publicUrl", cfg.PublicURL,
		"tokenIssuer", cfg.TokenIssuer, "tokenAudience", cfg.TokenAudience, "tokenKeyId", cfg.TokenKeyID,
		"oidcIssuer", cfg.OIDCIssuer, "oidcClientId", cfg.OIDCClientID, "admins", cfg.AdminEmails,
		"maxObjectBytes", cfg.MaxObjectBytes, "requestTimeout", cfg.RequestTimeout.String())
	ln, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return err
	}
	// No overall read/write timeouts: bundles stream for as long as
	// RequestTimeout allows, set per request by the handler.
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	log.Info("listening", "addr", ln.Addr().String())
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down", "timeout", shutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped")
	return nil
}

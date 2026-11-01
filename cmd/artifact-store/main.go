// Command artifact-store runs the PathOps Artifact Store: a Cell-internal
// HTTPS service that stores immutable, opaque artifact bundles behind the
// ArtifactStore abstraction (internal/store), with the filesystem backend
// (internal/store/fsstore) on the Cell's persistent volume. Workloads
// authenticate with Kubernetes ServiceAccount tokens (TokenReview) and act
// within attempt-scoped capabilities (internal/capability). The configuration
// comes from the environment (internal/config).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/PathOps/pathops-artifact-store/internal/auth"
	"github.com/PathOps/pathops-artifact-store/internal/capability"
	"github.com/PathOps/pathops-artifact-store/internal/config"
	"github.com/PathOps/pathops-artifact-store/internal/server"
	"github.com/PathOps/pathops-artifact-store/internal/store/fsstore"
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
	key, err := capability.LoadOrCreateKey(filepath.Join(cfg.DataDir, "capability.key"))
	if err != nil {
		return err
	}
	signer, err := capability.NewSigner(key)
	if err != nil {
		return err
	}
	tr, err := auth.InCluster(cfg.Audience)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return err
	}
	admins := map[string]bool{}
	for _, a := range cfg.Admins {
		admins[a] = true
	}
	handler := &server.Server{Name: cfg.StoreName, Store: st, Auth: tr, Signer: signer, Admins: admins,
		MaxObjectBytes: cfg.MaxObjectBytes, MaxTTL: cfg.MaxTTL, RequestTimeout: cfg.RequestTimeout, Log: log}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("configuration", "name", cfg.StoreName, "dataDir", cfg.DataDir, "audience", cfg.Audience, "admins", cfg.Admins,
		"maxObjectBytes", cfg.MaxObjectBytes, "maxCapabilityTtl", cfg.MaxTTL.String(), "requestTimeout", cfg.RequestTimeout.String())
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

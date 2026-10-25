// Package server wires configuration, engine, admission handler, metrics,
// audit log and HTTPS listener into a running webhook, and hot-reloads the
// policy set when its source files change.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/SlateGitOrg/admitly/internal/admission"
	"github.com/SlateGitOrg/admitly/internal/audit"
	"github.com/SlateGitOrg/admitly/internal/config"
	"github.com/SlateGitOrg/admitly/internal/engine"
	"github.com/SlateGitOrg/admitly/internal/metrics"
	"github.com/SlateGitOrg/admitly/internal/signature"
	"github.com/SlateGitOrg/admitly/internal/webhook"
)

// Server is an assembled admitly webhook.
type Server struct {
	cfg     *config.Config
	log     *slog.Logger
	Engine  *engine.Engine
	Handler *admission.Handler
	Metrics *metrics.Metrics
	// Mux serves every HTTP route; usable without TLS in tests.
	Mux http.Handler

	auditFile io.Closer

	mu          sync.Mutex
	fingerprint string
}

// New builds a Server from cfg and loads the initial policy set. It fails if
// the policies do not compile: a webhook must not start without policies.
func New(cfg *config.Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{cfg: cfg, log: log, Metrics: metrics.New()}

	var verifier *signature.Verifier
	if dir := cfg.Resolve(cfg.Signatures.StoreDir); dir != "" {
		verifier = signature.NewVerifier(signature.DirStore{Root: dir}, cfg.Signatures.CacheSize, cfg.Signatures.CacheTTL.Duration)
	}
	eng, err := engine.New(engine.Options{
		CostLimit: cfg.CEL.CostLimit,
		Verifier:  verifier,
		Logger:    log,
		Observer:  s.Metrics.PolicyObserver(),
	})
	if err != nil {
		return nil, err
	}
	s.Engine = eng

	auditLog, closer, err := openAudit(cfg.Resolve(cfg.Audit.File))
	if err != nil {
		return nil, err
	}
	s.auditFile = closer

	s.Handler, err = admission.New(admission.Options{
		Engine:      eng,
		FailureMode: cfg.FailureMode,
		Timeout:     cfg.Timeout.Duration,
		Audit:       auditLog,
		Metrics:     s.Metrics,
		Logger:      log,
	})
	if err != nil {
		return nil, err
	}
	s.Mux = webhook.NewMux(webhook.Options{
		Handler:      s.Handler,
		Metrics:      s.Metrics,
		Logger:       log,
		MaxBodyBytes: cfg.MaxRequestBytes,
		Ready: func() error {
			if eng.PolicySet() == nil {
				return engine.ErrNoPolicies
			}
			return nil
		},
	})
	if _, err := s.Reload(true); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func openAudit(path string) (*audit.Logger, io.Closer, error) {
	switch path {
	case "":
		return nil, nil, nil
	case "-":
		return audit.New(os.Stdout), nil, nil
	default:
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("opening audit log: %w", err)
		}
		return audit.New(f), f, nil
	}
}

// Reload re-reads the policy sources when their fingerprint changed (or
// always, with force) and atomically installs the new set. It reports
// whether a new set was installed. On error the previous set stays active.
func (s *Server) Reload(force bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !force {
		fp, err := s.cfg.Fingerprint()
		if err != nil {
			s.Metrics.ObserveReload(err, 0)
			return false, err
		}
		if fp == s.fingerprint {
			return false, nil
		}
	}
	ps, fp, err := s.cfg.LoadPolicies()
	if err == nil {
		var set *engine.PolicySet
		if set, err = s.Engine.Load(ps); err == nil {
			s.fingerprint = fp
			s.Metrics.ObserveReload(nil, set.Generation)
			s.log.Info("policy set loaded", "generation", set.Generation, "policies", set.Names)
			return true, nil
		}
	}
	s.Metrics.ObserveReload(err, 0)
	// Remember the broken fingerprint so the error is logged once per change.
	if bad, ferr := s.cfg.Fingerprint(); ferr == nil {
		s.fingerprint = bad
	}
	return false, fmt.Errorf("loading policies: %w", err)
}

// Run serves HTTPS on ln and polls for policy changes until ctx is cancelled.
func (s *Server) Run(ctx context.Context, ln net.Listener) error {
	tlsCfg, err := webhook.TLSConfig(webhook.TLSOptions{
		CertFile:       s.cfg.Resolve(s.cfg.TLS.CertFile),
		KeyFile:        s.cfg.Resolve(s.cfg.TLS.KeyFile),
		ClientCAFile:   s.cfg.Resolve(s.cfg.TLS.ClientCAFile),
		ReloadInterval: s.cfg.TLS.ReloadInterval.Duration,
	}, s.log)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	if iv := s.cfg.Policies.ReloadInterval.Duration; iv > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.watch(ctx, iv)
		}()
	}
	s.log.Info("admitly webhook listening", "addr", ln.Addr().String(), "failureMode", s.Handler.FailureMode(),
		"timeout", s.Handler.Timeout(), "mtls", s.cfg.TLS.ClientCAFile != "")
	err = webhook.Serve(ctx, ln, s.Mux, tlsCfg, 10*time.Second, s.log)
	cancel()
	wg.Wait()
	return err
}

func (s *Server) watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Reload(false); err != nil {
				s.log.Error("policy reload failed; keeping previous set", "error", err)
			}
		}
	}
}

// Close releases the audit log file.
func (s *Server) Close() error {
	if s.auditFile == nil {
		return nil
	}
	err := s.auditFile.Close()
	s.auditFile = nil
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

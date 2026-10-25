// Package webhook serves the admission endpoints over HTTPS.
//
// Routes:
//
//	POST /validate   AdmissionReview v1 -> validating decision
//	POST /mutate     AdmissionReview v1 -> mutating decision (JSON Patch)
//	GET  /healthz    process liveness
//	GET  /readyz     200 once a policy set is loaded
//	GET  /metrics    Prometheus metrics
package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	kjson "sigs.k8s.io/json"

	"github.com/archit2501/admitly/internal/admission"
	"github.com/archit2501/admitly/internal/metrics"
	"github.com/archit2501/admitly/internal/tlsutil"
)

// DefaultMaxBodyBytes matches the API server's 3 MiB request size limit.
const DefaultMaxBodyBytes = 3 << 20

// deadlineShare is the fraction of the API server's ?timeout= budget the
// handler allows itself, leaving headroom for network and serialisation.
const deadlineShare = 0.8

// Options configure the HTTP layer.
type Options struct {
	Handler      *admission.Handler
	Metrics      *metrics.Metrics
	Logger       *slog.Logger
	MaxBodyBytes int64
	// Ready reports whether the server can answer reviews (policies loaded).
	Ready func() error
}

// NewMux returns the HTTP handler with every route registered.
func NewMux(opts Options) http.Handler {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &server{opts: opts}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /validate", s.review(admission.Validate))
	mux.HandleFunc("POST /mutate", s.review(admission.Mutate))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", s.readyz)
	if opts.Metrics != nil {
		mux.Handle("GET /metrics", opts.Metrics.Handler())
	}
	return mux
}

type server struct {
	opts Options
}

func (s *server) readyz(w http.ResponseWriter, _ *http.Request) {
	if s.opts.Ready != nil {
		if err := s.opts.Ready(); err != nil {
			http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	_, _ = w.Write([]byte("ok\n"))
}

func (s *server) badRequest(w http.ResponseWriter, code int, reason, msg string) {
	if s.opts.Metrics != nil {
		s.opts.Metrics.ObserveBadRequest(reason)
	}
	s.opts.Logger.Warn("rejected admission HTTP request", "reason", reason, "detail", msg)
	http.Error(w, msg, code)
}

func (s *server) review(ep admission.Endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" {
			s.badRequest(w, http.StatusUnsupportedMediaType, "content_type", "Content-Type must be application/json")
			return
		}
		body := http.MaxBytesReader(w, r.Body, s.opts.MaxBodyBytes)
		var review admissionv1.AdmissionReview
		dec := kjson.NewDecoderCaseSensitivePreserveInts(body)
		if err := dec.Decode(&review); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				s.badRequest(w, http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("request body exceeds %d bytes", s.opts.MaxBodyBytes))
				return
			}
			s.badRequest(w, http.StatusBadRequest, "decode", "decoding AdmissionReview: "+err.Error())
			return
		}

		ctx := r.Context()
		if budget, ok := apiServerBudget(r); ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, budget)
			defer cancel()
		}
		resp, err := s.opts.Handler.Review(ctx, ep, &review)
		if err != nil {
			s.badRequest(w, http.StatusBadRequest, "malformed_review", err.Error())
			return
		}
		out, err := json.Marshal(resp)
		if err != nil {
			s.opts.Logger.Error("encoding AdmissionReview response", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}
}

// apiServerBudget reads the ?timeout= parameter the API server appends to
// webhook calls and returns the share of it the handler may use.
func apiServerBudget(r *http.Request) (time.Duration, bool) {
	raw := r.URL.Query().Get("timeout")
	if raw == "" {
		return 0, false
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, false
	}
	return time.Duration(float64(d) * deadlineShare), true
}

// TLSOptions configure the HTTPS listener.
type TLSOptions struct {
	CertFile string
	KeyFile  string
	// ClientCAFile, when set, requires and verifies client certificates
	// (configure the API server's admission kubeconfig to present one).
	ClientCAFile   string
	ReloadInterval time.Duration
}

// TLSConfig builds the server TLS configuration with hot certificate reload.
func TLSConfig(o TLSOptions, log *slog.Logger) (*tls.Config, error) {
	if o.ReloadInterval <= 0 {
		o.ReloadInterval = 30 * time.Second
	}
	reloader, err := tlsutil.NewReloader(o.CertFile, o.KeyFile, o.ReloadInterval, log)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: reloader.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
	if o.ClientCAFile != "" {
		data, err := os.ReadFile(o.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("client CA file contains no certificates")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// Serve runs an HTTPS server on ln until ctx is cancelled, then shuts down
// gracefully, letting in-flight reviews finish for up to drain.
func Serve(ctx context.Context, ln net.Listener, h http.Handler, tlsCfg *tls.Config, drain time.Duration, log *slog.Logger) error {
	srv := &http.Server{
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), drain)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

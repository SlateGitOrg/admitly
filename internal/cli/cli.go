// Package cli implements the admitly command-line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/archit2501/admitly/internal/config"
	"github.com/archit2501/admitly/internal/server"
)

// Version is set at build time with -ldflags "-X .../cli.Version=...".
var Version = "dev"

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout, stderr io.Writer) error
}

func commands() []command {
	return []command{
		{"serve", "run the admission webhook server", runServe},
		{"eval", "evaluate manifests or AdmissionReviews offline (mutate, then validate)", runEval},
		{"lint", "load and compile policies, reporting every error", runLint},
		{"certs", "generate a CA and webhook serving certificate", runCerts},
		{"keygen", "generate an ECDSA P-256 signing key pair (lab use)", runKeygen},
		{"sign", "sign pinned images into a signature store (lab use)", runSign},
		{"verify", "verify pinned images against a public key and signature store", runVerify},
		{"bench", "measure end-to-end webhook latency over TLS on loopback", runBench},
		{"version", "print the version", func(_ context.Context, _ []string, stdout, _ io.Writer) error {
			_, err := fmt.Fprintln(stdout, "admitly", Version)
			return err
		}},
	}
}

// errUsage marks errors caused by bad arguments; Run exits 2 for them.
var errUsage = errors.New("usage error")

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, args, stdout, stderr)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	for _, c := range commands() {
		if c.name != args[0] {
			continue
		}
		err := c.run(ctx, args[1:], stdout, stderr)
		switch {
		case err == nil:
			return 0
		case errors.Is(err, flag.ErrHelp):
			return 0
		case errors.Is(err, errUsage):
			fmt.Fprintf(stderr, "admitly %s: %v\n", c.name, err)
			return 2
		case errors.Is(err, errDenied):
			return 1
		default:
			fmt.Fprintf(stderr, "admitly %s: %v\n", c.name, err)
			return 1
		}
	}
	fmt.Fprintf(stderr, "admitly: unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "admitly - Kubernetes admission webhook with a CEL policy engine")
	fmt.Fprintln(w, "\nUsage: admitly <command> [flags]\n\nCommands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-8s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\nRun 'admitly <command> -h' for command flags.")
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("admitly "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	return nil
}

// discardLogger is used by offline commands, which report through stdout.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newLogger(level string, w io.Writer) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
}

func runServe(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := newFlagSet("serve", stderr)
	cfgPath := fs.String("config", "", "path to the configuration file (required)")
	listen := fs.String("listen", "", "override the listen address from the config")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("%w: --config is required", errUsage)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	log := newLogger(cfg.LogLevel, stderr)
	srv, err := server.New(cfg, log)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.Listen, err)
	}
	return srv.Run(ctx, ln)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

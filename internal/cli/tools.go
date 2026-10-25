package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/SlateGitOrg/admitly/internal/imageref"
	"github.com/SlateGitOrg/admitly/internal/policy"
	"github.com/SlateGitOrg/admitly/internal/signature"
	"github.com/SlateGitOrg/admitly/internal/tlsutil"
)

func runLint(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("lint", stderr)
	var pf policyFlags
	pf.register(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	pf.dirs = append(pf.dirs, fs.Args()...)
	ps, eng, err := pf.load()
	if err != nil {
		return err
	}
	if _, err := eng.Compile(ps); err != nil {
		return err
	}
	policy.SortByName(ps)
	for _, p := range ps {
		fmt.Fprintf(stdout, "ok  %-26s %-24s mode=%-8s failurePolicy=%-6s %s\n",
			p.Metadata.Name, p.Kind, p.EffectiveMode(), p.EffectiveFailurePolicy(), p.Source)
	}
	fmt.Fprintf(stdout, "%d policies compiled\n", len(ps))
	return nil
}

func runCerts(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("certs", stderr)
	hosts := fs.String("hosts", "admitly.admitly-system.svc", "comma-separated DNS names and IPs for the serving certificate")
	out := fs.String("out", "certs", "output directory for ca.crt, tls.crt and tls.key")
	days := fs.Int("days", 365, "validity in days")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	hs := splitList(*hosts)
	if len(hs) == 0 || *days <= 0 {
		return fmt.Errorf("%w: --hosts and a positive --days are required", errUsage)
	}
	b, err := tlsutil.GenerateServing(hs, time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	if err := b.WriteServing(*out); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s/{ca.crt,tls.crt,tls.key} for %v (valid %d days)\n", *out, hs, *days)
	fmt.Fprintln(stdout, "use ca.crt (base64) as caBundle in the webhook configurations")
	return nil
}

func runKeygen(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keygen", stderr)
	out := fs.String("out", ".", "output directory for cosign.key and cosign.pub")
	force := fs.Bool("force", false, "overwrite existing key files")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	keyPath, pubPath := filepath.Join(*out, "cosign.key"), filepath.Join(*out, "cosign.pub")
	if !*force {
		for _, p := range []string{keyPath, pubPath} {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("%s exists (use --force to overwrite)", p)
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil { //nolint:gosec // a public key is meant to be world-readable
		return err
	}
	pk, err := signature.ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s (0600, unencrypted: lab use only) and %s\nkey id %s\n", keyPath, pubPath, pk.ID)
	return nil
}

func runSign(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("sign", stderr)
	keyPath := fs.String("key", "cosign.key", "PEM private key (PKCS#8 or SEC1, unencrypted)")
	store := fs.String("store", "", "signature store directory (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *store == "" || fs.NArg() == 0 {
		return fmt.Errorf("%w: usage: admitly sign --key KEY --store DIR IMAGE@sha256:<digest>", errUsage)
	}
	data, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	signer, err := signature.ParsePrivateKey(data)
	if err != nil {
		return err
	}
	st := signature.DirStore{Root: *store}
	for _, img := range fs.Args() {
		ref, err := imageref.Parse(img)
		if err != nil {
			return err
		}
		sig, err := signature.Sign(signer, ref, map[string]any{"signedBy": "admitly sign"})
		if err != nil {
			return fmt.Errorf("%s: %w", img, err)
		}
		if err := st.Put(ref, sig); err != nil {
			return err
		}
		path, _ := st.Path(ref)
		fmt.Fprintf(stdout, "signed %s -> %s\n", ref, path)
	}
	return nil
}

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("verify", stderr)
	keyPath := fs.String("key", "cosign.pub", "PEM public key")
	store := fs.String("store", "", "signature store directory (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *store == "" || fs.NArg() == 0 {
		return fmt.Errorf("%w: usage: admitly verify --key PUB --store DIR IMAGE@sha256:<digest>", errUsage)
	}
	data, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	key, err := signature.ParsePublicKey(data)
	if err != nil {
		return err
	}
	v := signature.NewVerifier(signature.DirStore{Root: *store}, 0, 0)
	var failed bool
	for _, img := range fs.Args() {
		ref, err := imageref.Parse(img)
		if err != nil {
			fmt.Fprintf(stdout, "FAIL %s: %v\n", img, err)
			failed = true
			continue
		}
		res, err := v.Verify(ctx, ref, []*signature.PublicKey{key})
		if err != nil {
			fmt.Fprintf(stdout, "FAIL %v\n", err)
			failed = true
			continue
		}
		fmt.Fprintf(stdout, "OK   %s (key %s)\n", ref, res.KeyID)
	}
	if failed {
		return errors.New("verification failed")
	}
	return nil
}

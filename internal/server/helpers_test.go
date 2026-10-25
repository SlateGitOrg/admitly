package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/SlateGitOrg/admitly/internal/config"
	"github.com/SlateGitOrg/admitly/internal/imageref"
	"github.com/SlateGitOrg/admitly/internal/signature"
)

// signedImage is the only image the test signature store holds a signature for.
const signedImage = "registry.lab.local/team/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const verifyPolicy = `apiVersion: admitly.dev/v1alpha1
kind: ImageVerificationPolicy
metadata:
  name: verify-images
spec:
  mode: Enforce
  severity: critical
  match:
    resources:
      - apiGroups: [""]
        kinds: [Pod]
  verification:
    rules:
      - images: ["registry.lab.local/**"]
        keyFiles: [cosign.pub]
`

// fixture creates a signing key, a verification policy that trusts it and a
// signature store holding a signature for signedImage. It returns a config
// that loads the built-ins, the golden custom policies and that policy.
func fixture(t testing.TB) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	polDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(polDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(polDir, "cosign.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	mustWrite(t, filepath.Join(polDir, "verify-images.yaml"), []byte(verifyPolicy))

	ref, err := imageref.Parse(signedImage)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signature.Sign(priv, ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := signature.DirStore{Root: filepath.Join(dir, "store")}
	if err := store.Put(ref, sig); err != nil {
		t.Fatal(err)
	}

	golden, err := filepath.Abs(filepath.Join("..", "..", "testdata", "golden", "policies"))
	if err != nil {
		t.Fatal(err)
	}
	cfgYAML := `
failureMode: Closed
timeout: 3s
policies:
  builtin: true
  dirs: [` + golden + `, policies]
  reloadInterval: 0s
signatures:
  storeDir: store
audit:
  file: audit.log
`
	cfgPath := filepath.Join(dir, "admitly.yaml")
	mustWrite(t, cfgPath, []byte(cfgYAML))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, dir
}

func mustWrite(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}

func newServer(t testing.TB, cfg *config.Config) *Server {
	t.Helper()
	s, err := New(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

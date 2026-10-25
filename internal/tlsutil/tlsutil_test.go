package tlsutil

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateServingVerifies(t *testing.T) {
	b, err := GenerateServing([]string{"admitly.admitly-system.svc", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"admitly.admitly-system.svc", "127.0.0.1"} {
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: host, Roots: b.CertPool()}); err != nil {
			t.Errorf("verify %s: %v", host, err)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "evil.example", Roots: b.CertPool()}); err == nil {
		t.Error("certificate must not verify for other hosts")
	}
	if _, err := b.TLSCertificate(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := b.WriteServing(dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "tls.key"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("tls.key mode: %v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); !os.IsNotExist(err) {
		t.Fatal("CA key must not be written")
	}
}

func TestIssueErrors(t *testing.T) {
	ca, err := GenerateCA("ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Issue("x", nil, false, time.Hour); err == nil {
		t.Fatal("serving cert without hosts must fail")
	}
	client, err := ca.Issue("client", nil, true, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Bundle{}).Issue("x", []string{"a"}, false, time.Hour); err == nil {
		t.Fatal("bundle without CA key must fail")
	}
	block, _ := pem.Decode(client.CertPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("client cert must have client auth usage")
	}
	if err := client.WriteServing(filepath.Join(t.TempDir(), "f\x00")); err == nil {
		t.Fatal("invalid dir must fail")
	}
}

func TestReloaderPicksUpRotation(t *testing.T) {
	dir := t.TempDir()
	first, _ := GenerateServing([]string{"localhost"}, time.Hour)
	if err := first.WriteServing(dir); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	r, err := NewReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), time.Second, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	c1, _ := r.GetCertificate(&tls.ClientHelloInfo{})

	second, _ := GenerateServing([]string{"localhost"}, time.Hour)
	if err := second.WriteServing(dir); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	for _, f := range []string{"tls.crt", "tls.key"} {
		if err := os.Chtimes(filepath.Join(dir, f), future, future); err != nil {
			t.Fatal(err)
		}
	}
	if c, _ := r.GetCertificate(nil); !bytes.Equal(c.Certificate[0], c1.Certificate[0]) {
		t.Fatal("reloaded before the interval elapsed")
	}
	now = now.Add(2 * time.Second)
	c2, _ := r.GetCertificate(nil)
	if bytes.Equal(c2.Certificate[0], c1.Certificate[0]) {
		t.Fatal("rotation not picked up")
	}

	// A broken rotation keeps serving the last good certificate.
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := future.Add(time.Minute)
	_ = os.Chtimes(filepath.Join(dir, "tls.crt"), later, later)
	now = now.Add(2 * time.Second)
	c3, _ := r.GetCertificate(nil)
	if !bytes.Equal(c3.Certificate[0], c2.Certificate[0]) {
		t.Fatal("broken rotation replaced the certificate")
	}
	if !bytes.Contains(logs.Bytes(), []byte("reload failed")) {
		t.Fatalf("expected reload failure log, got %s", logs.String())
	}
	if _, err := NewReloader(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "tls.key"), time.Second, nil); err == nil {
		t.Fatal("missing cert must fail")
	}
}

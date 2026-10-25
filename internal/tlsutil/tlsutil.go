// Package tlsutil generates the self-signed CA and serving certificate a
// webhook needs, and reloads serving certificates from disk when they rotate.
package tlsutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Bundle is a CA plus a leaf certificate it issued, all PEM-encoded.
type Bundle struct {
	CACert   []byte
	CAKey    []byte
	CertPEM  []byte
	KeyPEM   []byte
	caCert   *x509.Certificate
	caSigner crypto.Signer
}

// GenerateCA creates a self-signed ECDSA P-256 CA valid for validity.
func GenerateCA(commonName string, validity time.Duration) (*Bundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"admitly"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		CACert:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CAKey:    keyPEM,
		caCert:   cert,
		caSigner: key,
	}, nil
}

// Issue creates a leaf certificate signed by the CA in b. hosts may contain
// DNS names and IP addresses; client selects ExtKeyUsageClientAuth instead of
// ServerAuth. The returned bundle shares b's CA.
func (b *Bundle) Issue(commonName string, hosts []string, client bool, validity time.Duration) (*Bundle, error) {
	if b.caSigner == nil {
		return nil, errors.New("bundle has no CA key")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"admitly"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if !client && len(hosts) == 0 {
		return nil, errors.New("a serving certificate needs at least one host")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, b.caCert, &key.PublicKey, b.caSigner)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		CACert:   b.CACert,
		CAKey:    b.CAKey,
		CertPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:   keyPEM,
		caCert:   b.caCert,
		caSigner: b.caSigner,
	}, nil
}

// GenerateServing creates a fresh CA and a serving certificate for hosts.
func GenerateServing(hosts []string, validity time.Duration) (*Bundle, error) {
	ca, err := GenerateCA("admitly-webhook-ca", validity)
	if err != nil {
		return nil, err
	}
	cn := "admitly"
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	return ca.Issue(cn, hosts, false, validity)
}

// WriteServing writes ca.crt, tls.crt and tls.key into dir. The CA private
// key is deliberately not written: rotation regenerates the whole bundle, so
// no long-lived CA key sits next to the webhook.
func (b *Bundle) WriteServing(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"ca.crt", b.CACert, 0o644},
		{"tls.crt", b.CertPEM, 0o644},
		{"tls.key", b.KeyPEM, 0o600},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return fmt.Errorf("writing %s: %w", f.name, err)
		}
	}
	return nil
}

// TLSCertificate returns the leaf as a tls.Certificate.
func (b *Bundle) TLSCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(b.CertPEM, b.KeyPEM)
}

// CertPool returns a pool containing the bundle's CA.
func (b *Bundle) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b.CACert)
	return pool
}

func encodeKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		// crypto/rand failing is unrecoverable for a TLS component.
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return n
}

// Reloader serves a certificate pair from disk and re-reads it when either
// file's modification time changes, so cert-manager style rotation needs no
// restart. A failed reload keeps the previous certificate.
type Reloader struct {
	certFile, keyFile string
	interval          time.Duration
	log               *slog.Logger

	mu        sync.Mutex
	cert      *tls.Certificate
	modTime   time.Time
	lastCheck time.Time
	now       func() time.Time
}

// NewReloader loads the pair once and returns a Reloader that checks for
// changes at most once per interval.
func NewReloader(certFile, keyFile string, interval time.Duration, log *slog.Logger) (*Reloader, error) {
	if log == nil {
		log = slog.Default()
	}
	r := &Reloader{certFile: certFile, keyFile: keyFile, interval: interval, log: log, now: time.Now}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Reloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("loading TLS key pair: %w", err)
	}
	r.cert = &cert
	r.modTime = r.latestModTime()
	r.lastCheck = r.now()
	return nil
}

func (r *Reloader) latestModTime() time.Time {
	var latest time.Time
	for _, f := range []string{r.certFile, r.keyFile} {
		if st, err := os.Stat(f); err == nil && st.ModTime().After(latest) {
			latest = st.ModTime()
		}
	}
	return latest
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.now().Sub(r.lastCheck) >= r.interval {
		r.lastCheck = r.now()
		if mt := r.latestModTime(); mt.After(r.modTime) {
			old := r.cert
			if err := r.load(); err != nil {
				r.cert = old
				r.log.Error("TLS certificate reload failed; keeping previous certificate", "error", err)
			} else {
				r.log.Info("TLS certificate reloaded", "certFile", r.certFile)
			}
		}
	}
	return r.cert, nil
}

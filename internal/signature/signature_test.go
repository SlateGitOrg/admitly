package signature

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/archit2501/admitly/internal/imageref"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func mustRef(t *testing.T, s string) imageref.Ref {
	t.Helper()
	r, err := imageref.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func pubPEM(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func mustPub(t *testing.T, signer crypto.Signer) *PublicKey {
	t.Helper()
	k, err := ParsePublicKey(pubPEM(t, signer.Public()))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signers(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	return map[string]crypto.Signer{"p256": p256, "p384": p384, "ed25519": ed, "rsa": rk}
}

func TestSignVerifyAllKeyTypes(t *testing.T) {
	ref := mustRef(t, "registry.lab.local/team/app@"+testDigest)
	for name, s := range signers(t) {
		store := DirStore{Root: t.TempDir()}
		sig, err := Sign(s, ref, map[string]any{"build": "42"})
		if err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		if err := store.Put(ref, sig); err != nil {
			t.Fatal(err)
		}
		v := NewVerifier(store, 0, 0)
		res, err := v.Verify(context.Background(), ref, []*PublicKey{mustPub(t, s)})
		if err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
		if !strings.HasPrefix(res.KeyID, "sha256:") || res.Cached {
			t.Fatalf("%s: unexpected result %+v", name, res)
		}
	}
}

func TestP384CurveDigestAccepted(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	payload := []byte("payload")
	sig, err := ecdsa.SignASN1(rand.Reader, k, curveDigest(&k.PublicKey, payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := mustPub(t, k).VerifySignature(payload, sig); err != nil {
		t.Fatalf("SHA-384 signature from a P-384 key must verify: %v", err)
	}
	k521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	sig, _ = ecdsa.SignASN1(rand.Reader, k521, curveDigest(&k521.PublicKey, payload))
	if err := mustPub(t, k521).VerifySignature(payload, sig); err != nil {
		t.Fatalf("SHA-512 signature from a P-521 key must verify: %v", err)
	}
}

func TestVerifyFailures(t *testing.T) {
	ctx := context.Background()
	ref := mustRef(t, "registry.lab.local/team/app@"+testDigest)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := mustPub(t, key)

	put := func(t *testing.T, sigs ...Signature) *Verifier {
		store := DirStore{Root: t.TempDir()}
		for _, s := range sigs {
			if err := store.Put(ref, s); err != nil {
				t.Fatal(err)
			}
		}
		return NewVerifier(store, 10, time.Minute)
	}
	signPayload := func(p []byte, k crypto.Signer) Signature {
		raw, err := SignPayload(k, p)
		if err != nil {
			t.Fatal(err)
		}
		return Signature{Base64Signature: base64.StdEncoding.EncodeToString(raw), Payload: p}
	}
	good, _ := NewPayload(ref, nil)
	otherRepo, _ := NewPayload(mustRef(t, "registry.lab.local/team/evil@"+testDigest), nil)
	otherDigest, _ := NewPayload(mustRef(t, "registry.lab.local/team/app@sha256:"+strings.Repeat("f", 64)), nil)
	var wrongType Payload
	_ = json.Unmarshal(good, &wrongType)
	wrongType.Critical.Type = "something else"
	wrongTypeJSON, _ := json.Marshal(wrongType)

	cases := []struct {
		name string
		v    *Verifier
		ref  imageref.Ref
		keys []*PublicKey
		want error
	}{
		{"unpinned", put(t), mustRef(t, "registry.lab.local/team/app:v1"), []*PublicKey{pub}, ErrNotPinned},
		{"no keys", put(t), ref, nil, ErrNoValidSignature},
		{"no signatures", put(t), ref, []*PublicKey{pub}, ErrNoSignatures},
		{"wrong key", put(t, signPayload(good, other)), ref, []*PublicKey{pub}, ErrNoValidSignature},
		{"repo mismatch", put(t, signPayload(otherRepo, key)), ref, []*PublicKey{pub}, ErrNoValidSignature},
		{"digest mismatch", put(t, signPayload(otherDigest, key)), ref, []*PublicKey{pub}, ErrNoValidSignature},
		{"wrong type", put(t, signPayload(wrongTypeJSON, key)), ref, []*PublicKey{pub}, ErrNoValidSignature},
		{"garbage payload", put(t, signPayload([]byte("{"), key)), ref, []*PublicKey{pub}, ErrNoValidSignature},
		{"bad base64", put(t, Signature{Base64Signature: "!!", Payload: good}), ref, []*PublicKey{pub}, ErrNoValidSignature},
		{"tampered payload", put(t, Signature{Base64Signature: signPayload(good, key).Base64Signature, Payload: append([]byte(nil), otherRepo...)}), ref, []*PublicKey{pub}, ErrNoValidSignature},
	}
	for _, tc := range cases {
		_, err := tc.v.Verify(ctx, tc.ref, tc.keys)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		if !IsTrustFailure(err) {
			t.Errorf("%s: should be a trust failure", tc.name)
		}
	}
	// A good signature after bad ones still verifies.
	v := put(t, signPayload(good, other), signPayload(good, key))
	if _, err := v.Verify(ctx, ref, []*PublicKey{pub}); err != nil {
		t.Fatalf("second signature should verify: %v", err)
	}
}

func TestStoreErrors(t *testing.T) {
	ref := mustRef(t, "registry.lab.local/team/app@"+testDigest)
	root := t.TempDir()
	store := DirStore{Root: root}
	path, err := store.Path(ref)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "registry.lab.local", "team", "app", "sha256-"+testDigest[7:]+".sig"); path != want {
		t.Fatalf("path = %s, want %s", path, want)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("\n{not json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(store, 0, 0)
	_, err = v.Verify(context.Background(), ref, []*PublicKey{mustPub(t, signers(t)["ed25519"])})
	if err == nil || IsTrustFailure(err) {
		t.Fatalf("malformed store must be an infrastructure error, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Signatures(ctx, ref); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if _, err := store.Path(mustRef(t, "registry.lab.local/app:v1")); !errors.Is(err, ErrNotPinned) {
		t.Fatal("unpinned path must fail")
	}
	if err := store.Put(mustRef(t, "registry.lab.local/app:v1"), Signature{}); err == nil {
		t.Fatal("unpinned put must fail")
	}
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := DirStore{Root: filepath.Join(root, "file")}
	if err := blocked.Put(ref, Signature{}); err == nil {
		t.Fatal("put under a file must fail")
	}
}

func TestVerifierCache(t *testing.T) {
	ref := mustRef(t, "registry.lab.local/team/app@"+testDigest)
	k := signers(t)["ed25519"]
	store := DirStore{Root: t.TempDir()}
	sig, _ := Sign(k, ref, nil)
	_ = store.Put(ref, sig)
	v := NewVerifier(store, 10, time.Hour)
	keys := []*PublicKey{mustPub(t, k)}
	if r, err := v.Verify(context.Background(), ref, keys); err != nil || r.Cached {
		t.Fatalf("first: %+v %v", r, err)
	}
	// Remove the store: a cached positive result must still be served.
	v.store = DirStore{Root: filepath.Join(t.TempDir(), "gone")}
	if r, err := v.Verify(context.Background(), ref, keys); err != nil || !r.Cached {
		t.Fatalf("second: %+v %v", r, err)
	}
}

func TestLRU(t *testing.T) {
	now := time.Unix(0, 0)
	c := newLRU(2, time.Minute, func() time.Time { return now })
	c.put("a", "1")
	c.put("b", "2")
	if _, ok := c.get("a"); !ok {
		t.Fatal("a missing")
	}
	c.put("c", "3") // evicts b (least recently used)
	if _, ok := c.get("b"); ok {
		t.Fatal("b should be evicted")
	}
	c.put("a", "1b")
	if v, _ := c.get("a"); v != "1b" {
		t.Fatalf("a = %q", v)
	}
	now = now.Add(2 * time.Minute)
	if _, ok := c.get("a"); ok {
		t.Fatal("a should be expired")
	}
	if c.len() != 1 {
		t.Fatalf("len = %d", c.len())
	}
}

func TestParseKeys(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, data := range map[string][]byte{
		"empty":     nil,
		"wrong pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		"bad der":   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2}}),
		"small rsa": pubPEM(t, &small.PublicKey),
	} {
		if _, err := ParsePublicKey(data); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: want ErrInvalidKey, got %v", name, err)
		}
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(ec)
	sec1, _ := x509.MarshalECPrivateKey(ec)
	for _, block := range []*pem.Block{{Type: "PRIVATE KEY", Bytes: pkcs8}, {Type: "EC PRIVATE KEY", Bytes: sec1}} {
		if _, err := ParsePrivateKey(pem.EncodeToMemory(block)); err != nil {
			t.Errorf("%s: %v", block.Type, err)
		}
	}
	for _, data := range [][]byte{nil, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED SIGSTORE PRIVATE KEY", Bytes: []byte{1}}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})} {
		if _, err := ParsePrivateKey(data); err == nil {
			t.Errorf("want error for %q", data)
		}
	}
	if _, err := NewPayload(mustRef(t, "nginx:1"), nil); !errors.Is(err, ErrNotPinned) {
		t.Error("NewPayload must require a digest")
	}
}

// TestPayloadShape pins the exact JSON layout of the simple-signing payload,
// which must match what cosign produces and expects.
func TestPayloadShape(t *testing.T) {
	p, err := NewPayload(mustRef(t, "registry.lab.local/team/app:v1@"+testDigest), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"critical":{"identity":{"docker-reference":"registry.lab.local/team/app"},"image":{"docker-manifest-digest":"` + testDigest + `"},"type":"cosign container image signature"},"optional":null}`
	if string(p) != want {
		t.Fatalf("payload\n got %s\nwant %s", p, want)
	}
}

// TestOpenSSLInterop signs a payload with the openssl CLI exactly as
// `cosign sign-blob` does for an ECDSA P-256 key (ASN.1 DER signature over
// SHA-256, base64-encoded) and verifies it with admitly. It is skipped when
// openssl is not installed.
func TestOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	pubPath := filepath.Join(dir, "pub.pem")
	payloadPath := filepath.Join(dir, "payload.json")
	sigPath := filepath.Join(dir, "payload.sig")
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(openssl, args...).CombinedOutput(); err != nil {
			t.Skipf("openssl %v failed (%v): %s", args, err, out)
		}
	}
	run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", keyPath)
	run("ec", "-in", keyPath, "-pubout", "-out", pubPath)
	ref := mustRef(t, "registry.lab.local/team/app@"+testDigest)
	payload, _ := NewPayload(ref, nil)
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	run("dgst", "-sha256", "-sign", keyPath, "-out", sigPath, payloadPath)
	rawSig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	pubData, _ := os.ReadFile(pubPath)
	pub, err := ParsePublicKey(pubData)
	if err != nil {
		t.Fatal(err)
	}
	store := DirStore{Root: t.TempDir()}
	if err := store.Put(ref, Signature{Base64Signature: base64.StdEncoding.EncodeToString(rawSig), Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerifier(store, 0, 0).Verify(context.Background(), ref, []*PublicKey{pub}); err != nil {
		t.Fatalf("openssl-produced signature did not verify: %v", err)
	}
	// And the reverse: an admitly signature verifies with openssl.
	priv, err := ParsePrivateKey(must(os.ReadFile(keyPath)))
	if err != nil {
		t.Fatal(err)
	}
	ours, err := SignPayload(priv, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, ours, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(openssl, "dgst", "-sha256", "-verify", pubPath, "-signature", sigPath, payloadPath).CombinedOutput(); err != nil {
		t.Fatalf("openssl rejected admitly signature: %v %s", err, out)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

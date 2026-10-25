// Package signature verifies container image signatures in the cosign
// "simple signing" format against configured public keys.
//
// A signature is a JSON payload (see Payload) that names the image repository
// and manifest digest, plus a detached signature over that payload. The
// payload/signature pair is stored in the shape `cosign download signature`
// prints ({"Base64Signature": ..., "Payload": ...}), so signatures produced by
// `cosign sign-blob --key` over a payload, or downloaded from a registry with
// cosign, verify unchanged. Keyless (Fulcio/Rekor) verification is out of
// scope: only key-pair signatures are supported.
package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/archit2501/admitly/internal/imageref"
)

// PayloadType is the critical.type value of a cosign container image signature.
const PayloadType = "cosign container image signature"

// Errors returned by verification. They describe why an image is not
// trusted and are reported to the user as policy violations.
var (
	ErrNotPinned        = errors.New("image is not pinned by digest")
	ErrNoSignatures     = errors.New("no signatures found")
	ErrNoValidSignature = errors.New("no valid signature")
	ErrInvalidKey       = errors.New("invalid public key")
)

// Payload is the cosign simple-signing payload.
type Payload struct {
	Critical Critical       `json:"critical"`
	Optional map[string]any `json:"optional"`
}

// Critical holds the fields a verifier must check.
type Critical struct {
	Identity Identity `json:"identity"`
	Image    Image    `json:"image"`
	Type     string   `json:"type"`
}

// Identity names the repository the signature is for.
type Identity struct {
	DockerReference string `json:"docker-reference"`
}

// Image names the manifest digest the signature is for.
type Image struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

// NewPayload builds the canonical payload for a pinned image reference.
func NewPayload(ref imageref.Ref, optional map[string]any) ([]byte, error) {
	if !ref.Pinned() {
		return nil, ErrNotPinned
	}
	return json.Marshal(Payload{
		Critical: Critical{
			Identity: Identity{DockerReference: ref.Name()},
			Image:    Image{DockerManifestDigest: ref.Digest},
			Type:     PayloadType,
		},
		Optional: optional,
	})
}

// Signature is one stored signature, field-compatible with the JSON lines
// printed by `cosign download signature`.
type Signature struct {
	Base64Signature string `json:"Base64Signature"`
	// Payload is the base64-encoded payload (encoding/json encodes []byte as base64).
	Payload []byte `json:"Payload"`
}

// PublicKey is a parsed verification key.
type PublicKey struct {
	key crypto.PublicKey
	// ID is "sha256:<hex>" of the DER-encoded SubjectPublicKeyInfo.
	ID string
}

// ParsePublicKey parses a PEM "PUBLIC KEY" (PKIX) block holding an ECDSA
// (P-256/P-384/P-521), Ed25519 or RSA (>= 2048 bit) key.
func ParsePublicKey(pemData []byte) (*PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrInvalidKey)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%w: PEM type %q, want PUBLIC KEY", ErrInvalidKey, block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("%w: RSA key shorter than 2048 bits", ErrInvalidKey)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported key type %T", ErrInvalidKey, pub)
	}
	sum := sha256.Sum256(block.Bytes)
	return &PublicKey{key: pub, ID: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// VerifySignature checks a detached signature over payload. ECDSA and RSA
// signatures are over the SHA-256 digest of the payload, which is what cosign
// uses for key-pair signatures; for P-384/P-521 keys the curve's default
// SHA-384/SHA-512 digest (used by other sigstore clients) is also accepted.
// Ed25519 signs the payload directly.
func (k *PublicKey) VerifySignature(payload, sig []byte) error {
	switch pub := k.key.(type) {
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(payload)
		if ecdsa.VerifyASN1(pub, sum[:], sig) {
			return nil
		}
		if pub.Curve.Params().BitSize > 256 && ecdsa.VerifyASN1(pub, curveDigest(pub, payload), sig) {
			return nil
		}
		return errors.New("ecdsa signature mismatch")
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, payload, sig) {
			return errors.New("ed25519 signature mismatch")
		}
		return nil
	case *rsa.PublicKey:
		sum := sha256.Sum256(payload)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
			return fmt.Errorf("rsa signature mismatch: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type %T", pub)
	}
}

func curveDigest(pub *ecdsa.PublicKey, payload []byte) []byte {
	var h hash.Hash
	switch pub.Curve.Params().BitSize {
	case 384:
		h = sha512.New384()
	default:
		h = sha512.New()
	}
	h.Write(payload)
	return h.Sum(nil)
}

// CheckPayload verifies that a decoded payload binds the signature to ref.
func CheckPayload(payload []byte, ref imageref.Ref) error {
	var p Payload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("malformed payload: %w", err)
	}
	if p.Critical.Type != PayloadType {
		return fmt.Errorf("payload type %q is not %q", p.Critical.Type, PayloadType)
	}
	if p.Critical.Image.DockerManifestDigest != ref.Digest {
		return fmt.Errorf("payload digest %s does not match image digest %s", p.Critical.Image.DockerManifestDigest, ref.Digest)
	}
	signedRef, err := imageref.Parse(p.Critical.Identity.DockerReference)
	if err != nil {
		return fmt.Errorf("payload docker-reference: %w", err)
	}
	if signedRef.Name() != ref.Name() {
		return fmt.Errorf("payload is for %s, not %s", signedRef.Name(), ref.Name())
	}
	return nil
}

// Sign produces a Signature for ref with signer. It exists for lab use
// (`admitly sign`) and tests; production signing belongs in CI with cosign.
func Sign(signer crypto.Signer, ref imageref.Ref, optional map[string]any) (Signature, error) {
	payload, err := NewPayload(ref, optional)
	if err != nil {
		return Signature{}, err
	}
	sig, err := SignPayload(signer, payload)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Base64Signature: base64.StdEncoding.EncodeToString(sig), Payload: payload}, nil
}

// SignPayload signs raw payload bytes with the same digest conventions
// VerifySignature expects.
func SignPayload(signer crypto.Signer, payload []byte) ([]byte, error) {
	return signWith(signer, payload, rand.Reader)
}

func signWith(signer crypto.Signer, payload []byte, rnd io.Reader) ([]byte, error) {
	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		sum := sha256.Sum256(payload)
		return signer.Sign(rnd, sum[:], crypto.SHA256)
	case ed25519.PublicKey:
		return signer.Sign(rnd, payload, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("unsupported signer key type %T", pub)
	}
}

// ParsePrivateKey parses an unencrypted PKCS#8 "PRIVATE KEY" or SEC1
// "EC PRIVATE KEY" PEM block. Encrypted cosign private keys are not supported.
func ParsePrivateKey(pemData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#8 key: %w", err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key type %T cannot sign", k)
		}
		return s, nil
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing EC key: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q (encrypted cosign keys must be exported first)", block.Type)
	}
}

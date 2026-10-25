package signature

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/SlateGitOrg/admitly/internal/imageref"
)

// Store returns the signatures attached to a pinned image.
type Store interface {
	Signatures(ctx context.Context, ref imageref.Ref) ([]Signature, error)
}

// maxSignatureFile bounds how much of a signature file is read.
const maxSignatureFile = 1 << 20

// DirStore is a filesystem signature store that mirrors cosign's registry
// convention: the signatures of registry/repo@sha256:<hex> live in
// <root>/<registry>/<repo>/sha256-<hex>.sig, one JSON object per line.
// It stands in for an OCI registry so verification runs fully offline.
type DirStore struct {
	Root string
}

// Path returns the signature file path for ref. Repository components are
// validated by imageref.Parse, so they cannot contain ".." or absolute paths.
func (s DirStore) Path(ref imageref.Ref) (string, error) {
	if !ref.Pinned() {
		return "", ErrNotPinned
	}
	algo, hexDigest, ok := strings.Cut(ref.Digest, ":")
	if !ok {
		return "", fmt.Errorf("malformed digest %q", ref.Digest)
	}
	rel := filepath.Join(ref.Registry, filepath.FromSlash(ref.Repository), algo+"-"+hexDigest+".sig")
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("refusing non-local signature path %q", rel)
	}
	return filepath.Join(s.Root, rel), nil
}

// Signatures reads every signature recorded for ref. A missing file is not an
// error: it yields no signatures.
func (s DirStore) Signatures(ctx context.Context, ref imageref.Ref) ([]Signature, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.Path(ref)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening signature store: %w", err)
	}
	defer func() { _ = f.Close() }()

	var out []Signature
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxSignatureFile)
	for line := 1; sc.Scan(); line++ {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var sig Signature
		if err := json.Unmarshal(b, &sig); err != nil {
			return nil, fmt.Errorf("%s:%d: malformed signature record: %w", path, line, err)
		}
		out = append(out, sig)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return out, nil
}

// Put appends a signature for ref, creating directories as needed.
func (s DirStore) Put(ref imageref.Ref, sig Signature) error {
	path, err := s.Path(ref)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating store directory: %w", err)
	}
	line, err := json.Marshal(sig)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // signatures are public; the webhook only reads them
	if err != nil {
		return fmt.Errorf("opening signature file: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing signature: %w", err)
	}
	return f.Close()
}

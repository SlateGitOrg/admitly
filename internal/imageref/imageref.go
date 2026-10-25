// Package imageref parses and normalises OCI / Docker image references.
//
// The grammar follows the distribution reference specification
// (github.com/distribution/reference): an optional registry host, one or more
// lowercase path components, an optional tag and an optional digest. Parsing
// is deliberately strict because policies such as registry allow-lists make
// security decisions on the parsed registry: a lenient parser that accepted
// "registry.example.com.evil.io/app" as belonging to "registry.example.com"
// would turn a typo into a bypass.
package imageref

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// DefaultRegistry is the registry implied when a reference has no host part.
const DefaultRegistry = "docker.io"

// maxNameLength mirrors the 255-character limit on repository names.
const maxNameLength = 255

var (
	pathComponentRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*$`)
	domainRe        = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?))*(?::[0-9]+)?$|^\[[a-fA-F0-9:]+\](?::[0-9]+)?$`)
	tagRe           = regexp.MustCompile(`^[\w][\w.-]{0,127}$`)
	digestRe        = regexp.MustCompile(`^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]{32,}$`)
	sha256HexRe     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// ErrInvalidReference is wrapped by every parse failure.
var ErrInvalidReference = errors.New("invalid image reference")

// Ref is a parsed, normalised image reference.
type Ref struct {
	// Registry is the host (and optional port), e.g. "docker.io" or "registry.lab.local:5000".
	Registry string
	// Repository is the path within the registry, e.g. "library/nginx".
	Repository string
	// Tag is the tag, empty when absent. A reference with only a digest has no tag.
	Tag string
	// Digest is "algorithm:hex", empty when absent.
	Digest string
}

// Name returns "registry/repository", the fully-qualified repository name.
func (r Ref) Name() string { return r.Registry + "/" + r.Repository }

// Pinned reports whether the reference carries a content digest.
func (r Ref) Pinned() bool { return r.Digest != "" }

// String renders the canonical, fully-qualified form of the reference.
func (r Ref) String() string {
	var b strings.Builder
	b.WriteString(r.Name())
	if r.Tag != "" {
		b.WriteByte(':')
		b.WriteString(r.Tag)
	}
	if r.Digest != "" {
		b.WriteByte('@')
		b.WriteString(r.Digest)
	}
	return b.String()
}

// Parse parses s into a normalised Ref. A missing registry becomes docker.io
// and single-component Docker Hub names gain the "library/" prefix. Parse
// never defaults a tag: an image with neither tag nor digest has both empty,
// which lets policies distinguish "implicitly :latest" from an explicit tag.
func Parse(s string) (Ref, error) {
	if s == "" {
		return Ref{}, fmt.Errorf("%w: empty", ErrInvalidReference)
	}
	if strings.TrimSpace(s) != s {
		return Ref{}, fmt.Errorf("%w: %q contains surrounding whitespace", ErrInvalidReference, s)
	}

	var ref Ref
	rest := s
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		ref.Digest = rest[i+1:]
		rest = rest[:i]
		if err := validateDigest(ref.Digest); err != nil {
			return Ref{}, fmt.Errorf("%w: %q: %w", ErrInvalidReference, s, err)
		}
	}

	// A tag separator is a ':' after the last '/', so "host:5000/app" is not tagged.
	lastSlash := strings.LastIndexByte(rest, '/')
	if i := strings.LastIndexByte(rest, ':'); i > lastSlash {
		ref.Tag = rest[i+1:]
		rest = rest[:i]
		if !tagRe.MatchString(ref.Tag) {
			return Ref{}, fmt.Errorf("%w: %q: bad tag %q", ErrInvalidReference, s, ref.Tag)
		}
	}

	if rest == "" {
		return Ref{}, fmt.Errorf("%w: %q: missing repository name", ErrInvalidReference, s)
	}

	registry, path := splitDomain(rest)
	if !domainRe.MatchString(registry) {
		return Ref{}, fmt.Errorf("%w: %q: bad registry host %q", ErrInvalidReference, s, registry)
	}
	for _, c := range strings.Split(path, "/") {
		if !pathComponentRe.MatchString(c) {
			return Ref{}, fmt.Errorf("%w: %q: bad path component %q", ErrInvalidReference, s, c)
		}
	}
	registry = strings.ToLower(registry)
	if registry != "localhost" && !strings.ContainsAny(registry, ".:") {
		// Only reachable for an upper-case first component such as "FOO/app",
		// which Docker treats as a host; refuse rather than guess.
		return Ref{}, fmt.Errorf("%w: %q: ambiguous registry host %q", ErrInvalidReference, s, registry)
	}
	if registry == DefaultRegistry && !strings.Contains(path, "/") {
		path = "library/" + path
	}
	ref.Registry = registry
	ref.Repository = path
	if n := len(ref.Name()); n > maxNameLength {
		// Checked on the normalised name so that the canonical form always re-parses.
		return Ref{}, fmt.Errorf("%w: %q: name longer than %d characters", ErrInvalidReference, s, maxNameLength)
	}
	return ref, nil
}

// splitDomain separates the registry host from the repository path using the
// same heuristic as the Docker CLI: the first component is a host only when it
// contains '.' or ':' or is exactly "localhost".
func splitDomain(name string) (registry, path string) {
	i := strings.IndexByte(name, '/')
	if i < 0 {
		return DefaultRegistry, name
	}
	first := name[:i]
	if first != "localhost" && !strings.ContainsAny(first, ".:") && strings.ToLower(first) == first {
		return DefaultRegistry, name
	}
	if first == "index.docker.io" {
		return DefaultRegistry, name[i+1:]
	}
	return first, name[i+1:]
}

func validateDigest(d string) error {
	if !digestRe.MatchString(d) {
		return fmt.Errorf("bad digest %q", d)
	}
	algo, hex, _ := strings.Cut(d, ":")
	if algo == "sha256" && !sha256HexRe.MatchString(hex) {
		return fmt.Errorf("sha256 digest must be 64 lowercase hex characters")
	}
	return nil
}

// MatchGlob reports whether name matches pattern, where pattern components are
// separated by '/', "*" matches exactly one component (any characters except
// '/') and a trailing "**" matches any number of remaining components,
// including zero. Matching is anchored: "registry.lab.local/**" does not match
// "registry.lab.local.evil.io/app".
func MatchGlob(pattern, name string) bool {
	pp := strings.Split(pattern, "/")
	np := strings.Split(name, "/")
	for i, p := range pp {
		if p == "**" && i == len(pp)-1 {
			return len(np) >= i
		}
		if i >= len(np) {
			return false
		}
		if !matchComponent(p, np[i]) {
			return false
		}
	}
	return len(pp) == len(np)
}

// matchComponent matches a single path component where '*' matches any run of
// characters. It is an iterative wildcard matcher, O(len(p)*len(s)) worst case.
func matchComponent(p, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == s[si]:
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

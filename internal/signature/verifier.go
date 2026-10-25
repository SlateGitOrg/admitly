package signature

import (
	"container/list"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SlateGitOrg/admitly/internal/imageref"
)

// Result describes a successful verification.
type Result struct {
	// KeyID identifies the key that verified the signature.
	KeyID string
	// Cached is true when the result came from the verification cache.
	Cached bool
}

// Verifier checks images against a Store, caching positive results.
// Negative results are never cached, so adding a signature takes effect on
// the next request. A Verifier is safe for concurrent use.
type Verifier struct {
	store Store
	cache *lru
}

// NewVerifier returns a Verifier. cacheSize <= 0 disables caching.
func NewVerifier(store Store, cacheSize int, ttl time.Duration) *Verifier {
	v := &Verifier{store: store}
	if cacheSize > 0 && ttl > 0 {
		v.cache = newLRU(cacheSize, ttl, time.Now)
	}
	return v
}

// KeySetID returns a stable identifier for a set of keys, used in cache keys.
func KeySetID(keys []*PublicKey) string {
	ids := make([]string, len(keys))
	for i, k := range keys {
		ids[i] = k.ID
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

// Verify succeeds when at least one stored signature for ref has a payload
// bound to ref and verifies under one of keys. The returned error wraps
// ErrNotPinned, ErrNoSignatures or ErrNoValidSignature for trust failures;
// any other error is an infrastructure failure (store unreadable, context
// cancelled) that the caller should treat according to its failure policy.
func (v *Verifier) Verify(ctx context.Context, ref imageref.Ref, keys []*PublicKey) (Result, error) {
	if !ref.Pinned() {
		return Result{}, fmt.Errorf("%s: %w", ref, ErrNotPinned)
	}
	if len(keys) == 0 {
		return Result{}, fmt.Errorf("%s: %w: no keys configured", ref, ErrNoValidSignature)
	}
	cacheKey := ref.Name() + "@" + ref.Digest + "|" + KeySetID(keys)
	if v.cache != nil {
		if keyID, ok := v.cache.get(cacheKey); ok {
			return Result{KeyID: keyID, Cached: true}, nil
		}
	}
	sigs, err := v.store.Signatures(ctx, ref)
	if err != nil {
		return Result{}, fmt.Errorf("fetching signatures for %s: %w", ref, err)
	}
	if len(sigs) == 0 {
		return Result{}, fmt.Errorf("%s: %w", ref, ErrNoSignatures)
	}
	var reasons []string
	for i, s := range sigs {
		raw, err := base64.StdEncoding.DecodeString(s.Base64Signature)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("signature %d: bad base64", i))
			continue
		}
		if err := CheckPayload(s.Payload, ref); err != nil {
			reasons = append(reasons, fmt.Sprintf("signature %d: %v", i, err))
			continue
		}
		for _, k := range keys {
			if k.VerifySignature(s.Payload, raw) == nil {
				if v.cache != nil {
					v.cache.put(cacheKey, k.ID)
				}
				return Result{KeyID: k.ID}, nil
			}
		}
		reasons = append(reasons, fmt.Sprintf("signature %d: not signed by a trusted key", i))
	}
	return Result{}, fmt.Errorf("%s: %w (%s)", ref, ErrNoValidSignature, strings.Join(reasons, "; "))
}

// IsTrustFailure reports whether err means "the image is not trusted" as
// opposed to "verification could not be performed".
func IsTrustFailure(err error) bool {
	return errors.Is(err, ErrNotPinned) || errors.Is(err, ErrNoSignatures) || errors.Is(err, ErrNoValidSignature)
}

// lru is a size-bounded, TTL-expiring cache of verified images.
type lru struct {
	mu    sync.Mutex
	size  int
	ttl   time.Duration
	now   func() time.Time
	order *list.List // front = most recently used
	items map[string]*list.Element
}

type lruEntry struct {
	key     string
	keyID   string
	expires time.Time
}

func newLRU(size int, ttl time.Duration, now func() time.Time) *lru {
	return &lru{size: size, ttl: ttl, now: now, order: list.New(), items: make(map[string]*list.Element, size)}
}

func (c *lru) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return "", false
	}
	e := el.Value.(*lruEntry)
	if c.now().After(e.expires) {
		c.order.Remove(el)
		delete(c.items, key)
		return "", false
	}
	c.order.MoveToFront(el)
	return e.keyID, true
}

func (c *lru) put(key, keyID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*lruEntry)
		e.keyID, e.expires = keyID, c.now().Add(c.ttl)
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(&lruEntry{key: key, keyID: keyID, expires: c.now().Add(c.ttl)})
	for c.order.Len() > c.size {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.items, last.Value.(*lruEntry).key)
	}
}

func (c *lru) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

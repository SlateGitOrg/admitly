// Package config loads the admitly server configuration and assembles the
// policy set it describes (built-ins, overrides and policy directories).
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	kjson "sigs.k8s.io/json"
	"sigs.k8s.io/yaml"

	"github.com/SlateGitOrg/admitly/internal/admission"
	"github.com/SlateGitOrg/admitly/internal/policy"
	"github.com/SlateGitOrg/admitly/policies"
)

// Duration is a time.Duration that decodes from strings like "3s".
type Duration struct{ time.Duration }

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := kjson.UnmarshalCaseSensitivePreserveInts(b, &s); err != nil {
		return fmt.Errorf("duration must be a string such as \"5s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return []byte(`"` + d.String() + `"`), nil }

// Config is the server configuration file.
type Config struct {
	Listen          string                `json:"listen"`
	TLS             TLS                   `json:"tls"`
	FailureMode     admission.FailureMode `json:"failureMode"`
	Timeout         Duration              `json:"timeout"`
	MaxRequestBytes int64                 `json:"maxRequestBytes"`
	Policies        Policies              `json:"policies"`
	Signatures      Signatures            `json:"signatures"`
	CEL             CEL                   `json:"cel"`
	Audit           Audit                 `json:"audit"`
	LogLevel        string                `json:"logLevel"`

	// dir is the directory relative paths are resolved against.
	dir string
}

// TLS configures the HTTPS listener.
type TLS struct {
	CertFile       string   `json:"certFile"`
	KeyFile        string   `json:"keyFile"`
	ClientCAFile   string   `json:"clientCAFile,omitempty"`
	ReloadInterval Duration `json:"reloadInterval"`
}

// Policies selects where policies come from.
type Policies struct {
	Builtin        bool                `json:"builtin"`
	Dirs           []string            `json:"dirs,omitempty"`
	Overrides      map[string]Override `json:"overrides,omitempty"`
	ReloadInterval Duration            `json:"reloadInterval"`
}

// Override adjusts a policy by name after loading.
type Override struct {
	Mode          policy.Mode          `json:"mode,omitempty"`
	FailurePolicy policy.FailurePolicy `json:"failurePolicy,omitempty"`
	// Params are merged over the policy's params (top-level keys replaced).
	Params            map[string]any `json:"params,omitempty"`
	ExcludeNamespaces []string       `json:"excludeNamespaces,omitempty"`
}

// Signatures configures image signature verification.
type Signatures struct {
	StoreDir  string   `json:"storeDir,omitempty"`
	CacheSize int      `json:"cacheSize"`
	CacheTTL  Duration `json:"cacheTTL"`
}

// CEL configures the expression runtime.
type CEL struct {
	CostLimit uint64 `json:"costLimit"`
}

// Audit configures the decision log. File "-" is stdout; empty disables it.
type Audit struct {
	File string `json:"file"`
}

// Default returns the configuration used when a field is not set.
func Default() *Config {
	return &Config{
		Listen:          ":8443",
		TLS:             TLS{ReloadInterval: Duration{30 * time.Second}},
		FailureMode:     admission.FailClosed,
		Timeout:         Duration{admission.DefaultTimeout},
		MaxRequestBytes: 3 << 20,
		Policies:        Policies{Builtin: true, ReloadInterval: Duration{10 * time.Second}},
		Signatures:      Signatures{CacheSize: 1024, CacheTTL: Duration{5 * time.Minute}},
		LogLevel:        "info",
		dir:             ".",
	}
}

// Load reads a YAML or JSON configuration file. Unknown fields are errors.
// Relative paths in the file are resolved against the file's directory.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.dir = filepath.Dir(path)
	return cfg, nil
}

// Parse decodes configuration data over the defaults and validates it.
func Parse(data []byte) (*Config, error) {
	js, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, err
	}
	cfg := Default()
	strictErrs, err := kjson.UnmarshalStrict(js, cfg)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(strictErrs...); err != nil {
		return nil, err
	}
	return cfg, cfg.Validate()
}

// Validate checks field values.
func (c *Config) Validate() error {
	var errs []error
	switch c.FailureMode {
	case admission.FailClosed, admission.FailOpen:
	default:
		errs = append(errs, fmt.Errorf("failureMode must be Closed or Open, got %q", c.FailureMode))
	}
	if c.Timeout.Duration <= 0 || c.Timeout.Duration > 30*time.Second {
		errs = append(errs, fmt.Errorf("timeout must be in (0s, 30s], got %s", c.Timeout.Duration))
	}
	if c.MaxRequestBytes < 1024 {
		errs = append(errs, fmt.Errorf("maxRequestBytes must be at least 1024"))
	}
	for name, o := range c.Policies.Overrides {
		switch o.Mode {
		case "", policy.ModeEnforce, policy.ModeAudit, policy.ModeDisabled:
		default:
			errs = append(errs, fmt.Errorf("policies.overrides.%s.mode: invalid %q", name, o.Mode))
		}
		switch o.FailurePolicy {
		case "", policy.FailurePolicyFail, policy.FailurePolicyIgnore:
		default:
			errs = append(errs, fmt.Errorf("policies.overrides.%s.failurePolicy: invalid %q", name, o.FailurePolicy))
		}
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("logLevel must be debug, info, warn or error, got %q", c.LogLevel))
	}
	return errors.Join(errs...)
}

// Resolve returns p relative to the config file's directory (absolute paths
// and "-" are returned unchanged).
func (c *Config) Resolve(p string) string {
	if p == "" || p == "-" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

// LoadPolicies assembles the configured policy set and returns it with a
// fingerprint of every source file, used to detect changes for hot reload.
func (c *Config) LoadPolicies() ([]*policy.Policy, string, error) {
	h := sha256.New()
	var all []*policy.Policy
	if c.Policies.Builtin {
		ps, err := policy.LoadFS(policies.Builtin(), "builtin")
		if err != nil {
			return nil, "", fmt.Errorf("loading built-in policies: %w", err)
		}
		all = append(all, ps...)
		h.Write([]byte("builtin\x00"))
	}
	for _, d := range c.Policies.Dirs {
		dir := c.Resolve(d)
		if err := fingerprintDir(h, dir); err != nil {
			return nil, "", err
		}
		ps, err := policy.LoadDir(dir)
		if err != nil {
			return nil, "", err
		}
		all = append(all, ps...)
	}
	if err := policy.CheckUnique(all); err != nil {
		return nil, "", err
	}
	if err := applyOverrides(all, c.Policies.Overrides); err != nil {
		return nil, "", err
	}
	return all, hex.EncodeToString(h.Sum(nil)), nil
}

// Fingerprint hashes the policy sources without parsing them. It is cheap
// enough to call on every reload tick.
func (c *Config) Fingerprint() (string, error) {
	h := sha256.New()
	if c.Policies.Builtin {
		h.Write([]byte("builtin\x00"))
	}
	for _, d := range c.Policies.Dirs {
		if err := fingerprintDir(h, c.Resolve(d)); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fingerprintDir(h interface{ Write([]byte) (int, error) }, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading policy directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		_, _ = h.Write([]byte(e.Name() + "\x00"))
		_, _ = h.Write(data)
		_, _ = h.Write([]byte{0})
	}
	return nil
}

func applyOverrides(ps []*policy.Policy, overrides map[string]Override) error {
	byName := make(map[string]*policy.Policy, len(ps))
	for _, p := range ps {
		byName[p.Metadata.Name] = p
	}
	names := slices.Collect(maps.Keys(overrides))
	sort.Strings(names)
	for _, name := range names {
		o := overrides[name]
		p, ok := byName[name]
		if !ok {
			return fmt.Errorf("policies.overrides: no policy named %q", name)
		}
		if o.Mode != "" {
			p.Spec.Mode = o.Mode
		}
		if o.FailurePolicy != "" {
			p.Spec.FailurePolicy = o.FailurePolicy
		}
		if len(o.Params) > 0 {
			merged := maps.Clone(p.Spec.Params)
			if merged == nil {
				merged = map[string]any{}
			}
			maps.Copy(merged, o.Params)
			p.Spec.Params = merged
		}
		p.Spec.Match.ExcludeNamespaces = append(p.Spec.Match.ExcludeNamespaces, o.ExcludeNamespaces...)
		if err := p.Validate(); err != nil {
			return fmt.Errorf("policies.overrides.%s: %w", name, err)
		}
	}
	return nil
}

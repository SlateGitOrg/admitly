package imageref

import (
	"errors"
	"strings"
	"testing"
)

const dg = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Ref
	}{
		{"nginx", Ref{Registry: "docker.io", Repository: "library/nginx"}},
		{"nginx:1.27", Ref{Registry: "docker.io", Repository: "library/nginx", Tag: "1.27"}},
		{"bitnami/redis:7", Ref{Registry: "docker.io", Repository: "bitnami/redis", Tag: "7"}},
		{"index.docker.io/library/nginx", Ref{Registry: "docker.io", Repository: "library/nginx"}},
		{"docker.io/nginx", Ref{Registry: "docker.io", Repository: "library/nginx"}},
		{"registry.lab.local/team/app@" + dg, Ref{Registry: "registry.lab.local", Repository: "team/app", Digest: dg}},
		{"registry.lab.local:5000/app:v1@" + dg, Ref{Registry: "registry.lab.local:5000", Repository: "app", Tag: "v1", Digest: dg}},
		{"localhost/app", Ref{Registry: "localhost", Repository: "app"}},
		{"localhost:5000/a/b/c", Ref{Registry: "localhost:5000", Repository: "a/b/c"}},
		{"Registry.Lab.Local/app", Ref{Registry: "registry.lab.local", Repository: "app"}},
		{"[::1]:5000/app", Ref{Registry: "[::1]:5000", Repository: "app"}},
		{"gcr.io/proj/my_app-x.y:tag_1.0-rc", Ref{Registry: "gcr.io", Repository: "proj/my_app-x.y", Tag: "tag_1.0-rc"}},
	}
	for _, tc := range cases {
		got, err := Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	bad := []string{
		"",
		" nginx",
		"nginx ",
		"UPPER",
		"UPPER/app",
		"app:",
		"app@sha256:short",
		"app@sha256:" + strings.Repeat("A", 64),
		"app@md5",
		"registry..lab/app",
		"-bad.host/app",
		"host.io/app//x",
		"host.io/",
		":tag",
		"app:" + strings.Repeat("t", 129),
		strings.Repeat("a", 256),
		"app:bad tag",
		"@" + dg,
	}
	for _, in := range bad {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", in)
		} else if !errors.Is(err, ErrInvalidReference) {
			t.Errorf("Parse(%q) error %v does not wrap ErrInvalidReference", in, err)
		}
	}
}

func TestRefHelpers(t *testing.T) {
	r, err := Parse("registry.lab.local/team/app:v1@" + dg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Name() != "registry.lab.local/team/app" {
		t.Errorf("Name = %q", r.Name())
	}
	if !r.Pinned() {
		t.Error("Pinned = false")
	}
	if got := r.String(); got != "registry.lab.local/team/app:v1@"+dg {
		t.Errorf("String = %q", got)
	}
	r2, _ := Parse("nginx")
	if r2.Pinned() || r2.String() != "docker.io/library/nginx" {
		t.Errorf("unexpected %+v %q", r2, r2.String())
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"registry.lab.local/**", "registry.lab.local/team/app", true},
		{"registry.lab.local/**", "registry.lab.local/app", true},
		{"registry.lab.local/**", "registry.lab.local.evil.io/app", false},
		{"registry.lab.local/*", "registry.lab.local/team/app", false},
		{"registry.lab.local/*", "registry.lab.local/app", true},
		{"registry.lab.local/team-*/app", "registry.lab.local/team-a/app", true},
		{"registry.lab.local/team-*/app", "registry.lab.local/teamb/app", false},
		{"*.lab.local/**", "registry.lab.local/app", true},
		{"docker.io/library/nginx", "docker.io/library/nginx", true},
		{"docker.io/library/nginx", "docker.io/library/nginx2", false},
		{"a/b", "a", false},
		{"a/**", "a", true},
		{"a/*b*c", "a/xbyyc", true},
		{"a/*b*c", "a/xbyyd", false},
		{"**", "anything/at/all", true},
	}
	for _, tc := range cases {
		if got := MatchGlob(tc.pattern, tc.name); got != tc.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

// FuzzParse checks that Parse never panics and that every accepted reference
// round-trips: re-parsing the canonical String() yields the same Ref.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"nginx", "a/b:c", "registry.lab.local:5000/x/y:z@" + dg, "[::1]/a", "localhost/x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Parse(s)
		if err != nil {
			return
		}
		r2, err := Parse(r.String())
		if err != nil {
			t.Fatalf("canonical form %q of %q does not parse: %v", r.String(), s, err)
		}
		if r2 != r {
			t.Fatalf("round trip mismatch: %+v vs %+v", r, r2)
		}
	})
}

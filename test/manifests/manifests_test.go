package manifests

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/archit2501/admitly/internal/config"
	"github.com/archit2501/admitly/internal/policy"
)

// TestDeployManifestsDecodeStrictly decodes every document in deploy/ and
// examples/manifests/ into its typed Kubernetes object with strict decoding,
// so unknown or misspelt fields fail the build.
func TestDeployManifestsDecodeStrictly(t *testing.T) {
	codecs := serializer.NewCodecFactory(scheme.Scheme, serializer.EnableStrict)
	decoder := codecs.UniversalDeserializer()
	files, _ := filepath.Glob(filepath.Join("..", "..", "deploy", "*.yaml"))
	more, _ := filepath.Glob(filepath.Join("..", "..", "examples", "manifests", "*.yaml"))
	files = append(files, more...)
	if len(files) < 3 {
		t.Fatalf("expected manifest files, got %v", files)
	}
	kinds := map[string]int{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for i := 0; ; i++ {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				t.Fatalf("%s doc %d: %v", f, i, err)
			}
			if len(bytes.TrimSpace(raw)) == 0 || string(raw) == "null" {
				continue
			}
			_, gvk, err := decoder.Decode(raw, nil, nil)
			if err != nil {
				t.Fatalf("%s doc %d: %v", f, i, err)
			}
			kinds[gvk.Kind]++
		}
	}
	for _, k := range []string{"Deployment", "Service", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", "Pod"} {
		if kinds[k] == 0 {
			t.Errorf("no %s found in manifests (%v)", k, kinds)
		}
	}
}

// TestExampleConfigAndPolicies loads the example configuration and every
// example policy (with a throwaway key for the verification policy).
func TestExampleConfigAndPolicies(t *testing.T) {
	if _, err := config.Load(filepath.Join("..", "..", "examples", "admitly.yaml")); err != nil {
		t.Fatalf("examples/admitly.yaml: %v", err)
	}
	ps, err := policy.LoadFile(filepath.Join("..", "..", "examples", "policies", "disallow-latest-tag.yaml"))
	if err != nil || len(ps) != 1 {
		t.Fatalf("disallow-latest-tag: %v", err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "policies", "verify-images.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cosign.pub"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Parse(data, "verify-images.yaml", dir); err != nil {
		t.Fatalf("verify-images: %v", err)
	}
}

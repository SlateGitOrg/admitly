//go:build envtest

// Package e2e runs admitly against a real kube-apiserver and etcd started
// by controller-runtime's envtest. The webhook is registered with generated
// TLS material exactly as it would be in a cluster, so these tests exercise
// the API server's own webhook client: TLS verification against caBundle,
// AdmissionReview v1 encoding, JSON Patch application, warnings, and the API
// server's failurePolicy when the webhook is unreachable.
//
// Run with `make envtest` (needs KUBEBUILDER_ASSETS; the target resolves it
// with setup-envtest).
package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/SlateGitOrg/admitly/internal/config"
	"github.com/SlateGitOrg/admitly/internal/imageref"
	"github.com/SlateGitOrg/admitly/internal/server"
	"github.com/SlateGitOrg/admitly/internal/signature"
	"github.com/SlateGitOrg/admitly/internal/tlsutil"
)

const (
	namespace   = "shop"
	digestA     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB     = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	signedImage = "registry.lab.local/team/web@" + digestA
)

// warnings collects API server Warning headers (audit-mode findings).
type warnings struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warnings) HandleWarningHeader(_ int, _ string, text string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, text)
}

func (w *warnings) take() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.msgs
	w.msgs = nil
	return out
}

type harness struct {
	t       *testing.T
	client  *kubernetes.Clientset
	warn    *warnings
	bundle  *tlsutil.Bundle
	url     string
	stopSrv func()
}

func TestAdmissionAgainstRealAPIServer(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set; run `make envtest`")
	}
	env := &envtest.Environment{}
	restCfg, err := env.Start()
	if err != nil {
		t.Fatalf("starting envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Logf("stopping envtest: %v", err)
		}
	})

	h := &harness{t: t, warn: &warnings{}}
	h.startWebhook()
	cfg := rest.CopyConfig(restCfg)
	cfg.WarningHandler = h.warn
	h.client = kubernetes.NewForConfigOrDie(cfg)
	ctx := context.Background()

	_, err = h.client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: map[string]string{"admitly.dev/enforce": "true"}},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h.registerWebhooks(h.bundle.CACert, admissionregistrationv1.Fail)
	h.waitUntilEnforced()

	t.Run("compliant pod is admitted and mutated", func(t *testing.T) {
		created, err := h.client.CoreV1().Pods(namespace).Create(ctx, pod("web", signedImage, nil), metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("compliant pod rejected: %v", err)
		}
		psc := created.Spec.SecurityContext
		if psc == nil || psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot || psc.SeccompProfile == nil || psc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			t.Fatalf("pod securityContext not defaulted by the mutating webhook: %+v", psc)
		}
		csc := created.Spec.Containers[0].SecurityContext
		if csc == nil || csc.AllowPrivilegeEscalation == nil || *csc.AllowPrivilegeEscalation || csc.Capabilities == nil || len(csc.Capabilities.Drop) != 1 || csc.Capabilities.Drop[0] != "ALL" {
			t.Fatalf("container securityContext not defaulted: %+v", csc)
		}
	})

	t.Run("privileged pod is denied with a 403", func(t *testing.T) {
		p := pod("priv", signedImage, nil)
		p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: ptr(true)}
		_, err := h.client.CoreV1().Pods(namespace).Create(ctx, p, metav1.CreateOptions{})
		mustDeny(t, err, "[disallow-privileged] privileged containers are not allowed: app")
		if !apierrors.IsForbidden(err) {
			t.Fatalf("want 403 Forbidden, got %v", err)
		}
		t.Logf("API server error: %v", err)
	})

	t.Run("unsigned image is denied", func(t *testing.T) {
		_, err := h.client.CoreV1().Pods(namespace).Create(ctx, pod("unsigned", "registry.lab.local/team/other@"+digestB, nil), metav1.CreateOptions{})
		mustDeny(t, err, "[verify-images] image signature verification failed")
	})

	t.Run("several violations are reported together", func(t *testing.T) {
		p := pod("shady", "docker.io/library/nginx:1.27", map[string]string{"app.kubernetes.io/name": "shady"})
		p.Spec.Containers[0].Resources = corev1.ResourceRequirements{}
		_, err := h.client.CoreV1().Pods(namespace).Create(ctx, p, metav1.CreateOptions{})
		for _, want := range []string{"[registry-allowlist]", "[require-image-digest]", "[require-labels]", "[require-resource-limits]"} {
			mustDeny(t, err, want)
		}
	})

	t.Run("audit-mode finding is admitted with a warning", func(t *testing.T) {
		h.warn.take()
		_, err := h.client.CoreV1().Pods(namespace).Create(ctx, pod("latest", "registry.lab.local/team/web:latest@"+digestA, nil), metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("audit-mode violation must not block: %v", err)
		}
		got := strings.Join(h.warn.take(), "\n")
		if !strings.Contains(got, "[audit] disallow-latest-tag: containers use the latest tag: app") {
			t.Fatalf("warning not surfaced by the API server, got %q", got)
		}
	})

	t.Run("deployment template is validated", func(t *testing.T) {
		d := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: namespace, Labels: labels("edge")},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "edge"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "edge"}},
					Spec:       corev1.PodSpec{HostNetwork: true, Containers: pod("x", signedImage, nil).Spec.Containers},
				},
			},
		}
		_, err := h.client.AppsV1().Deployments(namespace).Create(ctx, d, metav1.CreateOptions{})
		mustDeny(t, err, "sharing host namespaces is not allowed: hostNetwork")
	})

	t.Run("privileged ephemeral debug container is denied", func(t *testing.T) {
		p, err := h.client.CoreV1().Pods(namespace).Get(ctx, "web", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name: "debugger", Image: "docker.io/library/busybox:1.36",
				SecurityContext: &corev1.SecurityContext{Privileged: ptr(true)},
			},
			TargetContainerName: "app",
		})
		_, err = h.client.CoreV1().Pods(namespace).UpdateEphemeralContainers(ctx, "web", p, metav1.UpdateOptions{})
		mustDeny(t, err, "privileged containers are not allowed: debugger")
	})

	t.Run("API server rejects a webhook whose certificate does not chain to caBundle", func(t *testing.T) {
		other, err := tlsutil.GenerateCA("unrelated-ca", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		h.registerWebhooks(other.CACert, admissionregistrationv1.Fail)
		err = eventually(30*time.Second, func() error {
			_, err := h.client.CoreV1().Pods(namespace).Create(ctx, pod("tls-probe", signedImage, nil), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
			if err == nil {
				return errors.New("request still admitted")
			}
			if !strings.Contains(err.Error(), "x509") && !strings.Contains(err.Error(), "certificate") {
				return fmt.Errorf("unexpected error: %w", err)
			}
			t.Logf("API server error: %v", err)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		h.registerWebhooks(h.bundle.CACert, admissionregistrationv1.Fail)
		h.waitUntilEnforced()
	})

	t.Run("failurePolicy Fail: webhook down means requests fail closed", func(t *testing.T) {
		h.stopSrv()
		err := eventually(30*time.Second, func() error {
			_, err := h.client.CoreV1().Pods(namespace).Create(ctx, pod("closed", signedImage, nil), metav1.CreateOptions{})
			if err == nil {
				return errors.New("pod admitted while webhook is down")
			}
			if !strings.Contains(err.Error(), "failed calling webhook") {
				return fmt.Errorf("unexpected error: %w", err)
			}
			t.Logf("API server error: %v", err)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("failurePolicy Ignore: webhook down means requests fail open", func(t *testing.T) {
		h.registerWebhooks(h.bundle.CACert, admissionregistrationv1.Ignore)
		p := pod("open", signedImage, nil)
		p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: ptr(true)}
		err := eventually(30*time.Second, func() error {
			_, err := h.client.CoreV1().Pods(namespace).Create(ctx, p, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
			return err
		})
		if err != nil {
			t.Fatalf("with failurePolicy Ignore and the webhook down, even a privileged pod is admitted: %v", err)
		}
	})
}

func (h *harness) startWebhook() {
	t := h.t
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	polDir := filepath.Join(dir, "policies")
	must(t, os.MkdirAll(polDir, 0o755))
	must(t, os.WriteFile(filepath.Join(polDir, "cosign.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600))
	must(t, os.WriteFile(filepath.Join(polDir, "verify.yaml"), []byte(`apiVersion: admitly.dev/v1alpha1
kind: ImageVerificationPolicy
metadata: {name: verify-images}
spec:
  match: {resources: [{apiGroups: [""], kinds: [Pod]}]}
  verification:
    rules: [{images: ["registry.lab.local/**"], keyFiles: [cosign.pub]}]
`), 0o600))
	ref, _ := imageref.Parse(signedImage)
	sig, err := signature.Sign(priv, ref, nil)
	must(t, err)
	must(t, signature.DirStore{Root: filepath.Join(dir, "store")}.Put(ref, sig))

	h.bundle, err = tlsutil.GenerateServing([]string{"127.0.0.1"}, time.Hour)
	must(t, err)
	must(t, h.bundle.WriteServing(filepath.Join(dir, "certs")))

	golden, err := filepath.Abs(filepath.Join("..", "..", "testdata", "golden", "policies"))
	must(t, err)
	cfgPath := filepath.Join(dir, "admitly.yaml")
	must(t, os.WriteFile(cfgPath, []byte(`
tls: {certFile: certs/tls.crt, keyFile: certs/tls.key}
failureMode: Closed
policies: {builtin: true, dirs: [policies, `+golden+`], reloadInterval: 0s}
signatures: {storeDir: store}
audit: {file: audit.log}
`), 0o600))
	cfg, err := config.Load(cfgPath)
	must(t, err)
	srv, err := server.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	must(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	h.url = "https://" + ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx, ln) }()
	var once sync.Once
	h.stopSrv = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("webhook server: %v", err)
			}
			_ = srv.Close()
		})
	}
	t.Cleanup(h.stopSrv)
}

// registerWebhooks creates or replaces both webhook configurations.
func (h *harness) registerWebhooks(caBundle []byte, fp admissionregistrationv1.FailurePolicyType) {
	t := h.t
	ctx := context.Background()
	sideEffects := admissionregistrationv1.SideEffectClassNone
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"admitly.dev/enforce": "true"}}
	podRules := func(subresources ...string) []admissionregistrationv1.RuleWithOperations {
		resources := []string{"pods"}
		for _, s := range subresources {
			resources = append(resources, "pods/"+s)
		}
		return []admissionregistrationv1.RuleWithOperations{
			{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
				Rule:       admissionregistrationv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: resources},
			},
			{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
				Rule:       admissionregistrationv1.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments"}},
			},
		}
	}
	clientConfig := func(path string) admissionregistrationv1.WebhookClientConfig {
		url := h.url + path
		return admissionregistrationv1.WebhookClientConfig{URL: &url, CABundle: caBundle}
	}
	mwc := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "admitly"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name: "mutate.admitly.dev", ClientConfig: clientConfig("/mutate"), Rules: podRules(),
			FailurePolicy: &fp, SideEffects: &sideEffects, AdmissionReviewVersions: []string{"v1"},
			TimeoutSeconds: ptr(int32(5)), NamespaceSelector: selector,
		}},
	}
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "admitly"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name: "validate.admitly.dev", ClientConfig: clientConfig("/validate"), Rules: podRules("ephemeralcontainers"),
			FailurePolicy: &fp, SideEffects: &sideEffects, AdmissionReviewVersions: []string{"v1"},
			TimeoutSeconds: ptr(int32(5)), NamespaceSelector: selector,
		}},
	}
	mc := h.client.AdmissionregistrationV1().MutatingWebhookConfigurations()
	vc := h.client.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	_ = mc.Delete(ctx, "admitly", metav1.DeleteOptions{})
	_ = vc.Delete(ctx, "admitly", metav1.DeleteOptions{})
	if _, err := mc.Create(ctx, mwc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := vc.Create(ctx, vwc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// waitUntilEnforced polls with dry-run requests until the API server has
// picked up the webhook configuration and admitly answers.
func (h *harness) waitUntilEnforced() {
	p := pod("probe", signedImage, nil)
	p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: ptr(true)}
	err := eventually(30*time.Second, func() error {
		_, err := h.client.CoreV1().Pods(namespace).Create(context.Background(), p, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		if err != nil && strings.Contains(err.Error(), "admitly denied the request") {
			return nil
		}
		return fmt.Errorf("webhook not active yet: %w", err)
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

func eventually(timeout time.Duration, f func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := f()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func labels(name string) map[string]string {
	return map[string]string{"app.kubernetes.io/name": name, "team": "payments"}
}

func pod(name, image string, lbls map[string]string) *corev1.Pod {
	if lbls == nil {
		lbls = labels(name)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: lbls},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "app",
			Image: image,
			Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			}},
		}}},
	}
}

func mustDeny(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("request admitted, want denial containing %q", want)
	}
	if !strings.Contains(err.Error(), "admitly denied the request") || !strings.Contains(err.Error(), want) {
		t.Fatalf("denial %q does not contain %q", err, want)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func ptr[T any](v T) *T { return &v }

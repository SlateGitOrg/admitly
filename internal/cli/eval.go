package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/SlateGitOrg/admitly/internal/admission"
	"github.com/SlateGitOrg/admitly/internal/config"
	"github.com/SlateGitOrg/admitly/internal/engine"
	"github.com/SlateGitOrg/admitly/internal/mutate"
	"github.com/SlateGitOrg/admitly/internal/policy"
	"github.com/SlateGitOrg/admitly/internal/signature"
	"github.com/SlateGitOrg/admitly/policies"
)

// errDenied makes `admitly eval` exit 1 when any object is denied, so it
// can gate CI pipelines with the same policies the cluster enforces.
var errDenied = errors.New("one or more objects were denied")

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, splitList(v)...); return nil }

// policyFlags selects a policy set either from a config file or from flags.
type policyFlags struct {
	config    string
	builtin   bool
	dirs      stringList
	store     string
	costLimit uint64
}

func (p *policyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&p.config, "config", "", "load policies, overrides and signature store from this config file")
	fs.BoolVar(&p.builtin, "builtin", true, "include the built-in policies (ignored with --config)")
	fs.Var(&p.dirs, "policies", "policy directory (repeatable or comma-separated; ignored with --config)")
	fs.StringVar(&p.store, "store", "", "signature store directory (ignored with --config)")
}

// load returns the policies and an engine with the matching verifier.
func (p *policyFlags) load() ([]*policy.Policy, *engine.Engine, error) {
	var (
		ps       []*policy.Policy
		store    string
		cost     uint64
		cacheTTL = 5 * time.Minute
	)
	if p.config != "" {
		cfg, err := config.Load(p.config)
		if err != nil {
			return nil, nil, err
		}
		if ps, _, err = cfg.LoadPolicies(); err != nil {
			return nil, nil, err
		}
		store = cfg.Resolve(cfg.Signatures.StoreDir)
		cost = cfg.CEL.CostLimit
	} else {
		if p.builtin {
			b, err := policy.LoadFS(policies.Builtin(), "builtin")
			if err != nil {
				return nil, nil, err
			}
			ps = append(ps, b...)
		}
		for _, d := range p.dirs {
			more, err := policy.LoadDir(d)
			if err != nil {
				return nil, nil, err
			}
			ps = append(ps, more...)
		}
		store, cost = p.store, p.costLimit
	}
	var verifier *signature.Verifier
	if store != "" {
		verifier = signature.NewVerifier(signature.DirStore{Root: store}, 256, cacheTTL)
	}
	eng, err := engine.New(engine.Options{CostLimit: cost, Verifier: verifier, Logger: discardLogger()})
	if err != nil {
		return nil, nil, err
	}
	return ps, eng, nil
}

type evalReport struct {
	Source   string                         `json:"source"`
	Object   string                         `json:"object"`
	Mutate   *admissionv1.AdmissionResponse `json:"mutate"`
	Patch    []mutate.Op                    `json:"patch,omitempty"`
	Validate *admissionv1.AdmissionResponse `json:"validate"`
}

func runEval(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("eval", stderr)
	var pf policyFlags
	pf.register(fs)
	op := fs.String("operation", "CREATE", "operation for plain manifests: CREATE or UPDATE")
	namespace := fs.String("namespace", "default", "namespace for manifests that do not set one")
	user := fs.String("user", "admitly-eval", "username placed in the generated requests")
	output := fs.String("output", "text", "output format: text or json")
	noMutate := fs.Bool("no-mutate", false, "skip the mutating phase")
	failOnDeny := fs.Bool("fail-on-deny", true, "exit 1 if any object is denied")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: admitly eval [flags] FILE... (YAML/JSON manifests or AdmissionReview v1; '-' reads stdin)")
		fs.PrintDefaults()
	}
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("%w: at least one input file is required", errUsage)
	}
	if *output != "text" && *output != "json" {
		return fmt.Errorf("%w: --output must be text or json", errUsage)
	}
	operation := admissionv1.Operation(strings.ToUpper(*op))
	if operation != admissionv1.Create && operation != admissionv1.Update {
		return fmt.Errorf("%w: --operation must be CREATE or UPDATE", errUsage)
	}

	ps, eng, err := pf.load()
	if err != nil {
		return err
	}
	if _, err := eng.Load(ps); err != nil {
		return err
	}
	h, err := admission.New(admission.Options{Engine: eng, Logger: discardLogger(), Timeout: 10 * time.Second})
	if err != nil {
		return err
	}

	var reports []evalReport
	for _, file := range fs.Args() {
		reviews, err := readReviews(file, operation, *namespace, *user)
		if err != nil {
			return err
		}
		for _, rv := range reviews {
			rep, err := evalOne(ctx, h, rv, !*noMutate)
			if err != nil {
				return fmt.Errorf("%s: %w", file, err)
			}
			rep.Source = file
			reports = append(reports, rep)
		}
	}

	if *output == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return err
		}
	} else {
		printReports(stdout, reports)
	}
	if *failOnDeny {
		for _, r := range reports {
			if !r.Validate.Allowed || (r.Mutate != nil && !r.Mutate.Allowed) {
				return errDenied
			}
		}
	}
	return nil
}

// evalOne runs the API server's admission order: mutate, apply the patch,
// then validate the mutated object.
func evalOne(ctx context.Context, h *admission.Handler, rv *admissionv1.AdmissionReview, doMutate bool) (evalReport, error) {
	req := rv.Request
	rep := evalReport{Object: describe(req)}
	if doMutate && req.Object.Raw != nil {
		out, err := h.Review(ctx, admission.Mutate, rv)
		if err != nil {
			return rep, err
		}
		rep.Mutate = out.Response
		if p := out.Response.Patch; len(p) > 0 {
			if err := json.Unmarshal(p, &rep.Patch); err != nil {
				return rep, fmt.Errorf("decoding patch: %w", err)
			}
			patch, err := jsonpatch.DecodePatch(p)
			if err != nil {
				return rep, fmt.Errorf("decoding patch: %w", err)
			}
			patched, err := patch.Apply(req.Object.Raw)
			if err != nil {
				return rep, fmt.Errorf("applying patch: %w", err)
			}
			req.Object = runtime.RawExtension{Raw: patched}
		}
	}
	out, err := h.Review(ctx, admission.Validate, rv)
	if err != nil {
		return rep, err
	}
	rep.Validate = out.Response
	return rep, nil
}

func describe(req *admissionv1.AdmissionRequest) string {
	ns := req.Namespace
	if ns != "" {
		ns += "/"
	}
	return fmt.Sprintf("%s %s%s (%s)", req.Kind.Kind, ns, req.Name, req.Operation)
}

func readReviews(file string, op admissionv1.Operation, namespace, user string) ([]*admissionv1.AdmissionReview, error) {
	var data []byte
	var err error
	if file == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(file)
	}
	if err != nil {
		return nil, err
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []*admissionv1.AdmissionReview
	for i := 0; ; i++ {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("%s: document %d: %w", file, i, err)
		}
		if t := bytes.TrimSpace(raw); len(t) == 0 || bytes.Equal(t, []byte("null")) {
			continue
		}
		var meta struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Metadata   struct {
				Name         string `json:"name"`
				GenerateName string `json:"generateName"`
				Namespace    string `json:"namespace"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, fmt.Errorf("%s: document %d: %w", file, i, err)
		}
		if meta.Kind == "AdmissionReview" {
			var rv admissionv1.AdmissionReview
			if err := json.Unmarshal(raw, &rv); err != nil {
				return nil, fmt.Errorf("%s: document %d: %w", file, i, err)
			}
			if err := admission.CheckReview(&rv); err != nil {
				return nil, fmt.Errorf("%s: document %d: %w", file, i, err)
			}
			out = append(out, &rv)
			continue
		}
		if meta.Kind == "" || meta.APIVersion == "" {
			return nil, fmt.Errorf("%s: document %d: apiVersion and kind are required", file, i)
		}
		group, version, found := strings.Cut(meta.APIVersion, "/")
		if !found {
			group, version = "", meta.APIVersion
		}
		ns := meta.Metadata.Namespace
		if ns == "" && meta.Kind != "Namespace" {
			ns = namespace
		}
		name := meta.Metadata.Name
		if name == "" {
			name = meta.Metadata.GenerateName
		}
		req := &admissionv1.AdmissionRequest{
			UID:       types.UID(fmt.Sprintf("eval-%s-%d", strings.ToLower(meta.Kind), len(out)+1)),
			Kind:      metav1.GroupVersionKind{Group: group, Version: version, Kind: meta.Kind},
			Resource:  metav1.GroupVersionResource{Group: group, Version: version, Resource: strings.ToLower(meta.Kind) + "s"},
			Name:      name,
			Namespace: ns,
			Operation: op,
			UserInfo:  authenticationv1.UserInfo{Username: user, Groups: []string{"system:authenticated"}},
			Object:    runtime.RawExtension{Raw: raw},
		}
		if op == admissionv1.Update {
			req.OldObject = runtime.RawExtension{Raw: raw}
		}
		out = append(out, &admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
			Request:  req,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no objects found", file)
	}
	return out, nil
}

func printReports(w io.Writer, reports []evalReport) {
	allowed, denied := 0, 0
	for _, r := range reports {
		fmt.Fprintf(w, "%s  [%s]\n", r.Object, r.Source)
		if r.Mutate != nil {
			switch {
			case !r.Mutate.Allowed:
				fmt.Fprintf(w, "  mutate:   DENIED  %s\n", r.Mutate.Result.Message)
			case len(r.Patch) == 0:
				fmt.Fprintln(w, "  mutate:   no changes")
			default:
				fmt.Fprintf(w, "  mutate:   %d patch operation(s) by %s\n", len(r.Patch), r.Mutate.AuditAnnotations[admission.AnnotationMutatedBy])
				for _, op := range r.Patch {
					v, _ := json.Marshal(op.Value)
					fmt.Fprintf(w, "            %s %s %s\n", op.Op, op.Path, v)
				}
			}
		}
		v := r.Validate
		if v.Allowed {
			allowed++
			fmt.Fprintln(w, "  validate: ALLOWED")
		} else {
			denied++
			fmt.Fprintf(w, "  validate: DENIED (HTTP %d %s)\n", v.Result.Code, v.Result.Reason)
			msg := strings.TrimPrefix(v.Result.Message, "admitly denied the request: ")
			for _, part := range strings.Split(msg, "; [") {
				if !strings.HasPrefix(part, "[") {
					part = "[" + part
				}
				fmt.Fprintf(w, "            deny  %s\n", part)
			}
		}
		for _, warn := range v.Warnings {
			fmt.Fprintf(w, "            warn  %s\n", warn)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%d object(s): %d allowed, %d denied\n", len(reports), allowed, denied)
}

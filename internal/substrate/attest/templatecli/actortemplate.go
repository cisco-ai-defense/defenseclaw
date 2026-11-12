// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package templatecli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// ExitUnavailable is the exit code when the Substrate API cannot be reached
// (EX_TEMPFAIL): the image may be published already, and the same command can
// be run again.
const ExitUnavailable = 75

// ClassLabel is the worker pool label `--class` selects on when no
// `--worker-label` is given. The pools of a cluster must carry it.
const ClassLabel = "defenseclaw.io/sandbox-class"

const (
	// containerName is the one container of a kit template.
	containerName = "agent"
	// systemInfoMount is where the egress trust bundle and the actor identity
	// files are projected (kit.TrustBundle and the relay's identity dir live
	// under it).
	systemInfoMount = "/run/ate"
	// probePort and probePath are the relay's readiness endpoint; the kit
	// image's ENTRYPOINT starts the relay, so the template sets no command.
	probePort    = 8080
	probePath    = "/readyz"
	probeTimeout = 120
	// kitWorkdir is the WORKDIR of the kit images. An ActorTemplate has no
	// working-directory field: the image decides.
	kitWorkdir = "/work"

	defaultCPU    = "1500m"
	defaultMemory = "1536Mi"
	revisionHex   = 8
	maxNameLen    = 63
)

var (
	labelRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	digestRE = regexp.MustCompile(`^[^\s@]+@sha256:[0-9a-f]{64}$`)
	// secretNameRE matches variable names that usually hold a credential. A
	// template is stored in the cluster and shown to its readers: the real
	// value belongs to the egress credential provider, not to the template.
	secretNameRE = regexp.MustCompile(`(?i)(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE)`)
)

// Seams for tests: the publish step, the verify step of --dry-run, the API
// dialer and the retry backoff.
var (
	publishImage = attest.Publish
	verifyImage  = func(ctx context.Context, v *attest.Verifier, image string) (string, error) {
		got, err := v.Verify(ctx, image)
		if err != nil {
			return "", err
		}
		return got.Digest, nil
	}
	dialAPI = func(o ateapi.Options) (ateapi.Client, error) {
		c, err := ateapi.New(o)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	apiBackoff = 300 * time.Millisecond
)

// templateFlags are the flags of `publish` that create the ActorTemplate.
type templateFlags struct {
	template   string
	class      string
	cpu        string
	memory     string
	workdir    string
	env        multi
	labels     multi
	dryRun     bool
	apiAddress string
	apiServer  string
	apiCA      string
	apiToken   string
	apiAuth    string
}

func (t *templateFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&t.template, "template", "", "create or update the ActorTemplate ATESPACE/NAME from the published image")
	fs.StringVar(&t.class, "class", "gvisor", "sandbox class of the template: gvisor or microvm")
	fs.StringVar(&t.cpu, "cpu", defaultCPU, "cpu limit of the actor, for example 1500m or 2")
	fs.StringVar(&t.memory, "memory", defaultMemory, "memory limit of the actor, for example 1536Mi or 2Gi")
	fs.StringVar(&t.workdir, "workdir", "", "working directory; the image decides it (kit images use "+kitWorkdir+"), so only that value is accepted")
	fs.Var(&t.env, "env", "non-secret environment variable K=V for the container (repeatable)")
	fs.Var(&t.labels, "worker-label", "label K=V a worker pool must carry (repeatable; replaces the --class label)")
	fs.BoolVar(&t.dryRun, "dry-run", false, "verify the image and print what would happen; copy and create nothing")
	fs.StringVar(&t.apiAddress, "api-address", "", "ate-api-server host:port (default substrate.api.address)")
	fs.StringVar(&t.apiServer, "api-server-name", "", "TLS name of ate-api-server (default substrate.api.server_name)")
	fs.StringVar(&t.apiCA, "api-ca-file", "", "CA bundle that signed ate-api-server's certificate (default substrate.api.ca_file)")
	fs.StringVar(&t.apiToken, "api-token-file", "", "bearer token file (default substrate.api.token_file)")
	fs.StringVar(&t.apiAuth, "api-auth", "", "serviceaccount or mtls (default substrate.api.auth)")
}

// templatePlan is a validated --template request.
type templatePlan struct {
	Atespace string
	Name     string
	Class    string
	CPU      int64 // millicores
	Memory   int64 // bytes
	Env      []*ateapi.EnvVar
	Labels   map[string]string
	API      ateapi.Options
}

// plan validates the flags; given names the flags that were set. It returns
// nil when --template is not given.
func (t *templateFlags) plan(cfg *config.Config, given map[string]bool) (*templatePlan, error) {
	if t.template == "" {
		for _, n := range []string{"class", "cpu", "memory", "workdir", "env", "worker-label",
			"api-address", "api-server-name", "api-ca-file", "api-token-file", "api-auth"} {
			if given[n] {
				return nil, fmt.Errorf("--%s only applies with --template ATESPACE/NAME", n)
			}
		}
		return nil, nil
	}
	p := &templatePlan{}
	ns, name, ok := strings.Cut(t.template, "/")
	if !ok || !validLabel(ns) || !validLabel(name) {
		return nil, fmt.Errorf("--template wants ATESPACE/NAME with lower-case letters, digits and dashes, got %q", t.template)
	}
	p.Atespace, p.Name = ns, name
	switch c := strings.ToLower(t.class); c {
	case config.SubstrateSandboxGVisor, config.SubstrateSandboxMicroVM:
		p.Class = c
	default:
		return nil, fmt.Errorf("--class wants gvisor or microvm, got %q", t.class)
	}
	var err error
	if p.CPU, err = parseCPU(t.cpu); err != nil {
		return nil, err
	}
	if p.Memory, err = parseMemory(t.memory); err != nil {
		return nil, err
	}
	if t.workdir != "" && t.workdir != kitWorkdir {
		return nil, fmt.Errorf("--workdir %q: an ActorTemplate has no working-directory field; the image WORKDIR decides it (%s in the kit images)", t.workdir, kitWorkdir)
	}
	if p.Env, err = parseEnv(t.env); err != nil {
		return nil, err
	}
	if p.Labels, err = parseLabels(t.labels, p.Class); err != nil {
		return nil, err
	}
	api := cfg.Substrate.API
	auth, err := ateapi.ParseAuth(first(t.apiAuth, api.Auth))
	if err != nil {
		return nil, err
	}
	p.API = ateapi.Options{
		Address:          first(t.apiAddress, api.Address),
		ServerName:       first(t.apiServer, api.ServerName),
		CAFile:           first(t.apiCA, api.CAFile),
		Auth:             auth,
		TokenFile:        first(t.apiToken, api.TokenFile),
		CredentialBundle: api.CredentialBundle,
	}
	return p, nil
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func validLabel(s string) bool { return len(s) <= maxNameLen && labelRE.MatchString(s) }

func parseCPU(s string) (int64, error) {
	s = strings.TrimSpace(s)
	var milli float64
	if v, ok := strings.CutSuffix(s, "m"); ok {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("--cpu %q is not a number of cores (2) or millicores (1500m)", s)
		}
		milli = f
	} else {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, fmt.Errorf("--cpu %q is not a number of cores (2) or millicores (1500m)", s)
		}
		milli = f * 1000
	}
	if math.IsNaN(milli) || milli < 1 || milli > 999999 {
		return 0, fmt.Errorf("--cpu %q must be between 1m and 999 cores", s)
	}
	return int64(math.Round(milli)), nil
}

func parseMemory(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := float64(1)
	for _, u := range []struct {
		suffix string
		mult   float64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}} {
		if v, ok := strings.CutSuffix(s, u.suffix); ok {
			s, mult = v, u.mult
			break
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || f <= 0 || f*mult > float64(math.MaxInt64)/2 {
		return 0, fmt.Errorf("--memory wants a size such as 1536Mi, 2Gi or a number of bytes")
	}
	return int64(f * mult), nil
}

func parseEnv(kvs []string) ([]*ateapi.EnvVar, error) {
	seen := map[string]bool{}
	var out []*ateapi.EnvVar
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" || strings.ContainsAny(k, " \t\r\n") {
			return nil, fmt.Errorf("--env wants K=V, got %q", redactEnv(kv))
		}
		if seen[k] {
			return nil, fmt.Errorf("--env %s is given twice", k)
		}
		seen[k] = true
		if secretNameRE.MatchString(k) && !strings.HasPrefix(strings.ToLower(v), "placeholder") {
			return nil, fmt.Errorf("--env %s looks like a credential: a template is readable by anyone who can read the cluster. Give a placeholder value (placeholder-...) and let the egress credential provider inject the real one", k)
		}
		out = append(out, &ateapi.EnvVar{Name: k, Value: v})
	}
	slices.SortFunc(out, func(a, b *ateapi.EnvVar) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// redactEnv hides the value of a malformed --env so an error line cannot
// echo a secret that was pasted by mistake.
func redactEnv(kv string) string {
	if k, _, ok := strings.Cut(kv, "="); ok {
		return k + "=..."
	}
	return "..."
}

func parseLabels(kvs []string, class string) (map[string]string, error) {
	if len(kvs) == 0 {
		return map[string]string{ClassLabel: class}, nil
	}
	out := map[string]string{}
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--worker-label wants K=V, got %q", kv)
		}
		out[k] = v
	}
	if len(out) > 10 {
		return nil, errors.New("--worker-label: at most 10 labels")
	}
	return out, nil
}

// buildTemplate is the ActorTemplate of a kit image: one container that runs
// the image's own ENTRYPOINT (the relay), readiness on the relay's /readyz,
// the egress trust bundle and the actor identity files projected under
// /run/ate, and the sized limits. Every field is the one the E1 probe
// templates use.
func buildTemplate(p *templatePlan, name, image string) (*ateapi.ActorTemplate, error) {
	if !digestRE.MatchString(image) {
		return nil, fmt.Errorf("the template image %q is not pinned by digest (repo@sha256:...)", image)
	}
	t := &ateapi.ActorTemplate{
		Metadata: &ateapi.ResourceMetadata{Atespace: p.Atespace, Name: name},
		Containers: []*ateapi.Container{{
			Name:         containerName,
			Image:        image,
			Env:          p.Env,
			VolumeMounts: []*ateapi.VolumeMount{{Name: "system-info", MountPath: systemInfoMount}},
			WakeupProbe:  &ateapi.WakeupProbe{HttpGet: &ateapi.HttpGetAction{Path: probePath, Port: probePort}, TimeoutSeconds: probeTimeout},
		}},
		Volumes: []*ateapi.Volume{{
			Name: "system-info",
			SystemInfo: &ateapi.SystemInfoVolume{DataSources: []*ateapi.SystemInfoDataSource{
				{TrustBundle: &ateapi.TrustBundleSource{Names: []string{"egress-mitm.ate.dev", "system-roots.ate.dev"}, Path: "trust-bundle.pem"}},
				{ActorMetadata: &ateapi.ActorMetadataSource{Items: []*ateapi.ActorMetadataItem{
					{Field: ateapi.ActorMetadataFieldAtespace, Path: "actor/atespace"},
					{Field: ateapi.ActorMetadataFieldName, Path: "actor/name"},
					{Field: ateapi.ActorMetadataFieldUID, Path: "actor/uid"},
				}}},
			}},
		}},
		Resources:      &ateapi.ResourceRequirements{Limits: &ateapi.Resources{CpuMillicores: p.CPU, MemoryBytes: p.Memory}},
		SnapshotConfig: &ateapi.SnapshotConfig{PreferredFidelity: ateapi.SnapshotFidelityMemory},
	}
	if len(p.Labels) > 0 {
		t.WorkerSelector = &ateapi.Selector{MatchLabels: p.Labels}
	}
	return t, nil
}

// settingsOf drops what the server owns or defaults (metadata, status, the
// golden-snapshot settings) and puts the lists in a fixed order, so two
// templates with the same image and settings compare equal.
func settingsOf(t *ateapi.ActorTemplate) *ateapi.ActorTemplate {
	c := proto.Clone(t).(*ateapi.ActorTemplate)
	c.Metadata, c.Status, c.GoldenEgressPolicy = nil, nil, nil
	fid := c.GetSnapshotConfig().GetPreferredFidelity()
	if fid == 0 {
		fid = ateapi.SnapshotFidelityMemory
	}
	c.SnapshotConfig = &ateapi.SnapshotConfig{PreferredFidelity: fid}
	if len(c.GetWorkerSelector().GetMatchLabels()) == 0 {
		c.WorkerSelector = nil
	}
	for _, ct := range c.Containers {
		slices.SortFunc(ct.Env, func(a, b *ateapi.EnvVar) int { return strings.Compare(a.Name, b.Name) })
		slices.SortFunc(ct.VolumeMounts, func(a, b *ateapi.VolumeMount) int { return strings.Compare(a.MountPath, b.MountPath) })
	}
	slices.SortFunc(c.Volumes, func(a, b *ateapi.Volume) int { return strings.Compare(a.Name, b.Name) })
	return c
}

func sameSettings(a, b *ateapi.ActorTemplate) bool { return proto.Equal(settingsOf(a), settingsOf(b)) }

// revisionName is the name of the new revision of a template whose image
// changed: NAME-<first 8 hex of the image digest>.
func revisionName(name, image string) (string, error) {
	_, d, _ := strings.Cut(image, "@sha256:")
	if len(d) < revisionHex {
		return "", fmt.Errorf("image %q has no digest", image)
	}
	rev := name + "-" + d[:revisionHex]
	if len(rev) > maxNameLen {
		return "", fmt.Errorf("the name %q is too long for a revision suffix; use at most %d characters", name, maxNameLen-revisionHex-1)
	}
	return rev, nil
}

// Result is what `publish --template` did, and the template block of
// `publish --json`.
type Result struct {
	// Action is created, revision (a new name for a changed image or
	// settings), up-to-date or dry-run.
	Action    string `json:"action"`
	Atespace  string `json:"atespace"`
	Name      string `json:"name"`
	Requested string `json:"requested"`
	Image     string `json:"image"`
	// RunWith is the name to give `defenseclaw substrate run --template`.
	RunWith string `json:"run_with,omitempty"`
	// Template is the template that would be created (dry-run only).
	Template json.RawMessage `json:"template,omitempty"`
}

// templateUnavailable is an API that could not be reached.
type templateUnavailable struct{ err error }

func (e *templateUnavailable) Error() string {
	return "the Substrate API cannot be reached: " + apiMessage(e.err)
}
func (e *templateUnavailable) Unwrap() error { return e.err }

func apiMessage(err error) string {
	if s, ok := status.FromError(err); ok {
		return s.Message()
	}
	return err.Error()
}

// call runs one API call, retrying transient failures (the client does not).
func call[T any](ctx context.Context, f func() (T, error)) (T, error) {
	var (
		out T
		err error
	)
	delay := apiBackoff
	for attempt := range 3 {
		if out, err = f(); err == nil || !ateapi.IsRetryable(err) || ctx.Err() != nil {
			break
		}
		if attempt < 2 && delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
			}
			delay *= 2
		}
	}
	if c := status.Code(err); c == codes.Unavailable || c == codes.DeadlineExceeded {
		return out, &templateUnavailable{err}
	}
	return out, err
}

// getTemplate returns the template or nil when it does not exist.
func getTemplate(ctx context.Context, c ateapi.Client, atespace, name string) (*ateapi.ActorTemplate, error) {
	t, err := call(ctx, func() (*ateapi.ActorTemplate, error) { return c.GetActorTemplate(ctx, ateapi.Ref(atespace, name)) })
	if ateapi.IsNotFound(err) {
		return nil, nil
	}
	return t, err
}

// applyTemplate creates the ActorTemplate for image, or says it is up to date,
// or creates a revision. Templates are immutable and may have actors, so it
// never deletes or replaces one.
func applyTemplate(ctx context.Context, c ateapi.Client, p *templatePlan, image string) (*Result, error) {
	res := &Result{Atespace: p.Atespace, Requested: p.Name, Image: image}
	want, err := buildTemplate(p, p.Name, image)
	if err != nil {
		return nil, err
	}
	have, err := getTemplate(ctx, c, p.Atespace, p.Name)
	if err != nil {
		return nil, err
	}
	if have == nil {
		return finish(res, create(ctx, c, res, want, "created"))
	}
	if sameSettings(have, want) {
		res.Action, res.Name, res.RunWith = "up-to-date", p.Name, p.Name
		return res, nil
	}
	rev, err := revisionName(p.Name, image)
	if err != nil {
		return nil, err
	}
	want, _ = buildTemplate(p, rev, image)
	return finish(res, create(ctx, c, res, want, "revision"))
}

func finish(res *Result, err error) (*Result, error) {
	if err != nil {
		return nil, err
	}
	return res, nil
}

// create stores want. A template that appears meanwhile (a retry that had
// already landed, or another publisher) is accepted when it is the same.
func create(ctx context.Context, c ateapi.Client, res *Result, want *ateapi.ActorTemplate, action string) error {
	name := want.GetMetadata().GetName()
	_, err := call(ctx, func() (*ateapi.ActorTemplate, error) { return c.CreateActorTemplate(ctx, want) })
	switch {
	case err == nil:
		res.Action = action
	case ateapi.IsAlreadyExists(err):
		have, gerr := getTemplate(ctx, c, res.Atespace, name)
		if gerr != nil {
			return gerr
		}
		if have == nil || !sameSettings(have, want) {
			return fmt.Errorf("the template %s/%s exists with other settings for the same image; pick another name with --template", res.Atespace, name)
		}
		res.Action = "up-to-date"
	default:
		return err
	}
	res.Name, res.RunWith = name, name
	return nil
}

// dryRunResult is the template that publish would create, as it appears in
// the output.
func dryRunResult(p *templatePlan, image string) (*Result, *ateapi.ActorTemplate, error) {
	t, err := buildTemplate(p, p.Name, image)
	if err != nil {
		return nil, nil, err
	}
	b, err := templateJSON(t)
	if err != nil {
		return nil, nil, err
	}
	return &Result{Action: "dry-run", Atespace: p.Atespace, Name: p.Name, Requested: p.Name, Image: image, Template: b}, t, nil
}

// templateJSON is the template in the camelCase form `kubectl ate` reads.
func templateJSON(t *ateapi.ActorTemplate) (json.RawMessage, error) {
	raw, err := protojson.MarshalOptions{}.Marshal(t)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	numberize(m)
	return json.Marshal(m)
}

// numberize turns the 64-bit sizes protojson writes as strings back into
// numbers, as they appear in a template file.
func numberize(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && (k == "cpuMillicores" || k == "memoryBytes") {
				if n, err := strconv.ParseInt(s, 10, 64); err == nil {
					x[k] = n
				}
				continue
			}
			numberize(e)
		}
	case []any:
		for _, e := range x {
			numberize(e)
		}
	}
}

// printTemplateYAML writes a template as YAML.
func printTemplateYAML(w io.Writer, raw json.RawMessage) error {
	// UseNumber keeps 1610612736 from becoming a float.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return err
	}
	plainNumbers(m)
	b, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// plainNumbers turns the json.Number values into integers, which YAML writes
// unquoted.
func plainNumbers(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if n, ok := e.(json.Number); ok {
				if i, err := n.Int64(); err == nil {
					x[k] = i
				}
				continue
			}
			plainNumbers(e)
		}
	case []any:
		for _, e := range x {
			plainNumbers(e)
		}
	}
}

func printResult(w io.Writer, r *Result) {
	switch r.Action {
	case "created":
		fmt.Fprintf(w, "created actor template %s/%s\n  image %s\n  run with: defenseclaw substrate run --template %s\n", r.Atespace, r.Name, r.Image, r.RunWith)
	case "revision":
		fmt.Fprintf(w, "actor template %s/%s has another image or settings and cannot be changed (templates are immutable)\ncreated the new revision %s/%s\n  image %s\n  run with: defenseclaw substrate run --template %s\n",
			r.Atespace, r.Requested, r.Atespace, r.Name, r.Image, r.RunWith)
	case "up-to-date":
		fmt.Fprintf(w, "actor template %s/%s is already up to date\n  image %s\n  run with: defenseclaw substrate run --template %s\n", r.Atespace, r.Name, r.Image, r.RunWith)
	}
}

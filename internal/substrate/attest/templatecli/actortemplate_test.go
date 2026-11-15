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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

const testRepo = "registry.example.test/team/kit"

func digestOf(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }
func imageOf(c byte) string  { return testRepo + "@" + digestOf(c) }

// noClose lets one fake serve several runs: the fake refuses calls after Close.
type noClose struct{ ateapi.Client }

func (noClose) Close() error { return nil }

type rig struct {
	fake      *ateapifake.Fake
	dialed    int
	opts      ateapi.Options
	published int
	verified  int
	image     string // what the stubbed publish returns
	pubErr    error
}

// newRig stubs the publish, verify and dial steps. The fake has the atespace
// "team".
func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{fake: ateapifake.New(), image: imageOf('a')}
	r.fake.PutAtespace("team")
	oldPub, oldVer, oldDial, oldBackoff := publishImage, verifyImage, dialAPI, apiBackoff
	t.Cleanup(func() { publishImage, verifyImage, dialAPI, apiBackoff = oldPub, oldVer, oldDial, oldBackoff })
	apiBackoff = 0
	publishImage = func(context.Context, attest.PublishOptions) (string, error) {
		r.published++
		return r.image, r.pubErr
	}
	verifyImage = func(context.Context, *attest.Verifier, string) (string, error) {
		r.verified++
		_, d, _ := strings.Cut(r.image, "@")
		return d, r.pubErr
	}
	dialAPI = func(o ateapi.Options) (ateapi.Client, error) {
		r.dialed++
		r.opts = o
		return noClose{r.fake}, nil
	}
	return r
}

// anchorsFile writes a trust anchor with the keygen command.
func anchorsFile(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"keygen", "--out", dir}, &out, &errb); code != ExitOK {
		t.Fatalf("keygen: %d %s", code, errb.String())
	}
	return filepath.Join(dir, "attestation.pub")
}

func publish(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), append([]string{"publish", "src@" + digestOf('a'), "registry.example.test/team/kit:v1", "--anchors", anchorsFile(t)}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func plan(t *testing.T) *templatePlan {
	t.Helper()
	p, err := (&templateFlags{template: "team/kit", class: "gvisor", cpu: defaultCPU, memory: defaultMemory}).plan(&config.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyCreatesTheTemplateOfTheKitImage(t *testing.T) {
	f := ateapifake.New()
	f.PutAtespace("team")
	p := plan(t)
	p.Env = []*ateapi.EnvVar{{Name: "LANG", Value: "C.UTF-8"}}
	res, err := applyTemplate(context.Background(), f, p, imageOf('a'))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "created" || res.Name != "kit" || res.RunWith != "kit" {
		t.Fatalf("result = %+v", res)
	}
	got, err := f.GetActorTemplate(context.Background(), ateapi.Ref("team", "kit"))
	if err != nil {
		t.Fatal(err)
	}
	c := got.GetContainers()[0]
	if c.GetImage() != imageOf('a') || len(c.GetCommand()) != 0 || len(c.GetArgs()) != 0 {
		t.Errorf("container = %v: the image digest is used and the image ENTRYPOINT runs", c)
	}
	if pr := c.GetWakeupProbe().GetHttpGet(); pr.GetPath() != "/readyz" || pr.GetPort() != 8080 {
		t.Errorf("probe = %v", c.GetWakeupProbe())
	}
	if c.GetEnv()[0].GetName() != "LANG" {
		t.Errorf("env = %v", c.GetEnv())
	}
	if l := got.GetResources().GetLimits(); l.GetCpuMillicores() != 1500 || l.GetMemoryBytes() != 1536<<20 {
		t.Errorf("limits = %v", l)
	}
	if got.GetWorkerSelector().GetMatchLabels()[ClassLabel] != "gvisor" {
		t.Errorf("selector = %v", got.GetWorkerSelector())
	}
	if v := got.GetVolumes()[0].GetSystemInfo().GetDataSources(); len(v) != 2 {
		t.Errorf("system-info volume = %v", got.GetVolumes())
	}
}

func TestApplySameImageIsUpToDateAndANewImageIsARevision(t *testing.T) {
	ctx := context.Background()
	f := ateapifake.New()
	f.PutAtespace("team")
	p := plan(t)
	if _, err := applyTemplate(ctx, f, p, imageOf('a')); err != nil {
		t.Fatal(err)
	}
	res, err := applyTemplate(ctx, f, p, imageOf('a'))
	if err != nil || res.Action != "up-to-date" || res.Name != "kit" {
		t.Fatalf("same digest: %+v %v", res, err)
	}
	if n := f.Calls("CreateActorTemplate"); n != 1 {
		t.Fatalf("the up-to-date run created again (%d creates)", n)
	}

	res, err = applyTemplate(ctx, f, p, imageOf('b'))
	if err != nil || res.Action != "revision" || res.Name != "kit-bbbbbbbb" || res.RunWith != "kit-bbbbbbbb" || res.Requested != "kit" {
		t.Fatalf("new digest: %+v %v", res, err)
	}
	old, err := f.GetActorTemplate(ctx, ateapi.Ref("team", "kit"))
	if err != nil || old.GetContainers()[0].GetImage() != imageOf('a') {
		t.Fatalf("the first template changed: %v %v", old, err)
	}
	// The revision is found again, not created twice.
	res, err = applyTemplate(ctx, f, p, imageOf('b'))
	if err != nil || res.Action != "up-to-date" || res.Name != "kit-bbbbbbbb" {
		t.Fatalf("revision again: %+v %v", res, err)
	}
	if n := f.Calls("CreateActorTemplate"); n != 3 {
		// 1 first, 2 the revision, 3 the revision again (already exists)
		t.Fatalf("creates = %d", n)
	}
	all, _ := ateapi.AllActorTemplates(ctx, f, "team", 0)
	if len(all) != 2 {
		t.Fatalf("%d templates, want 2", len(all))
	}
}

func TestApplyChangedSettingsMakeARevisionOfTheSameImage(t *testing.T) {
	ctx := context.Background()
	f := ateapifake.New()
	f.PutAtespace("team")
	p := plan(t)
	if _, err := applyTemplate(ctx, f, p, imageOf('a')); err != nil {
		t.Fatal(err)
	}
	p.CPU = 2000
	res, err := applyTemplate(ctx, f, p, imageOf('a'))
	if err != nil || res.Action != "revision" || res.Name != "kit-aaaaaaaa" {
		t.Fatalf("%+v %v", res, err)
	}
	// Another change on the same digest collides with the revision name.
	p.CPU = 3000
	if _, err := applyTemplate(ctx, f, p, imageOf('a')); err == nil || !strings.Contains(err.Error(), "exists with other settings") {
		t.Fatalf("collision: %v", err)
	}
}

func TestApplyComparesOnlyWhatPublishSets(t *testing.T) {
	ctx := context.Background()
	f := ateapifake.New()
	f.PutAtespace("team")
	p := plan(t)
	p.Env = []*ateapi.EnvVar{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}}
	want, _ := buildTemplate(p, "kit", imageOf('a'))
	// As the server may return it: snapshot settings left to their default,
	// env in another order, metadata set.
	want.SnapshotConfig = nil
	want.Containers[0].Env = []*ateapi.EnvVar{{Name: "B", Value: "2"}, {Name: "A", Value: "1"}}
	f.PutTemplate(want)
	res, err := applyTemplate(ctx, f, p, imageOf('a'))
	if err != nil || res.Action != "up-to-date" {
		t.Fatalf("%+v %v", res, err)
	}
	// Another env is a different template.
	p.Env = []*ateapi.EnvVar{{Name: "EXTRA", Value: "1"}}
	if res, err = applyTemplate(ctx, f, p, imageOf('a')); err != nil || res.Action != "revision" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestApplyRefusesATag(t *testing.T) {
	f := ateapifake.New()
	f.PutAtespace("team")
	for _, img := range []string{testRepo + ":v1", testRepo, testRepo + "@sha256:abc", ""} {
		if _, err := applyTemplate(context.Background(), f, plan(t), img); err == nil || !strings.Contains(err.Error(), "pinned by digest") {
			t.Errorf("%q: %v", img, err)
		}
	}
	if f.Calls("CreateActorTemplate")+f.Calls("GetActorTemplate") != 0 {
		t.Fatal("the API was called for an unpinned image")
	}
}

func TestPublishWithTemplateCreatesIt(t *testing.T) {
	r := newRig(t)
	code, out, errText := publish(t, "--template", "team/kit", "--env", "LANG=C.UTF-8", "--cpu", "2", "--memory", "2Gi", "--api-address", "api.example.test:443")
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, out, errText)
	}
	for _, want := range []string{"published " + imageOf('a'), "created actor template team/kit", "run with: defenseclaw substrate run --template kit"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if r.opts.Address != "api.example.test:443" {
		t.Errorf("address = %q", r.opts.Address)
	}
	got, err := r.fake.GetActorTemplate(context.Background(), ateapi.Ref("team", "kit"))
	if err != nil || got.GetResources().GetLimits().GetCpuMillicores() != 2000 || got.GetResources().GetLimits().GetMemoryBytes() != 2<<30 {
		t.Fatalf("template = %v %v", got, err)
	}

	// Again with the same image: nothing happens. Then a new image.
	if code, out, _ = publish(t, "--template", "team/kit", "--env", "LANG=C.UTF-8", "--cpu", "2", "--memory", "2Gi"); code != ExitOK || !strings.Contains(out, "already up to date") {
		t.Fatalf("second run: %d\n%s", code, out)
	}
	r.image = imageOf('c')
	code, out, _ = publish(t, "--template", "team/kit", "--env", "LANG=C.UTF-8", "--cpu", "2", "--memory", "2Gi", "--json")
	var js struct {
		Published bool    `json:"published"`
		Template  *Result `json:"template"`
	}
	if err := json.Unmarshal([]byte(out), &js); err != nil || code != ExitOK || !js.Published || js.Template.Action != "revision" || js.Template.RunWith != "kit-cccccccc" {
		t.Fatalf("json run: %d %v\n%s", code, err, out)
	}
	if n := r.fake.Calls("CreateActorTemplate"); n != 2 {
		t.Fatalf("creates = %d, want 2", n)
	}
}

func TestPublishWithoutTemplateOnlyCopies(t *testing.T) {
	r := newRig(t)
	code, out, errText := publish(t)
	if code != ExitOK || out != "published "+imageOf('a')+"\n" || errText != "" {
		t.Fatalf("exit %d\n%q\n%q", code, out, errText)
	}
	if r.dialed != 0 || r.fake.Calls("GetActorTemplate")+r.fake.Calls("CreateActorTemplate") != 0 {
		t.Fatal("the API was used without --template")
	}
	code, out, _ = publish(t, "--json")
	if code != ExitOK || !strings.Contains(out, `"published": true`) || strings.Contains(out, "template") {
		t.Fatalf("json: %d %s", code, out)
	}
}

func TestPublishNotAdmittedCreatesNothing(t *testing.T) {
	r := newRig(t)
	r.pubErr = &attest.Rejection{Code: "untrusted_key", Detail: "signed by a key that is not trusted"}
	code, out, _ := publish(t, "--template", "team/kit")
	if code != ExitNotAdmit || !strings.Contains(out, "NOT PUBLISHED: untrusted_key") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if n := r.fake.Calls("CreateActorTemplate"); n != 0 {
		t.Fatalf("a template was created for a rejected image (%d)", n)
	}
	if all, _ := ateapi.AllActorTemplates(context.Background(), r.fake, "", 0); len(all) != 0 {
		t.Fatalf("templates = %v", all)
	}
}

// With the real verifier: a tag is refused before any registry call.
func TestPublishATagIsRefusedAndCreatesNothing(t *testing.T) {
	r := newRig(t)
	publishImage = attest.Publish
	var out, errb bytes.Buffer
	code := Run(context.Background(), []string{"publish", testRepo + ":v1", "registry.example.test/team/out:v1", "--anchors", anchorsFile(t), "--template", "team/kit"}, &out, &errb)
	if code != ExitNotAdmit || !strings.Contains(out.String(), "NOT PUBLISHED") || !strings.Contains(out.String(), "digest") {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	if r.fake.Calls("CreateActorTemplate") != 0 {
		t.Fatal("a template was created")
	}
}

func TestPublishUnreachableAPIExits75BeforeCopying(t *testing.T) {
	r := newRig(t)
	r.fake.Err = func(method, _ string) error {
		return status.Error(codes.Unavailable, "connection refused")
	}
	code, _, errText := publish(t, "--template", "team/kit")
	if code != ExitUnavailable || !strings.Contains(errText, "cannot be reached") {
		t.Fatalf("exit %d: %s", code, errText)
	}
	if r.published != 0 {
		t.Fatal("the image was copied to a cluster that cannot be reached")
	}
	if n := r.fake.Calls("GetActorTemplate"); n != 3 {
		t.Fatalf("the read was tried %d times, want 3", n)
	}

	// The API goes away after the copy: exit 75, the image is published, the
	// message says to run it again.
	r.fake.Err = func(method, _ string) error {
		if method == "CreateActorTemplate" {
			return status.Error(codes.Unavailable, "connection reset")
		}
		return nil
	}
	code, out, errText := publish(t, "--template", "team/kit")
	if code != ExitUnavailable || r.published != 1 || !strings.Contains(out, "published "+imageOf('a')) || !strings.Contains(out, "run the same command again") {
		t.Fatalf("exit %d published %d\n%s%s", code, r.published, out, errText)
	}
}

func TestPublishAPIRefusalIsExit1(t *testing.T) {
	r := newRig(t)
	r.fake.Err = func(method, _ string) error {
		if method == "CreateActorTemplate" {
			return status.Error(codes.PermissionDenied, "not allowed to create templates in team")
		}
		return nil
	}
	code, _, errText := publish(t, "--template", "team/kit")
	if code != ExitNotAdmit || !strings.Contains(errText, "not allowed") {
		t.Fatalf("exit %d: %s", code, errText)
	}
	if n := r.fake.Calls("CreateActorTemplate"); n != 1 {
		t.Fatalf("a refusal was retried (%d calls)", n)
	}
}

func TestPublishDryRunTouchesNothing(t *testing.T) {
	r := newRig(t)
	dialAPI = func(ateapi.Options) (ateapi.Client, error) {
		t.Fatal("dry run contacted the API")
		return nil, nil
	}
	code, out, errText := publish(t, "--template", "team/kit", "--dry-run", "--env", "LANG=C.UTF-8")
	if code != ExitOK || errText != "" {
		t.Fatalf("exit %d: %s", code, errText)
	}
	img := "registry.example.test/team/kit@" + digestOf('a')
	for _, want := range []string{"dry run: would publish " + img, "image: " + img, "name: kit", "atespace: team", "path: /readyz", "cpuMillicores: 1500", "name: LANG", "kit-<first 8 hex"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "command:") {
		t.Errorf("the template sets a command:\n%s", out)
	}
	if r.published != 0 || r.verified != 1 {
		t.Fatalf("published %d verified %d", r.published, r.verified)
	}
	code, out, _ = publish(t, "--template", "team/kit", "--dry-run", "--json")
	var js struct {
		DryRun bool   `json:"dry_run"`
		Image  string `json:"image"`
	}
	if err := json.Unmarshal([]byte(out), &js); err != nil || code != ExitOK || !js.DryRun || js.Image != img || !strings.Contains(out, `"cpuMillicores": 1500`) {
		t.Fatalf("json: %d %v\n%s", code, err, out)
	}
	// Dry run without --template only says what would be copied.
	if code, out, _ = publish(t, "--dry-run"); code != ExitOK || !strings.Contains(out, "dry run: would publish "+img) {
		t.Fatalf("%d %s", code, out)
	}
	// A rejected image is reported the same way in a dry run.
	r.pubErr = &attest.Rejection{Code: "unattested", Detail: "no attestation"}
	if code, out, _ = publish(t, "--template", "team/kit", "--dry-run"); code != ExitNotAdmit || !strings.Contains(out, "WOULD NOT PUBLISH: unattested") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestPublishTemplateFlagsAreChecked(t *testing.T) {
	newRig(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bad ref", []string{"--template", "kit"}, "ATESPACE/NAME"},
		{"upper case", []string{"--template", "Team/kit"}, "ATESPACE/NAME"},
		{"bad class", []string{"--template", "team/kit", "--class", "vm"}, "gvisor or microvm"},
		{"bad cpu", []string{"--template", "team/kit", "--cpu", "lots"}, "--cpu"},
		{"bad memory", []string{"--template", "team/kit", "--memory", "-1"}, "--memory"},
		{"workdir", []string{"--template", "team/kit", "--workdir", "/srv"}, "no working-directory field"},
		{"env without equals", []string{"--template", "team/kit", "--env", "LANG"}, "K=V"},
		{"env twice", []string{"--template", "team/kit", "--env", "A=1", "--env", "A=2"}, "twice"},
		{"secret env", []string{"--template", "team/kit", "--env", "API_TOKEN=abc123"}, "looks like a credential"},
		{"bad auth", []string{"--template", "team/kit", "--api-auth", "basic"}, "serviceaccount or mtls"},
		{"flag without template", []string{"--cpu", "2"}, "only applies with --template"},
		{"api flag without template", []string{"--api-address", "x:1"}, "only applies with --template"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errText := publish(t, tc.args...)
			if code != ExitUsageError || !strings.Contains(errText, tc.want) {
				t.Fatalf("exit %d: %s", code, errText)
			}
			if strings.Contains(out+errText, "abc123") {
				t.Errorf("the value of a refused variable is printed: %s%s", out, errText)
			}
		})
	}
	// A placeholder under a credential-like name is how the egress provider
	// is told to inject the real one.
	if _, err := parseEnv([]string{"AWS_BEARER_TOKEN_BEDROCK=placeholder-not-a-secret"}); err != nil {
		t.Errorf("placeholder refused: %v", err)
	}
}

func TestPublishReadsTheAPIFromConfigAndFlagsWin(t *testing.T) {
	r := newRig(t)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("config_version: 9\nsubstrate:\n  api:\n    address: api.example.test:8443\n    server_name: api.example.test\n    ca_file: /etc/example/ca.pem\n    auth: mtls\n    token_file: /etc/example/token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errText := publish(t, "--template", "team/kit", "--config", cfg); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errText)
	}
	o := r.opts
	if o.Address != "api.example.test:8443" || o.ServerName != "api.example.test" || o.CAFile != "/etc/example/ca.pem" || o.Auth != ateapi.AuthMTLS || o.TokenFile != "/etc/example/token" {
		t.Fatalf("options from config = %+v", o)
	}
	if code, _, errText := publish(t, "--template", "team/kit", "--config", cfg, "--api-address", "other.example.test:443", "--api-auth", "serviceaccount", "--api-token-file", "/tmp/tok", "--api-ca-file", "/tmp/ca"); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errText)
	}
	o = r.opts
	if o.Address != "other.example.test:443" || o.Auth != ateapi.AuthServiceAccount || o.TokenFile != "/tmp/tok" || o.CAFile != "/tmp/ca" {
		t.Fatalf("flags did not win: %+v", o)
	}
}

func TestPublishMicroVMClassAndWorkerLabels(t *testing.T) {
	r := newRig(t)
	if code, _, e := publish(t, "--template", "team/kit", "--class", "microvm"); code != ExitOK {
		t.Fatalf("%d %s", code, e)
	}
	got, _ := r.fake.GetActorTemplate(context.Background(), ateapi.Ref("team", "kit"))
	if l := got.GetWorkerSelector().GetMatchLabels(); len(l) != 1 || l[ClassLabel] != "microvm" {
		t.Fatalf("selector = %v", l)
	}
	if code, _, e := publish(t, "--template", "team/pool", "--worker-label", "workload=team-gv"); code != ExitOK {
		t.Fatalf("%d %s", code, e)
	}
	got, _ = r.fake.GetActorTemplate(context.Background(), ateapi.Ref("team", "pool"))
	if l := got.GetWorkerSelector().GetMatchLabels(); len(l) != 1 || l["workload"] != "team-gv" {
		t.Fatalf("selector = %v", l)
	}
}

func TestRevisionNameLength(t *testing.T) {
	if _, err := revisionName(strings.Repeat("a", 60), imageOf('a')); err == nil {
		t.Fatal("a name that cannot take a suffix was accepted")
	}
	if got, err := revisionName("kit", imageOf('d')); err != nil || got != "kit-dddddddd" {
		t.Fatalf("%q %v", got, err)
	}
}

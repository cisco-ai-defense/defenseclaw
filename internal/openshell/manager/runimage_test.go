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

//go:build !windows

package manager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// fakeRunImages makes run images and aliases in memory, content-addressed
// like image.Builder's, and records the files of each RunImage call.
type fakeRunImages struct {
	runMu  sync.Mutex
	made   map[string]image.RunImage
	builds int
	calls  [][]connector.SandboxFile
	runErr error
}

func (f *fakeRunImages) runTag(base image.Record, files []connector.SandboxFile, repo string) (string, string) {
	digest := image.RunConfigDigest(files)
	return image.RunRepository(repo) + ":" + base.Connector + "-" + digest[:12], digest
}

func (f *fakeRunImages) aliasTag(base image.Record, repo string) string {
	_, name, _ := strings.Cut(base.Tag, ":")
	return repo + ":" + name
}

func (f *fakeRunImages) RunImage(_ context.Context, base image.Record, files []connector.SandboxFile, repo string) (image.RunImage, error) {
	f.runMu.Lock()
	defer f.runMu.Unlock()
	f.calls = append(f.calls, slices.Clone(files))
	if f.runErr != nil {
		return image.RunImage{}, f.runErr
	}
	tag, digest := f.runTag(base, files, repo)
	if ri, ok := f.made[tag]; ok {
		return ri, nil
	}
	f.builds++
	ri := image.RunImage{Tag: tag, ImageID: "sha256:" + digest, Digest: digest, BaseTag: base.Tag, BaseImageID: base.ImageID,
		Connector: base.Connector, UID: base.UID, GID: base.GID}
	if f.made == nil {
		f.made = map[string]image.RunImage{}
	}
	f.made[tag] = ri
	return ri, nil
}

func (f *fakeRunImages) AliasImage(_ context.Context, base image.Record, repo string) (image.RunImage, error) {
	f.runMu.Lock()
	defer f.runMu.Unlock()
	ri := image.RunImage{Tag: f.aliasTag(base, repo), ImageID: base.ImageID, Alias: true, BaseTag: base.Tag, BaseImageID: base.ImageID,
		Connector: base.Connector, UID: base.UID, GID: base.GID}
	if f.made == nil {
		f.made = map[string]image.RunImage{}
	}
	f.made[ri.Tag] = ri
	return ri, nil
}

func (f *fakeRunImages) RecordedRunImage(_ context.Context, base image.Record, files []connector.SandboxFile, repo string) (image.RunImage, bool, error) {
	f.runMu.Lock()
	defer f.runMu.Unlock()
	tag := f.aliasTag(base, repo)
	if len(files) > 0 {
		tag, _ = f.runTag(base, files, repo)
	}
	ri, ok := f.made[tag]
	return ri, ok, nil
}

// runCalls are the files of each RunImage call.
func (f *fakeRunImages) runCalls() [][]connector.SandboxFile {
	f.runMu.Lock()
	defer f.runMu.Unlock()
	return slices.Clone(f.calls)
}

// readRecord is sandbox name's record as the manager saved it.
func readRecord(t *testing.T, e *harnessEnv, name string) record {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.dataDir, "sandboxes", "manager", name+".json"))
	must(t, err)
	var rec record
	must(t, json.Unmarshal(data, &rec))
	return rec
}

// runFileOf returns the file at path among files.
func runFileOf(t *testing.T, files []connector.SandboxFile, path string) connector.SandboxFile {
	t.Helper()
	for _, f := range files {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("no run file %s among %d", path, len(files))
	return connector.SandboxFile{}
}

// runFileVerifies are the checks of v that are for one of the run files.
func runFileVerifies(v *verifyRecord, files []connector.SandboxFile) []verifyFile {
	var out []verifyFile
	for _, c := range v.Files {
		if slices.ContainsFunc(files, func(f connector.SandboxFile) bool { return f.Path == c.Path }) {
			out = append(out, c)
		}
	}
	return out
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// On a MicroVM gateway Claude Code's run files are baked into a run image:
// nothing is written on the host, the template names the run image and no
// driver_config, the record keeps what the workload check must find (root
// 0644 files with their digests), and a second sandbox of the same posture
// boots the same image.
func TestCreateOnVMBakesRunFilesIntoARunImage(t *testing.T) {
	e := newVMEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "vm-claude", Copy: true, LLM: anthropicLLM, Credentials: stripeCred})
	if sb.Phase != "ready" || sb.WorkdirMode != config.OpenShellWorkdirCopy {
		t.Fatalf("sandbox = %+v", sb)
	}
	calls := e.images.runCalls()
	if len(calls) != 1 {
		t.Fatalf("RunImage calls = %d", len(calls))
	}
	files := calls[0]
	dropIn := decodeJSON(t, runFileOf(t, files, connector.ClaudeCodeSandboxRunDropInPath).Data)
	if dropIn["allowManagedMcpServersOnly"] != true {
		t.Fatalf("baked drop-in = %v", dropIn)
	}
	runFileOf(t, files, connector.ClaudeCodeSandboxManagedMCPPath)
	got, err := e.client.GetSandbox(t.Context(), "vm-claude")
	must(t, err)
	if got.Spec.Template == nil || got.Spec.Template.DriverConfig != nil ||
		!strings.HasPrefix(got.Spec.Template.Image, "defenseclaw.invalid/sandbox-run:claudecode-") {
		t.Fatalf("template = %+v", got.Spec.Template)
	}
	if _, err := os.Stat(e.m.runConfigDir("vm-claude")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("run files were written on the host: %v", err)
	}
	rec := readRecord(t, e, "vm-claude")
	digest := image.RunConfigDigest(files)
	if rec.RunImage != got.Spec.Template.Image || rec.RunImageID != "sha256:"+digest || rec.ImageID != e.images.rec.ImageID ||
		rec.RunConfig == nil || rec.RunConfig.Delivery != runDeliveryImage || rec.RunConfig.Digest != digest {
		t.Fatalf("record: run image %s (%s), run config %+v", rec.RunImage, rec.RunImageID, rec.RunConfig)
	}
	if rec.Verify == nil || rec.Verify.UID != 1000 || rec.Verify.GID != 1000 {
		t.Fatalf("verify = %+v", rec.Verify)
	}
	checked := runFileVerifies(rec.Verify, files)
	if len(checked) != len(files) || len(rec.Verify.Files) == len(files) {
		t.Fatalf("verify = %+v; want the hooks and each of the %d run files", rec.Verify, len(files))
	}
	for _, v := range checked {
		f := runFileOf(t, files, v.Path)
		if v.SHA256 != sha256Hex(f.Data) || v.UID != 0 || v.GID != 0 || v.Mode != 0o644 || v.ReadOnlyMount {
			t.Fatalf("verify file %+v", v)
		}
	}
	if sb.RunImage != rec.RunImage || sb.RunImageID != rec.RunImageID {
		t.Fatalf("view run image = %s (%s)", sb.RunImage, sb.RunImageID)
	}

	e.create(sandboxapi.CreateRequest{Name: "vm-claude2", Copy: true, LLM: anthropicLLM, Credentials: stripeCred, Project: e.otherProject("other")})
	if e.images.builds != 1 || readRecord(t, e, "vm-claude2").RunImage != rec.RunImage {
		t.Fatalf("a second sandbox of the posture built %d run images", e.images.builds)
	}
	// The project is still never mounted live.
	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "vm-mount", Project: e.otherProject("third")})
	if apiErr := wantCode(t, err, sandboxapi.CodeNeedsCopy); !strings.Contains(apiErr.Error(), "--copy") {
		t.Fatalf("mount refusal = %+v", apiErr)
	}
}

// On docker the run files stay read-only bind mounts of host files, the
// template names the overlay image, and the record keeps their digests on
// a read-only mount.
func TestCreateOnDockerMountsRunFiles(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "dk-claude", LLM: anthropicLLM})
	got, err := e.client.GetSandbox(t.Context(), "dk-claude")
	must(t, err)
	if got.Spec.Template.Image != e.images.rec.Tag || len(e.images.runCalls()) != 0 {
		t.Fatalf("docker template image = %s, run image calls %d", got.Spec.Template.Image, len(e.images.runCalls()))
	}
	files := e.runFiles("dk-claude")
	rec := readRecord(t, e, "dk-claude")
	if rec.RunImage != "" || rec.RunConfig.Delivery != runDeliveryMount || rec.Verify == nil {
		t.Fatalf("record: run image %q, run config %+v, verify %+v", rec.RunImage, rec.RunConfig, rec.Verify)
	}
	checked := 0
	for _, v := range rec.Verify.Files {
		if _, ok := files[v.Path]; !ok {
			continue
		}
		checked++
		if v.SHA256 != sha256Hex(files[v.Path]) || !v.ReadOnlyMount || v.UID != 1000 || v.Mode != 0o644 {
			t.Fatalf("verify file %+v", v)
		}
	}
	if checked != len(files) || len(rec.Verify.Files) == len(files) {
		t.Fatalf("verify = %+v; want the hooks and each of the %d run files", rec.Verify, len(files))
	}
}

// A driver that neither mounts host folders nor bakes run files into an
// image still refuses Claude Code before anything is made.
func TestCreateRefusesRunFilesADriverCannotTake(t *testing.T) {
	e := newEnv(t, nil)
	e.gw.Driver = openshell.Driver{}
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "none", Copy: true})
	if apiErr := wantCode(t, err, sandboxapi.CodeUnavailable); !strings.Contains(apiErr.Message, "Claude Code") {
		t.Fatalf("refusal = %+v", apiErr)
	}
	if n := e.fake.Calls(openshelltest.MethodCreateSandbox); n != 0 || len(e.images.runCalls()) != 0 {
		t.Fatalf("create calls %d, run images %d", n, len(e.images.runCalls()))
	}
	assertNothingLeft(t, e)
}

// AG-MAC-F2: a MicroVM gateway refuses, before anything is made, a harness
// whose image did not pass the hook-fire probe's MicroVM scenario: one the
// scenario found to resolve names on its own cannot start, with the
// probe's reason; one whose scenario settled nothing, or never ran, is
// not checked yet. Every refusal names the command that checks the image
// again. A docker gateway, whose sandboxes get Docker's /etc/hosts, runs
// the same image.
func TestCreateOnVMRefusesAnImageThatCannotStartInAMicroVM(t *testing.T) {
	const problem = `Antigravity cannot resolve localhost in an OpenShell MicroVM: it printed "Failed to start: listen tcp: lookup localhost on 127.0.0.53:53: server misbehaving"`
	const inconclusive = "with the name resolution of an OpenShell MicroVM (an empty /etc/hosts, and a DNS relay that does not answer localhost), OpenCode exited 1"
	const recheck = "`defenseclaw sandbox image build opencode --force`"
	const unchecked = "OpenCode's image is not checked for an OpenShell MicroVM (the vm driver this gateway runs)"
	for _, tc := range []struct{ name, problem, inconclusive, message, detail string }{
		{"cannot resolve localhost", problem, "", "OpenCode cannot start in an OpenShell MicroVM (the vm driver this gateway runs)",
			problem + ". A gateway on the docker driver (Linux), whose sandboxes get Docker's /etc/hosts, runs OpenCode; to check the image again: " + recheck},
		{"settled nothing", "", inconclusive, unchecked,
			"was run with a MicroVM's name resolution, which settled nothing: " + inconclusive + "; check it again: " + recheck + " (a run without --no-build checks it first, too)"},
		{"never probed", "", "", unchecked, "was not checked with a MicroVM's name resolution (OpenShell 0.1.1 gives a MicroVM an empty /etc/hosts); " +
			"check it: " + recheck},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newVMEnv(t, nil)
			res := connector.ResolveSandboxHookContract("opencode", "1.18.31")
			e.images.rec.HarnessVersion, e.images.rec.HookContract = "1.18.31", res.Contract.ContractID
			e.images.rec.MicroVMVerified, e.images.rec.MicroVMProblem, e.images.rec.MicroVMInconclusive = false, tc.problem, tc.inconclusive
			_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "vm-no", Harness: "opencode", Copy: true})
			apiErr := wantCode(t, err, sandboxapi.CodeImageUnavailable)
			if apiErr.Message != tc.message || !strings.Contains(apiErr.Detail, tc.detail) || !strings.Contains(apiErr.Detail, recheck) {
				t.Fatalf("refusal = %+v", apiErr)
			}
			if n := e.fake.Calls(openshelltest.MethodCreateSandbox); n != 0 || len(e.images.runCalls()) != 0 {
				t.Fatalf("create calls %d, run images %d", n, len(e.images.runCalls()))
			}
			assertNothingLeft(t, e)
		})
	}
	e := newEnv(t, nil)
	e.images.rec.MicroVMVerified, e.images.rec.MicroVMProblem = false, problem
	e.create(sandboxapi.CreateRequest{Name: "dk-ok", Copy: true})
}

// hookFireDocker answers the docker calls of an image's resolve: the tag
// names id, and every hook-fire probe run fails at once (and is counted).
type hookFireDocker struct {
	mu   sync.Mutex
	id   string
	runs int
}

// Getenv implements image.Docker: the fake runs in an empty environment,
// not the test's.
func (*hookFireDocker) Getenv(string) string { return "" }

func (d *hookFireDocker) Run(_ context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case len(args) > 1 && args[0] == "image" && args[1] == "inspect":
		_, _ = io.WriteString(stdout, d.id+"\n")
		return nil
	case args[0] == "run":
		d.runs++
	case args[0] == "rm":
		return nil
	}
	return &image.CommandError{Args: args, ExitCode: 1}
}

// The daemon checks an image for the MicroVM driver again, before a
// sandbox on that driver boots it, when its last MicroVM run settled
// nothing: one bad run does not block the harness for good. An image
// verified for a MicroVM, or found to resolve localhost on its own, is
// returned as it is, and so is any image when the create may not build
// (it is then refused with the command that checks it).
func TestResolveChecksAgainAnImageNotCheckedForAMicroVM(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*image.Record)
		build  bool
		probed bool
	}{
		{"verified for a MicroVM", func(r *image.Record) { r.MicroVMVerified = true }, true, false},
		{"cannot resolve localhost", func(r *image.Record) { r.MicroVMProblem = "OpenCode cannot resolve localhost in an OpenShell MicroVM" }, true, false},
		{"settled nothing", func(r *image.Record) { r.MicroVMInconclusive = "the run timed out" }, true, true},
		{"never checked", func(*image.Record) {}, true, true},
		{"settled nothing, no build", func(r *image.Record) { r.MicroVMInconclusive = "the run timed out" }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := image.NewStore(t.TempDir())
			docker := &hookFireDocker{id: "sha256:" + strings.Repeat("b", 64)}
			b := &image.Builder{Docker: docker, Store: store, TempDir: t.TempDir()}
			spec := image.BuildSpec{Harness: harness.ClaudeCode, UID: 1000, GID: 1000, IngressPort: 18971, DefenseClawVersion: "1.2.3", MicroVM: true}
			c, err := b.Context(spec)
			if err != nil {
				t.Fatal(err)
			}
			rec := image.Record{Tag: c.Tag, ImageID: docker.id, ContentHash: c.ContentHash, Connector: "claudecode", HarnessVersion: c.HarnessVersion,
				HookContract: c.Contract, BaseImage: c.Spec.BaseImage, UID: 1000, GID: 1000, IngressPort: 18971, DefenseClawVersion: "1.2.3",
				FailMode: c.Spec.FailMode, Owner: c.Spec.Owner, MicroVM: true, HookFireVerified: true}
			tc.edit(&rec)
			if err := store.Put(rec); err != nil {
				t.Fatal(err)
			}
			images := BuilderImages{Builder: b, Options: image.BuildOptions{HookFire: image.HookFireOptions{Network: image.HookFireNetworkRelay}}}
			got, err := images.Resolve(context.Background(), spec, tc.build)
			if probed := docker.runs > 0; probed != tc.probed {
				t.Fatalf("probed %t (%d runs), want %t: %+v, %v", probed, docker.runs, tc.probed, got, err)
			}
			// The probe here fails at once, which a real resolve reports.
			if !tc.probed && (err != nil || got.Tag != c.Tag) {
				t.Fatalf("Resolve = %+v, %v", got, err)
			}
		})
	}
}

// A sandbox boots the image built for its gateway's compute driver: a
// MicroVM gateway's answers localhost itself (image.BuildSpec.MicroVM), a
// docker gateway's is the image it always was.
func TestCreateResolvesTheImageForTheGatewayDriver(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     func(*testing.T) *harnessEnv
		microVM bool
	}{
		{"docker", func(t *testing.T) *harnessEnv { return newEnv(t, nil) }, false},
		{"vm", func(t *testing.T) *harnessEnv { return newVMEnv(t, nil) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.env(t)
			e.create(sandboxapi.CreateRequest{Name: "img-" + tc.name, Copy: true})
			e.images.mu.Lock()
			defer e.images.mu.Unlock()
			if len(e.images.resolved) == 0 {
				t.Fatal("no image resolved")
			}
			for _, spec := range e.images.resolved {
				if spec.MicroVM != tc.microVM {
					t.Fatalf("resolved %s image with MicroVM=%t, want %t", spec.Harness.Name, spec.MicroVM, tc.microVM)
				}
			}
		})
	}
}

// A hooks-only harness is sent its overlay image's alias under the
// driver's repository, which no registry serves.
func TestCreateOnVMSendsTheAlias(t *testing.T) {
	e := newVMEnv(t, nil)
	res := connector.ResolveSandboxHookContract("opencode", "1.18.31")
	e.images.rec.HarnessVersion, e.images.rec.HookContract = "1.18.31", res.Contract.ContractID
	e.create(sandboxapi.CreateRequest{Name: "vm-oc", Harness: "opencode", Copy: true})
	got, err := e.client.GetSandbox(t.Context(), "vm-oc")
	must(t, err)
	rec := readRecord(t, e, "vm-oc")
	if got.Spec.Template.Image != "defenseclaw.invalid/sandbox:test" || rec.RunImage != got.Spec.Template.Image ||
		rec.RunImageID != e.images.rec.ImageID || rec.RunConfig != nil || len(e.images.runCalls()) != 0 {
		t.Fatalf("template image %s, record run image %s (%s), run config %+v", got.Spec.Template.Image, rec.RunImage, rec.RunImageID, rec.RunConfig)
	}
}

// Codex's imported MCP servers get no per-repository cwd on a MicroVM
// gateway, so one run image serves every repository.
func TestCreateOnVMSharesCodexRunImagesAcrossRepositories(t *testing.T) {
	e := newVMEnv(t, nil)
	useCodex(e)
	e.m.opts.MCP = &fakeMCP{entries: []config.MCPServerEntry{{Name: "github", Command: "npx", Args: []string{"srv"}}}}
	e.create(sandboxapi.CreateRequest{Name: "cx-a", Harness: "codex", Copy: true})
	e.create(sandboxapi.CreateRequest{Name: "cx-b", Harness: "codex", Copy: true, Project: e.otherProject("second")})
	calls := e.images.runCalls()
	if len(calls) != 2 || e.images.builds != 1 {
		t.Fatalf("RunImage calls %d, builds %d", len(calls), e.images.builds)
	}
	managed := decodeTOML(t, runFileOf(t, calls[0], connector.CodexSandboxManagedConfigPath).Data)
	if gh, _ := managed["mcp_servers"].(map[string]any)["github"].(map[string]any); gh["command"] != "npx" || gh["cwd"] != nil {
		t.Fatalf("baked github server = %v", gh)
	}
}

// A credential passed with --env that the run files would carry is refused
// on a MicroVM gateway, before any image is made; a plain URL is not.
func TestCreateOnVMRefusesACredentialBakedIntoTheImage(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"token":          {"ANTHROPIC_AUTH_TOKEN": "sk-ant-not-real"},
		"headers":        {"ANTHROPIC_CUSTOM_HEADERS": "X-Api-Key: not-real"},
		"url with auth":  {"ANTHROPIC_BASE_URL": "https://user:pw@llm.example.com"},
		"url with a key": {"ANTHROPIC_BASE_URL": "https://gw.example.com/v1/?key=not-real"},
	} {
		e := newVMEnv(t, nil)
		_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "vm-secret", Copy: true, Env: env})
		apiErr := wantCode(t, err, sandboxapi.CodeInvalid)
		if !strings.Contains(apiErr.Detail, "--credential") || !strings.Contains(apiErr.Message, "baked into the image") {
			t.Fatalf("%s: refusal = %+v", name, apiErr)
		}
		if len(e.images.runCalls()) != 0 {
			t.Fatalf("%s: a run image was made", name)
		}
		assertNothingLeft(t, e)
	}
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "vm-url", Copy: true, Env: map[string]string{"ANTHROPIC_BASE_URL": "http://host.openshell.internal:28921"}})
	// On docker the value stays in the owner-only run-config directory.
	d := newEnv(t, nil)
	d.create(sandboxapi.CreateRequest{Name: "dk-token", Env: map[string]string{"ANTHROPIC_AUTH_TOKEN": "sk-ant-not-real"}})
}

// An imported MCP server whose command line or URL looks like it carries
// a credential stays behind on a MicroVM gateway, where it would be baked
// into the run image, which outlives the sandbox; the others come along.
// On docker the files go with the sandbox, and every server comes along.
func TestCreateOnVMLeavesMCPCredentialsBehind(t *testing.T) {
	entries := []config.MCPServerEntry{
		{Name: "github", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github"}},
		{Name: "keyed", Command: "npx", Args: []string{"mcp-server", "--api-key", "not-real"}},
		{Name: "remote", Command: "npx", Args: []string{"mcp-remote", "https://mcp.example.com/sse", "--header", "Authorization: Bearer not-real"}},
		{Name: "query", URL: "https://mcp.example.com/sse?token=not-real", Transport: "sse"},
		{Name: "linear", URL: "https://mcp.linear.app/mcp"},
		// A URL in the arguments is judged like the server's URL.
		{Name: "arg-query", Command: "npx", Args: []string{"mcp-remote", "https://mcp.example.com/sse?apiKey=not-real"}},
		{Name: "arg-userinfo", Command: "npx", Args: []string{"mcp-remote", "https://user:not-real@mcp.example.com/sse"}},
		{Name: "arg-fragment", Command: "npx", Args: []string{"mcp-remote", "https://mcp.example.com/sse#not-real"}},
		{Name: "arg-flag-url", Command: "srv", Args: []string{"--server=https://mcp.example.com/sse?s=not-real"}},
		{Name: "arg-plain", Command: "npx", Args: []string{"mcp-remote", "https://mcp.example.com/mcp"}},
	}
	e := newVMEnv(t, nil)
	e.m.opts.MCP = &fakeMCP{entries: entries}
	sb := e.create(sandboxapi.CreateRequest{Name: "vm-mcp", Copy: true})
	if imported := slices.Sorted(slices.Values(sb.MCP.Imported)); !slices.Equal(imported, []string{"arg-plain", "github", "linear"}) {
		t.Fatalf("imported = %v", sb.MCP.Imported)
	}
	var behind []string
	for _, l := range sb.MCP.LeftBehind {
		if strings.Contains(l.Reason, "look like they carry a credential") && strings.Contains(l.Reason, "--credential") {
			behind = append(behind, l.Name)
		}
	}
	if slices.Sort(behind); !slices.Equal(behind, []string{"arg-flag-url", "arg-fragment", "arg-query", "arg-userinfo", "keyed", "query", "remote"}) {
		t.Fatalf("left behind = %+v", sb.MCP.LeftBehind)
	}
	for _, f := range e.images.runCalls()[0] {
		if strings.Contains(string(f.Data), "not-real") {
			t.Fatalf("%s carries a credential:\n%s", f.Path, f.Data)
		}
	}

	d := newEnv(t, nil)
	d.m.opts.MCP = &fakeMCP{entries: entries}
	if sb := d.create(sandboxapi.CreateRequest{Name: "dk-mcp"}); len(sb.MCP.Imported) != len(entries) {
		t.Fatalf("docker imported = %v, left behind %+v", sb.MCP.Imported, sb.MCP.LeftBehind)
	}
}

// What looks like a credential in an MCP server's command line or URL.
func TestMCPCredential(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    connector.SandboxMCPServer
		want bool
	}{
		{"a package", connector.SandboxMCPServer{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github"}}, false},
		{"a flag with a path", connector.SandboxMCPServer{Command: "uvx", Args: []string{"mcp-server-git", "--repository", "/sandbox/work/app"}}, false},
		{"a plain URL", connector.SandboxMCPServer{URL: "https://mcp.linear.app/mcp"}, false},
		{"an empty query value", connector.SandboxMCPServer{URL: "https://mcp.example.com/mcp?debug"}, false},
		{"--token VALUE", connector.SandboxMCPServer{Command: "srv", Args: []string{"--token", "abc"}}, true},
		{"--auth-token=VALUE", connector.SandboxMCPServer{Command: "srv", Args: []string{"--auth-token=abc"}}, true},
		{"a flag without a value", connector.SandboxMCPServer{Command: "srv", Args: []string{"--api-key", "--verbose"}}, false},
		{"NAME=VALUE", connector.SandboxMCPServer{Command: "env", Args: []string{"GITHUB_TOKEN=abc", "srv"}}, true},
		{"a key header", connector.SandboxMCPServer{Command: "npx", Args: []string{"mcp-remote", "--header", "X-API-Key: abc"}}, true},
		{"a bearer header", connector.SandboxMCPServer{Command: "npx", Args: []string{"mcp-remote", "--header", "Authorization:Bearer abc"}}, true},
		{"a GitHub token", connector.SandboxMCPServer{Command: "srv", Args: []string{"ghp_0123456789abcdefghij"}}, true},
		{"a query value", connector.SandboxMCPServer{URL: "https://mcp.example.com/sse?key=abc"}, true},
		{"a fragment", connector.SandboxMCPServer{URL: "https://mcp.example.com/sse#abc"}, true},
		{"a URL argument", connector.SandboxMCPServer{Command: "npx", Args: []string{"mcp-remote", "https://mcp.example.com/sse"}}, false},
		{"a URL argument with an empty query value", connector.SandboxMCPServer{Command: "npx", Args: []string{"mcp-remote", "https://mcp.example.com/sse?debug"}}, false},
		{"a URL argument with a query value", connector.SandboxMCPServer{Command: "npx", Args: []string{"mcp-remote", "https://mcp.example.com/sse?t=abc"}}, true},
		{"a URL argument with a user", connector.SandboxMCPServer{Command: "npx", Args: []string{"mcp-remote", "https://u:abc@mcp.example.com/sse"}}, true},
		{"a URL argument with a fragment", connector.SandboxMCPServer{Command: "npx", Args: []string{"mcp-remote", "https://mcp.example.com/sse#abc"}}, true},
		{"--flag=URL", connector.SandboxMCPServer{Command: "srv", Args: []string{"--url=https://mcp.example.com/sse?t=abc"}}, true},
		{"NAME=URL", connector.SandboxMCPServer{Command: "env", Args: []string{"SERVER_URL=https://u:abc@mcp.example.com/sse", "srv"}}, true},
		{"a path with a query", connector.SandboxMCPServer{Command: "srv", Args: []string{"/sandbox/work/app?x=1"}}, false},
		{"a git URL argument with a user", connector.SandboxMCPServer{Command: "uvx", Args: []string{"--from", "git+ssh://git@github.com/org/mcp-srv.git", "mcp-srv"}}, false},
		{"a database URL argument with a user", connector.SandboxMCPServer{Command: "npx", Args: []string{"@modelcontextprotocol/server-postgres", "postgresql://postgres@db.example.com/app"}}, false},
		{"a URL argument with a token for its user", connector.SandboxMCPServer{Command: "srv", Args: []string{"https://ghp_0123456789abcdefghij@github.com/org/repo.git"}}, true},
		{"a URL argument with a long user", connector.SandboxMCPServer{Command: "srv", Args: []string{"https://" + strings.Repeat("a1", 16) + "@mcp.example.com/sse"}}, true},
		{"a URL argument with an empty password", connector.SandboxMCPServer{Command: "srv", Args: []string{"https://u:@mcp.example.com/sse"}}, true},
		{"a server URL with a user", connector.SandboxMCPServer{URL: "https://u@mcp.example.com/sse"}, true},
	} {
		if got := mcpCredential(tc.s); got != tc.want {
			t.Errorf("%s: mcpCredential(%+v) = %t, want %t", tc.name, tc.s, got, tc.want)
		}
	}
}

// A start renders a MicroVM sandbox's run files again and compares them
// with the baked ones: equal starts, stricter is refused (they cannot
// change), looser keeps them and never rebuilds.
func TestStartOnVMComparesTheBakedRunConfig(t *testing.T) {
	e := newVMEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "vm-same", Copy: true})
	e.stopBox("vm-same")
	e.startBox("vm-same", sandboxapi.StartRequest{})
	if len(e.images.runCalls()) != 1 {
		t.Fatalf("a start made a run image: %d calls", len(e.images.runCalls()))
	}

	// Looser: an MCP server the inventory lists now is not brought along.
	before := readRecord(t, e, "vm-same")
	e.m.opts.MCP = &fakeMCP{entries: []config.MCPServerEntry{{Name: "github", Command: "npx"}}}
	e.stopBox("vm-same")
	e.startBox("vm-same", sandboxapi.StartRequest{})
	after := readRecord(t, e, "vm-same")
	if after.RunConfig.Digest != before.RunConfig.Digest || len(after.MCP.Imported) != 0 || after.RunConfig.Safe != before.RunConfig.Safe ||
		after.RunImage != before.RunImage || len(e.images.runCalls()) != 1 {
		t.Fatalf("a looser start changed the baked run config: %+v / %+v", before.RunConfig, after.RunConfig)
	}

	// Stricter: skip-permissions is no longer allowed.
	e.create(sandboxapi.CreateRequest{Name: "vm-yolo", Copy: true, Yolo: true, Project: e.otherProject("yolo")})
	e.stopBox("vm-yolo")
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowYolo = boolPtr(false) })
	_, err := e.m.Start(t.Context(), "vm-yolo", sandboxapi.StartRequest{})
	// A copy's work is reached only by a start (pull starts it): the
	// refusal does not send the user to delete before it is pulled.
	if apiErr := wantCode(t, err, sandboxapi.CodePolicyViolation); !strings.Contains(apiErr.Message, "baked into its image") ||
		!strings.Contains(apiErr.Message, "deleting it discards what was never pulled") || strings.Contains(apiErr.Message, "delete it and run it again") ||
		!strings.Contains(apiErr.Detail, "start it under the settings it was made with") || !strings.Contains(apiErr.Detail, "`defenseclaw sandbox pull vm-yolo`, then") {
		t.Fatalf("stricter start = %+v", apiErr)
	}
}

// On docker a start that rewrites the run files records their new digests,
// so the session's workload check compares with what was just written.
func TestStartOnDockerRecordsTheRewrittenDigests(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "dk-yolo", Yolo: true})
	before := readRecord(t, e, "dk-yolo")
	e.stopBox("dk-yolo")
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowYolo = boolPtr(false) })
	e.startBox("dk-yolo", sandboxapi.StartRequest{})
	files := e.runFiles("dk-yolo")
	e.m.mu.Lock()
	after := e.m.boxes["dk-yolo"].rec
	e.m.mu.Unlock()
	if after.RunConfig.Digest == before.RunConfig.Digest || after.Verify == nil {
		t.Fatalf("digest %s -> %s, verify %+v", before.RunConfig.Digest, after.RunConfig.Digest, after.Verify)
	}
	runChecks := 0
	for _, v := range after.Verify.Files {
		if _, ok := files[v.Path]; !ok {
			continue
		}
		runChecks++
		if v.SHA256 != sha256Hex(files[v.Path]) {
			t.Fatalf("verify %s = %s, file holds %s", v.Path, v.SHA256, sha256Hex(files[v.Path]))
		}
	}
	if runChecks != len(files) {
		t.Fatalf("verify = %+v; want each of the %d run files", after.Verify, len(files))
	}
	if calls := e.workloadCheckCalls("dk-yolo"); len(calls) != 2 {
		t.Fatalf("workload checks = %d", len(calls))
	}
}

// A create on the vm driver whose image has no prepared disk yet is refused
// when the volume of the driver's image cache lacks the room to prepare
// one; one whose disk is prepared, and any on docker, is not (OC-F1).
func TestCreateRefusesAFirstBootWithoutDiskRoom(t *testing.T) {
	cache := t.TempDir()
	free := uint64(2 << 30)
	disk := func(e *harnessEnv) {
		e.m.opts.VMDiskFree = func() (string, uint64, error) { return cache, free, nil }
	}
	e := newVMEnv(t, nil)
	disk(e)
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "vm-full", Copy: true})
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || !strings.Contains(err.Error(), "not enough free disk space for this sandbox's first start: "+
		"the MicroVM driver prepares a disk of about 5.0 GiB from its image in "+cache+", where 2.0 GiB is free and at least 6.0 GiB is needed") {
		t.Fatalf("create on a full disk = %v", err)
	}
	if _, err := e.m.Get(t.Context(), "vm-full"); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("the refused create left a sandbox: %v", err)
	}

	free = 40 << 30
	sb := e.create(sandboxapi.CreateRequest{Name: "vm-room", Copy: true})
	// Its run image is prepared now: the same posture needs no room.
	name := "sandbox-prepared-rootfs-ext4-umoci-v3-openshell-0.1.1-configured-1000-1000-sha256-" + strings.TrimPrefix(sb.RunImageID, "sha256:")
	must(t, os.MkdirAll(filepath.Join(cache, name), 0o755))
	free = 1 << 30
	// Explain looks in the same cache (the gateway's state_dir).
	if ex, err := e.m.Explain(t.Context(), sandboxapi.ExplainRequest{Harness: "claudecode", Copy: true, Project: e.project}); err != nil || ex.VMFirstBoot {
		t.Fatalf("Explain of a prepared posture = %+v, %v", ex, err)
	}
	e.create(sandboxapi.CreateRequest{Name: "vm-cached", Copy: true, Project: e.otherProject("other")})
	// After an in-place upgrade the gateway prepares its own disk: the one
	// OpenShell 0.1.1 prepared counts for neither.
	e.fake.SetRelease(openshell.InstallerVersion)
	e.gw.Version = openshell.InstallerVersion
	if ex, err := e.m.Explain(t.Context(), sandboxapi.ExplainRequest{Harness: "claudecode", Copy: true, Project: e.project}); err != nil || !ex.VMFirstBoot {
		t.Fatalf("Explain on the upgraded gateway = %+v, %v", ex, err)
	}
	if _, err := e.tryCreate(sandboxapi.CreateRequest{Name: "vm-upgraded", Copy: true, Project: e.otherProject("upgraded")}); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		t.Fatalf("create on the upgraded gateway's full disk = %v", err)
	}

	d := newEnv(t, nil)
	disk(d)
	d.create(sandboxapi.CreateRequest{Name: "dk-full"})
}

// The pre-create Explain says whether the image a new sandbox would boot
// has a prepared MicroVM disk yet: never on docker; on vm by the alias's
// (the overlay image's) ID for a hooks-only harness, and by the run image
// of the posture for one with run files.
func TestExplainReportsAVMFirstBoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	vm, _ := openshell.LookupDriver("vm")
	cache := filepath.Join(home, vm.ImageCache)
	prepare := func(id string) {
		t.Helper()
		name := "sandbox-prepared-rootfs-ext4-umoci-v3-openshell-0.1.1-configured-1000-1000-sha256-" + strings.TrimPrefix(id, "sha256:")
		must(t, os.MkdirAll(filepath.Join(cache, name), 0o755))
	}
	explain := func(e *harnessEnv, req sandboxapi.ExplainRequest) bool {
		t.Helper()
		req.Project = orDefault(req.Project, e.project)
		ex, err := e.m.Explain(t.Context(), req)
		must(t, err)
		return ex.VMFirstBoot
	}

	d := newEnv(t, nil)
	if _, err := d.m.gateway(t.Context()); err != nil {
		t.Fatal(err)
	}
	if explain(d, sandboxapi.ExplainRequest{Harness: "claudecode", Copy: true}) {
		t.Fatal("a docker gateway reported a MicroVM first boot")
	}

	e := newVMEnv(t, nil)
	if _, err := e.m.gateway(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !explain(e, sandboxapi.ExplainRequest{Harness: "claudecode", Copy: true}) {
		t.Fatal("no run image yet, but no first boot")
	}
	sb := e.create(sandboxapi.CreateRequest{Name: "vm-first", Copy: true})
	if !explain(e, sandboxapi.ExplainRequest{Harness: "claudecode", Copy: true}) {
		t.Fatal("the run image has no prepared disk yet, but no first boot")
	}
	prepare(sb.RunImageID)
	if explain(e, sandboxapi.ExplainRequest{Harness: "claudecode", Copy: true}) {
		t.Fatal("the posture's run image is prepared, but a first boot")
	}
	if !explain(e, sandboxapi.ExplainRequest{Harness: "claudecode", Copy: true, Safe: true}) {
		t.Fatal("another posture (safe mode) reported no first boot")
	}
	// FIN-A-2: the run's own --env and credentials, when the client sends
	// them, decide its run image, not the newest sandbox's: another model
	// endpoint, a credential the files then leave out, or a value the
	// client withheld is another run image, so a first boot.
	const endpoint = "http://host.openshell.internal:39942"
	withRun := func(run sandboxapi.ExplainRun) sandboxapi.ExplainRequest {
		return sandboxapi.ExplainRequest{Harness: "claudecode", Copy: true, Run: &run}
	}
	if explain(e, withRun(sandboxapi.ExplainRun{})) {
		t.Fatal("a run with the prepared sandbox's inputs (none) reported a first boot")
	}
	for name, run := range map[string]sandboxapi.ExplainRun{
		"another --env":        {Env: map[string]string{"ANTHROPIC_BASE_URL": endpoint}},
		"a --credential":       {Credentials: []string{"ANTHROPIC_AUTH_TOKEN"}},
		"a withheld --env":     {EnvWithheld: []string{"ANTHROPIC_AUTH_TOKEN"}},
		"an unknown --llm":     {LLMProfile: "defenseclaw-nonesuch"},
		"another model --env":  {Env: map[string]string{"ANTHROPIC_MODEL": "claude-sonnet-4-5"}},
		"a provider selection": {Env: map[string]string{"CLAUDE_CODE_USE_BEDROCK": "1"}},
	} {
		if !explain(e, withRun(run)) {
			t.Fatalf("%s reported no first boot", name)
		}
	}
	env := e.create(sandboxapi.CreateRequest{Name: "vm-env", Copy: true, Project: e.otherProject("env"), Env: map[string]string{"ANTHROPIC_BASE_URL": endpoint}})
	prepare(env.RunImageID)
	if explain(e, withRun(sandboxapi.ExplainRun{Env: map[string]string{"ANTHROPIC_BASE_URL": endpoint, "UNRELATED": "x"}})) {
		t.Fatal("the --env of a prepared sandbox reported a first boot")
	}
	if explain(e, withRun(sandboxapi.ExplainRun{})) {
		t.Fatal("once another sandbox is newer, the first one's inputs reported a first boot")
	}
	// An existing sandbox's Explain describes no create.
	if explain(e, sandboxapi.ExplainRequest{Sandbox: "vm-first"}) {
		t.Fatal("an existing sandbox's Explain reported a first boot")
	}

	o := newVMEnv(t, nil)
	res := connector.ResolveSandboxHookContract("opencode", "1.18.31")
	o.images.rec.HarnessVersion, o.images.rec.HookContract = "1.18.31", res.Contract.ContractID
	if _, err := o.m.gateway(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !explain(o, sandboxapi.ExplainRequest{Harness: "opencode", Copy: true}) {
		t.Fatal("hooks-only: no prepared disk, but no first boot")
	}
	prepare(o.images.rec.ImageID)
	if explain(o, sandboxapi.ExplainRequest{Harness: "opencode", Copy: true}) {
		t.Fatal("hooks-only: the overlay image is prepared, but a first boot")
	}
	// An image to build first is a first boot too.
	o.images.err = ErrImageMissing
	if !explain(o, sandboxapi.ExplainRequest{Harness: "opencode", Copy: true}) {
		t.Fatal("no image built yet, but no first boot")
	}
}

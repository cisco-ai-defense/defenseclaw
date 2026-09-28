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

package sandboxcli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

const testToken = "test-master-token"

// call is one request the fake daemon served.
type call struct {
	Method string
	Path   string
	Query  string
	Body   json.RawMessage
}

// fakeDaemon serves the sandbox REST API from memory.
type fakeDaemon struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	calls     []call
	status    sandboxapi.Status
	sandboxes map[string]*sandboxapi.Sandbox
	approvals []sandboxapi.Approval
	events    []sandboxapi.ActivityEvent
	explain   sandboxapi.Explain
	review    sandboxapi.ReviewResponse
	undo      sandboxapi.UndoResponse
	// errors maps "METHOD path" to the error the fake answers with.
	errors map[string]*sandboxapi.Error
	// onGet runs before a sandbox is returned (hook counters move during
	// a session).
	onGet func(sb *sandboxapi.Sandbox)
	// createMCP and createWarnings are what create reports.
	createMCP        *sandboxapi.MCPSummary
	createWarnings   []string
	createViolations []sandboxapi.Violation
	// live are events only a followed activity stream delivers (they
	// happen during the session).
	live []sandboxapi.ActivityEvent
	// timeline records the order of the steps of a run, shared with the
	// other fakes of a testApp.
	timeline *timeline
	// refuseCreate, when set, may refuse a create request.
	refuseCreate func(req sandboxapi.CreateRequest) *sandboxapi.Error
	// pendingChanges says the folder holds changes on top of the snapshot
	// that were neither undone nor accepted: like the manager, a start
	// then keeps the snapshot unless it asks for a new one.
	pendingChanges bool
}

// timeline is the ordered record of what the fakes did.
type timeline struct {
	mu    sync.Mutex
	steps []string
}

func (tl *timeline) add(step string) {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	tl.steps = append(tl.steps, step)
	tl.mu.Unlock()
}

func (tl *timeline) list() []string {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return append([]string(nil), tl.steps...)
}

// hookTraffic is the hook traffic of a harness the fakes ran: an
// authenticated hook request for the sandbox the argv names.
func (d *fakeDaemon) hookTraffic(argv []string) {
	name := ""
	for i, a := range argv {
		if a == "--name" && i+1 < len(argv) {
			name = argv[i+1]
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if sb, ok := d.sandboxes[name]; ok {
		sb.Hooks.HookRequests++
		sb.Hooks.LastHookAt = time.Now()
	}
}

// runsHarness reports whether argv starts a harness through its launcher.
func runsHarness(argv []string) bool {
	return slices.ContainsFunc(argv, func(a string) bool { return strings.HasPrefix(a, harness.LauncherDir+"/") })
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	d := &fakeDaemon{t: t, sandboxes: map[string]*sandboxapi.Sandbox{}, errors: map[string]*sandboxapi.Error{}}
	d.status = sandboxapi.Status{Enabled: true, Available: true, IngressAddr: "127.0.0.1:18971", EgressAddr: "127.0.0.1:18972",
		Gateway: &sandboxapi.Gateway{Name: "openshell", Endpoint: "https://127.0.0.1:17670", Workspace: "default", Version: "0.1.1", Healthy: true},
		Pack:    "open", Profile: "open"}
	d.explain = sandboxapi.Explain{Pack: "open", PackSource: "builtin:open", PackDigest: "sha256:" + strings.Repeat("a", 64),
		Profile: "open", NetworkMode: "open", Approvals: "auto",
		Settings: []sandboxapi.Setting{{Key: "workdir.mode", Value: "mount", Source: "pack", Origin: "pack open"}, {Key: "yolo", Value: "true", Source: "pack", Origin: "pack open"}}}
	d.review = sandboxapi.ReviewResponse{Summary: "2 files changed (+10 −3)", Report: &workspace.ReviewReport{FilesChanged: 2, Insertions: 10, Deletions: 3}}
	d.srv = httptest.NewServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *fakeDaemon) client() *sandboxapi.Client { return sandboxapi.NewClient(d.srv.URL, testToken) }

func (d *fakeDaemon) add(sb sandboxapi.Sandbox) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sandboxes[sb.Name] = &sb
}

func (d *fakeDaemon) callsTo(method, path string) []call {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []call
	for _, c := range d.calls {
		if c.Method == method && c.Path == path {
			out = append(out, c)
		}
	}
	return out
}

func (d *fakeDaemon) paths() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, c := range d.calls {
		out = append(out, c.Method+" "+c.Path)
	}
	return out
}

func (d *fakeDaemon) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get(sandboxapi.ClientHeader) != sandboxapi.ClientName {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	d.mu.Lock()
	d.calls = append(d.calls, call{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: body})
	if e, ok := d.errors[r.Method+" "+r.URL.Path]; ok {
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.HTTPStatus())
		_ = json.NewEncoder(w).Encode(e)
		return
	}
	d.mu.Unlock()
	reply := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	fail := func(code, msg string) {
		e := sandboxapi.Errorf(code, "%s", msg)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.HTTPStatus())
		_ = json.NewEncoder(w).Encode(e)
	}
	path := r.URL.Path
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case path == sandboxapi.PathStatus:
		reply(d.status)
	case path == sandboxapi.PathPolicyExplain:
		reply(d.explain)
	case path == sandboxapi.PathApprovals && r.Method == http.MethodGet:
		var out []sandboxapi.Approval
		for _, a := range d.approvals {
			if s := r.URL.Query().Get("sandbox"); s == "" || a.Sandbox == s {
				out = append(out, a)
			}
		}
		reply(map[string]any{"approvals": out})
	case strings.HasPrefix(path, sandboxapi.PathApprovals+"/"):
		id := strings.TrimPrefix(path, sandboxapi.PathApprovals+"/")
		var dec sandboxapi.ApprovalDecision
		_ = json.Unmarshal(body, &dec)
		for _, a := range d.approvals {
			if a.ID == id {
				a.Status = sandboxapi.ApprovalQueued
				reply(sandboxapi.ApprovalResult{Approval: a, Persisted: dec.Always})
				return
			}
		}
		fail(sandboxapi.CodeNotFound, "no such approval")
	case path == sandboxapi.PathEgressUnblock:
		var req sandboxapi.UnblockRequest
		_ = json.Unmarshal(body, &req)
		scope := "sandbox"
		if req.Always {
			scope = "always"
		}
		reply(sandboxapi.UnblockResponse{Host: req.Host, Sandbox: req.Sandbox, Scope: scope})
	case path == sandboxapi.PathActivity:
		var out []sandboxapi.ActivityEvent
		events := d.events
		if r.URL.Query().Get("follow") == "true" {
			events = append(append([]sandboxapi.ActivityEvent(nil), events...), d.live...)
		}
		for _, ev := range events {
			if s := r.URL.Query().Get("sandbox"); s == "" || ev.Sandbox == s {
				out = append(out, ev)
			}
		}
		if r.URL.Query().Get("follow") == "true" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			for _, ev := range out {
				_ = sandboxapi.WriteEvent(w, ev)
			}
			return
		}
		if out == nil {
			out = []sandboxapi.ActivityEvent{}
		}
		reply(map[string]any{"events": out})
	case path == sandboxapi.PathSandboxes && r.Method == http.MethodGet:
		list := []sandboxapi.Sandbox{}
		for _, sb := range d.sandboxes {
			list = append(list, *sb)
		}
		reply(map[string]any{"sandboxes": list})
	case path == sandboxapi.PathSandboxes && r.Method == http.MethodPost:
		var req sandboxapi.CreateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			fail(sandboxapi.CodeInvalid, err.Error())
			return
		}
		if d.refuseCreate != nil {
			if e := d.refuseCreate(req); e != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(e.HTTPStatus())
				_ = json.NewEncoder(w).Encode(e)
				return
			}
		}
		name := req.Name
		if name == "" {
			name = "dc-claude-proj-1a2b"
		}
		if _, taken := d.sandboxes[name]; taken {
			fail(sandboxapi.CodeConflict, "a sandbox named "+name+" already exists")
			return
		}
		mode, workdir := "mount", "/work/"+filepath.Base(req.Project)
		if req.Copy {
			mode, workdir = "copy", "/sandbox/work/"+filepath.Base(req.Project)
		}
		sb := &sandboxapi.Sandbox{Name: name, ID: "sb-" + name, Harness: req.Harness, HarnessName: harnessName(req.Harness),
			Phase: "ready", Profile: "open", NetworkMode: "open", Yolo: !req.Safe, WorkdirMode: mode, Project: req.Project,
			Workdir: workdir, Launch: sandboxapi.Launch{Yolo: !req.Safe}, TamperTier: "managed", CreatedAt: time.Now()}
		if req.LLM != nil {
			sb.Launch.CredentialProfile = req.LLM.Profile
		}
		if mode == "mount" {
			sb.Workspace = &sandboxapi.WorkspaceSummary{Project: "~/proj → " + workdir + " (live)", Hidden: []string{".env"}, Protected: []string{".git/hooks", ".git/config"}}
			sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git"}
		}
		if d.createMCP != nil {
			sb.MCP = d.createMCP
		}
		sb.Warnings = append(sb.Warnings, d.createWarnings...)
		sb.Violations = append(sb.Violations, d.createViolations...)
		d.sandboxes[name] = sb
		d.timeline.add("create " + name)
		reply(sb)
	case strings.HasPrefix(path, sandboxapi.PathSandboxes+"/"):
		rest := strings.TrimPrefix(path, sandboxapi.PathSandboxes+"/")
		name, verb, _ := strings.Cut(rest, "/")
		sb, ok := d.sandboxes[name]
		if !ok {
			fail(sandboxapi.CodeNotFound, "no sandbox "+name)
			return
		}
		switch {
		case r.Method == http.MethodGet:
			if d.onGet != nil {
				d.onGet(sb)
			}
			reply(sb)
		case r.Method == http.MethodDelete:
			delete(d.sandboxes, name)
			reply(sandboxapi.DeleteResponse{Name: name, Deleted: true})
		case verb == "stop":
			sb.Phase = "stopped"
			reply(sb)
		case verb == "start":
			var req sandboxapi.StartRequest
			_ = json.Unmarshal(body, &req)
			sb.Phase = "ready"
			fresh := req.NewSnapshot || !d.pendingChanges || !sb.Snapshot.UndoneAt.IsZero()
			if sb.WorkdirMode == "mount" && sb.Snapshot != nil && !req.NoSnapshot && fresh {
				// A new session's snapshot replaces the undo point.
				sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: sb.Snapshot.Kind, CreatedAt: time.Now()}
			}
			reply(sb)
		case verb == "review":
			rev := d.review
			var req sandboxapi.ReviewRequest
			_ = json.Unmarshal(body, &req)
			if req.Diff {
				rev.Diff = "diff --git a/x b/x\n+changed\n"
			}
			reply(rev)
		case verb == "undo":
			var req sandboxapi.UndoRequest
			_ = json.Unmarshal(body, &req)
			u := d.undo
			if u.Result == nil {
				u.Result = &workspace.UndoResult{Project: sb.Project, Changes: []workspace.TreeChange{{Path: "README.md", Status: "M"}}}
			}
			if req.Stop && !req.Preview {
				sb.Phase = "stopped"
				u.Stopped = true
				u.Summary = "1 file restored"
			}
			reply(u)
		case verb == "workspace":
			reply(map[string]string{"status": "recorded"})
		default:
			fail(sandboxapi.CodeNotFound, "unknown verb")
		}
	default:
		fail(sandboxapi.CodeNotFound, "no route "+path)
	}
}

func harnessName(h string) string {
	if spec, ok := harness.Get(h); ok {
		return spec.DisplayName
	}
	return h
}

// fakeTerminal records interactive invocations.
type fakeTerminal struct {
	mu   sync.Mutex
	runs [][]string
	code int
	// startErr fails the start of the harness (nothing runs).
	startErr error
	// during runs while the harness "owns" the terminal; hooks then stands
	// for the harness's hook traffic (nil: its hooks never reach the
	// daemon).
	during   func()
	hooks    func(argv []string)
	timeline *timeline
}

func (f *fakeTerminal) Run(_ context.Context, inv openshell.Invocation) (int, error) {
	f.mu.Lock()
	f.runs = append(f.runs, inv.Argv)
	during, startErr, hooks := f.during, f.startErr, f.hooks
	f.mu.Unlock()
	if !inv.Interactive {
		return -1, io.ErrUnexpectedEOF
	}
	if startErr != nil {
		return -1, startErr
	}
	f.timeline.add("attach")
	if during != nil {
		during()
	}
	if hooks != nil {
		hooks(inv.Argv)
	}
	return f.code, nil
}

// fakeStreamer records non-interactive invocations and answers them.
type fakeStreamer struct {
	mu   sync.Mutex
	runs [][]string
	// answer returns the exit status and output for an argv.
	answer func(argv []string) (int, string)
	// hooks stands for the hook traffic of a harness it runs (nil: none
	// reaches the daemon).
	hooks    func(argv []string)
	timeline *timeline
}

func (f *fakeStreamer) Stream(_ context.Context, inv openshell.Invocation, stdout, _ io.Writer) (int, error) {
	f.mu.Lock()
	f.runs = append(f.runs, inv.Argv)
	answer, hooks := f.answer, f.hooks
	f.mu.Unlock()
	if inv.Interactive {
		return -1, io.ErrUnexpectedEOF
	}
	f.timeline.add(execStep(inv.Argv))
	if hooks != nil && runsHarness(inv.Argv) {
		hooks(inv.Argv)
	}
	if answer == nil {
		return 0, nil
	}
	code, out := answer(inv.Argv)
	_, _ = io.WriteString(stdout, out)
	return code, nil
}

func (f *fakeStreamer) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, argv := range f.runs {
		out = append(out, strings.Join(sandboxCommand(argv), " "))
	}
	return out
}

// execStep is an exec's timeline entry: "exec <command> in <workdir>",
// the workdir "-" when the exec names none.
func execStep(argv []string) string {
	workdir := "-"
	for i, a := range argv {
		if a == "--" {
			break
		}
		if a == "--workdir" && i+1 < len(argv) {
			workdir = argv[i+1]
		}
	}
	cmd := sandboxCommand(argv)
	head := ""
	if len(cmd) > 0 {
		head = cmd[0]
	}
	return "exec " + head + " in " + workdir
}

// sandboxCommand strips `openshell sandbox exec … --` from an argv.
func sandboxCommand(argv []string) []string {
	for i, a := range argv {
		if a == "--" {
			return argv[i+1:]
		}
	}
	return argv
}

// fakeImages is an in-memory ImageService.
type fakeImages struct {
	mu      sync.Mutex
	recs    []image.Record
	built   []string
	removed []string
	err     error
	// missing are harnesses whose image is not built yet (Current).
	missing map[string]bool
}

func (f *fakeImages) Current(spec *harness.Spec) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.missing[spec.Name], nil
}

func (f *fakeImages) Build(_ context.Context, spec *harness.Spec, _ bool, _ io.Writer) (image.Record, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return image.Record{}, false, f.err
	}
	rec := image.Record{Tag: "defenseclaw/sandbox:" + spec.Name, Connector: spec.Name, HarnessVersion: spec.DefaultVersion, HookFireVerified: true}
	f.built = append(f.built, spec.Name)
	f.recs = append(f.recs, rec)
	return rec, true, nil
}

func (f *fakeImages) List() ([]image.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]image.Record(nil), f.recs...), nil
}

func (f *fakeImages) Prune(context.Context, bool) (image.PruneReport, error) {
	return image.PruneReport{Removed: []string{"defenseclaw/sandbox:old"}}, nil
}

func (f *fakeImages) Remove(_ context.Context, dryRun bool) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var tags []string
	for _, r := range f.recs {
		tags = append(tags, r.Tag)
	}
	if !dryRun {
		f.removed = append(f.removed, tags...)
		f.recs = nil
	}
	return tags, nil
}

// fakeCopy is an in-memory CopyWorkspace.
type fakeCopy struct {
	mu       sync.Mutex
	steps    []string
	pull     *workspace.PullResult
	apply    []workspace.ApplyOptions
	timeline *timeline
	// applied and applyErr replace what Apply returns.
	applied  *workspace.ApplyResult
	applyErr error
	// undo is what UndoApply answers (ErrNothingApplied when nil).
	undo    *workspace.UndoApplyResult
	undoErr error
	// pending is what PendingWork answers per sandbox, with an execer
	// (running) or without one (stopped); pendingErr fails it.
	pending        map[string]workspace.CopyWork
	pendingStopped map[string]workspace.CopyWork
	pendingErr     error
}

func (f *fakeCopy) Discard(_, name string) error {
	f.step("discard " + name)
	return nil
}

func (f *fakeCopy) PendingWork(_ context.Context, _, name string, ex workspace.Execer) (workspace.CopyWork, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pendingErr != nil {
		return workspace.CopyWorkUnknown, f.pendingErr
	}
	if ex == nil {
		return f.pendingStopped[name], nil
	}
	return f.pending[name], nil
}

func (f *fakeCopy) UndoApply(_ context.Context, o workspace.UndoApplyOptions) (*workspace.UndoApplyResult, error) {
	f.step(fmt.Sprintf("undo-apply %s preview=%v", o.Name, o.Preview))
	if f.undoErr != nil {
		return nil, f.undoErr
	}
	if f.undo == nil {
		return nil, workspace.ErrNothingApplied
	}
	r := *f.undo
	r.Preview, r.Undone = o.Preview, !o.Preview && len(r.Conflicts) == 0
	return &r, nil
}

func (f *fakeCopy) step(s string) {
	f.mu.Lock()
	f.steps = append(f.steps, s)
	f.mu.Unlock()
	f.timeline.add(s)
}

func (f *fakeCopy) Stage(_ context.Context, o workspace.StageOptions) (*workspace.CopyRecord, error) {
	f.step("stage " + o.Name)
	return &workspace.CopyRecord{Name: o.Name, Project: o.Project, Files: 3, Bytes: 1024, HeldBack: []string{".env"}}, nil
}

func (f *fakeCopy) Upload(_ context.Context, _, name string, _ workspace.Uploader) (*workspace.CopyRecord, error) {
	f.step("upload " + name)
	return &workspace.CopyRecord{Name: name, Files: 3, Bytes: 1024}, nil
}

func (f *fakeCopy) Baseline(_ context.Context, _, name string, _ workspace.Execer) (*workspace.CopyRecord, error) {
	f.step("baseline " + name)
	return &workspace.CopyRecord{Name: name}, nil
}

func (f *fakeCopy) Refresh(_ context.Context, o workspace.RefreshOptions) (*workspace.CopyRecord, error) {
	f.step("refresh " + o.Stage.Name)
	return &workspace.CopyRecord{Name: o.Stage.Name}, nil
}

func (f *fakeCopy) Pull(_ context.Context, o workspace.PullOptions) (*workspace.PullResult, error) {
	f.step("pull " + o.Name)
	if f.pull != nil {
		return f.pull, nil
	}
	return &workspace.PullResult{Name: o.Name, Changes: []workspace.TreeChange{{Path: "main.go", Status: "M", Added: 4, Deleted: 1}},
		Review: workspace.ReviewReport{FilesChanged: 1, Insertions: 4, Deletions: 1}}, nil
}

func (f *fakeCopy) Apply(_ context.Context, o workspace.ApplyOptions) (*workspace.ApplyResult, error) {
	f.step("apply " + string(o.Mode))
	f.mu.Lock()
	f.apply = append(f.apply, o)
	applied, err := f.applied, f.applyErr
	f.mu.Unlock()
	if applied != nil || err != nil {
		if applied != nil {
			r := *applied
			applied = &r
		}
		return applied, err
	}
	return &workspace.ApplyResult{Mode: o.Mode, Applied: true, Branch: o.Branch, PatchPath: o.PatchPath,
		Changes: []workspace.TreeChange{{Path: "main.go", Status: "M"}}}, nil
}

// fakeGateway is an in-memory GatewayService.
type fakeGateway struct {
	state     openshell.GatewayConfigState
	planned   []openshell.GatewayChanges
	applied   int
	rollbacks []*openshell.GatewayApplyResult
	applyRes  *openshell.GatewayApplyResult
}

func (f *fakeGateway) State() (*openshell.GatewayConfigState, error) { s := f.state; return &s, nil }

func (f *fakeGateway) Plan(_ context.Context, ch openshell.GatewayChanges) (*openshell.GatewayPlan, error) {
	f.planned = append(f.planned, ch)
	return &openshell.GatewayPlan{Files: []*openshell.FileChange{{Path: "/cfg/gateway.toml", Summary: []string{"enable_bind_mounts = true"}}}, Restart: "systemctl --user restart openshell-gateway"}, nil
}

func (f *fakeGateway) Apply(context.Context, *openshell.GatewayPlan) (*openshell.GatewayApplyResult, error) {
	f.applied++
	return f.applyRes, nil
}

func (f *fakeGateway) Rollback(_ context.Context, res *openshell.GatewayApplyResult) error {
	f.rollbacks = append(f.rollbacks, res)
	return nil
}

// testApp wires an App to fakes.
type testApp struct {
	*App
	daemon   *fakeDaemon
	term     *fakeTerminal
	stream   *fakeStreamer
	images   *fakeImages
	copy     *fakeCopy
	gateway  *fakeGateway
	env      map[string]string
	out, err *bytes.Buffer
	in       *strings.Reader
	project  string
	home     string
	execs    [][]string
}

func newTestApp(t *testing.T, input string) *testApp {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ta := &testApp{
		daemon: newFakeDaemon(t), term: &fakeTerminal{}, stream: &fakeStreamer{}, images: &fakeImages{},
		copy: &fakeCopy{}, gateway: &fakeGateway{}, env: map[string]string{"SHELL": "/bin/bash"},
		out: &bytes.Buffer{}, err: &bytes.Buffer{}, in: strings.NewReader(input),
		project: filepath.Join(root, "home", "proj"), home: filepath.Join(root, "home"),
	}
	for _, d := range []string{ta.project, ta.home, filepath.Join(root, "data")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// One timeline for the order of a run's steps; every harness the fakes
	// run reaches the daemon with its hooks unless a test turns that off.
	tl := &timeline{}
	ta.daemon.timeline, ta.term.timeline, ta.stream.timeline, ta.copy.timeline = tl, tl, tl, tl
	ta.term.hooks, ta.stream.hooks = ta.daemon.hookTraffic, ta.daemon.hookTraffic
	// A test that drops Cfg (or its DataDir) falls back to
	// config.DefaultDataPath: keep that in the fixture too, never the
	// developer's ~/.defenseclaw.
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(root, "data"))
	cfg := &config.Config{DataDir: filepath.Join(root, "data")}
	cfg.Gateway.APIPort = 18970
	cfg.OpenShell.Enabled = true
	ta.App = &App{
		Cfg: cfg, ConfigPath: filepath.Join(root, "data", "config.yaml"), API: ta.daemon.client(),
		IO:       IO{In: ta.in, Out: ta.out, Err: ta.err, TTY: true},
		Terminal: ta.term, Streamer: ta.stream, Images: ta.images, Workspace: ta.copy, Gateway: ta.gateway,
		ExecProcess: func(path string, argv, _ []string) error {
			ta.execs = append(ta.execs, append([]string{path}, argv...))
			return nil
		},
		LookPath:   func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Getenv:     func(k string) string { return ta.env[k] },
		Environ:    func() []string { return nil },
		Getwd:      func() (string, error) { return ta.project, nil },
		Home:       func() (string, error) { return ta.home, nil },
		Executable: func() (string, error) { return "/usr/local/bin/defenseclaw-gateway", nil },
		Now:        func() time.Time { return time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC) },
		GOOS:       "linux",
		WSL:        func() bool { return false },
		Geteuid:    func() int { return 1000 },
		Sleep:      func(context.Context, time.Duration) error { return nil },
		OpenShell: func(context.Context) (openshell.Client, *openshell.Registration, error) {
			return nil, nil, io.ErrClosedPipe
		},
	}
	return ta
}

func (ta *testApp) output() string { return ta.out.String() }

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

package sandboxcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
	// toolCalls is how many tool calls a harness the fakes ran makes
	// (hookTraffic): a session with a turn.
	toolCalls int64
	// onStatus runs before the status is returned (the daemon notices a
	// change).
	onStatus func(st *sandboxapi.Status)
	// onExplain, when set, edits the explain answer to a request.
	onExplain func(req sandboxapi.ExplainRequest, ex *sandboxapi.Explain)
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
	// hold, when set, keeps a followed activity stream open, like the
	// daemon's, until it is closed (the daemon went away) or the client
	// leaves.
	hold chan struct{}
	// runLogs are the detached-run logs the daemon kept (GET …/logs), and
	// stopRunLogs the one a stop of the sandbox keeps, as the daemon's
	// stop keeps the log of the run it finds.
	runLogs     map[string]*sandboxapi.RunLog
	stopRunLogs map[string]*sandboxapi.RunLog
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
		sb.Hooks.ToolCalls += d.toolCalls
		sb.Hooks.LastHookAt = time.Now()
	}
}

// runsHarness reports whether argv starts a harness through its launcher.
func runsHarness(argv []string) bool {
	return slices.ContainsFunc(argv, func(a string) bool { return strings.HasPrefix(a, harness.LauncherDir+"/") })
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	d := &fakeDaemon{sandboxes: map[string]*sandboxapi.Sandbox{}, errors: map[string]*sandboxapi.Error{},
		runLogs: map[string]*sandboxapi.RunLog{}, stopRunLogs: map[string]*sandboxapi.RunLog{}}
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
		if d.onStatus != nil {
			d.onStatus(&d.status)
		}
		reply(d.status)
	case path == sandboxapi.PathPolicyExplain:
		ex := d.explain
		if d.onExplain != nil {
			d.onExplain(sandboxapi.ParseExplainQuery(r.URL.Query()), &ex)
		}
		reply(ex)
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
			if hold := d.hold; hold != nil {
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				d.mu.Unlock()
				select {
				case <-hold:
				case <-r.Context().Done():
				}
				d.mu.Lock()
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
			Workdir: workdir, Launch: sandboxapi.Launch{Yolo: !req.Safe}, TamperTier: "managed", CreatedAt: time.Now(), Session: 1}
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
		case r.Method == http.MethodGet && verb == "logs":
			kept, ok := d.runLogs[name]
			if !ok {
				fail(sandboxapi.CodeNotFound, "no log of a detached run of sandbox "+name+" was kept")
				return
			}
			out := *kept
			if n, _ := strconv.Atoi(r.URL.Query().Get("lines")); n > 0 {
				out.Log = string(lastLines([]byte(out.Log), n))
			}
			reply(out)
		case r.Method == http.MethodGet:
			if d.onGet != nil {
				d.onGet(sb)
			}
			reply(sb)
		case r.Method == http.MethodDelete:
			delete(d.sandboxes, name)
			delete(d.runLogs, name)
			reply(sandboxapi.DeleteResponse{Name: name, Deleted: true})
		case verb == "stop":
			if kept, ok := d.stopRunLogs[name]; ok && sb.Phase == "ready" {
				log := *kept
				log.Name, log.KeptAt = name, time.Now()
				d.runLogs[name] = &log
			}
			sb.Phase = "stopped"
			reply(sb)
		case verb == "start":
			var req sandboxapi.StartRequest
			_ = json.Unmarshal(body, &req)
			if sb.Phase != "ready" {
				sb.Session++
			}
			sb.Phase = "ready"
			if sb.WorkdirMode == "mount" && sb.Snapshot != nil {
				// Like the manager: a start takes a new snapshot unless
				// changes nobody undid or accepted sit on the undo point, and
				// uses an acceptance up.
				fresh := req.NewSnapshot || !d.pendingChanges || !sb.Snapshot.UndoneAt.IsZero() || !sb.Snapshot.AcceptedAt.IsZero()
				switch {
				case !req.NoSnapshot && fresh:
					sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: sb.Snapshot.Kind, CreatedAt: time.Now()}
				case !sb.Snapshot.AcceptedAt.IsZero():
					snap := *sb.Snapshot
					snap.AcceptedAt = time.Time{}
					sb.Snapshot = &snap
				}
			}
			reply(sb)
		case verb == "accept":
			var req sandboxapi.AcceptRequest
			_ = json.Unmarshal(body, &req)
			switch {
			case sb.Phase == "ready":
				fail(sandboxapi.CodeConflict, "sandbox "+name+" is running; stop it before accepting its changes")
				return
			case sb.Snapshot == nil:
				fail(sandboxapi.CodeNotFound, "sandbox "+name+" has no undo point")
				return
			case !req.Snapshot.IsZero() && !req.Snapshot.Equal(sb.Snapshot.CreatedAt):
				fail(sandboxapi.CodeConflict, "sandbox "+name+" has another undo point by now")
				return
			case req.Session != 0 && req.Session != sb.Session:
				fail(sandboxapi.CodeConflict, "sandbox "+name+" was started again since its changes were reviewed")
				return
			}
			snap := *sb.Snapshot
			snap.AcceptedAt = time.Now()
			sb.Snapshot = &snap
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
	// missing are harnesses whose image is not built yet (Current).
	missing map[string]bool
	// gone are the recorded tags Docker no longer has (Gone).
	gone map[string]bool
	// presentIDs are the image IDs Docker still has (GoneIDs: every other
	// one is gone), and goneIDsErr its failure.
	presentIDs map[string]bool
	goneIDsErr error
	// sizes are the sizes of images (Size), by harness or image ref.
	sizes map[string]uint64
	// pruned are the options of each Prune; pruneReport, when set, is its
	// answer.
	pruned      []image.PruneOptions
	pruneReport *image.PruneReport
	// microVMProblem, by harness, is why a built image fails the probe's
	// MicroVM scenario, and microVMInconclusive why that scenario settled
	// nothing (neither: it passes).
	microVMProblem, microVMInconclusive map[string]string
	// buildOutput is what Build writes to the build log; buildErr, when
	// set, fails it.
	buildOutput string
	buildErr    error
	// preflightErr, when set, is Preflight's refusal.
	preflightErr error
}

func (f *fakeImages) Preflight(context.Context, *harness.Spec, bool, bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.preflightErr
}

func (f *fakeImages) Current(spec *harness.Spec, _ bool) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.missing[spec.Name], nil
}

func (f *fakeImages) Build(_ context.Context, spec *harness.Spec, microVM, _ bool, log io.Writer) (image.Record, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if log != nil {
		_, _ = io.WriteString(log, f.buildOutput)
	}
	if f.buildErr != nil {
		return image.Record{}, true, f.buildErr
	}
	rec := image.Record{Tag: "defenseclaw/sandbox:" + spec.Name, Connector: spec.Name, HarnessVersion: spec.DefaultVersion, HookFireVerified: true,
		MicroVM: microVM, MicroVMVerified: microVM && f.microVMProblem[spec.Name] == "" && f.microVMInconclusive[spec.Name] == "",
		MicroVMProblem: f.microVMProblem[spec.Name], MicroVMInconclusive: f.microVMInconclusive[spec.Name]}
	f.built = append(f.built, spec.Name)
	f.recs = append(f.recs, rec)
	return rec, true, nil
}

func (f *fakeImages) List() ([]image.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]image.Record(nil), f.recs...), nil
}

func (f *fakeImages) Gone(_ context.Context, recs []image.Record) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for _, r := range recs {
		if f.gone[r.Tag] {
			out[r.Tag] = true
		}
	}
	return out, nil
}

func (f *fakeImages) Size(_ context.Context, spec *harness.Spec, _ bool, ref string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if spec != nil {
		return f.sizes[spec.Name], nil
	}
	return f.sizes[ref], nil
}

func (f *fakeImages) GoneIDs(_ context.Context, ids []string) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.goneIDsErr != nil {
		return nil, f.goneIDsErr
	}
	out := map[string]bool{}
	for _, id := range ids {
		if !f.presentIDs[id] {
			out[id] = true
		}
	}
	return out, nil
}

func (f *fakeImages) Prune(_ context.Context, opts image.PruneOptions) (image.PruneReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruned = append(f.pruned, opts)
	if f.pruneReport != nil {
		return *f.pruneReport, nil
	}
	return image.PruneReport{Removed: []string{"defenseclaw/sandbox:old"}}, nil
}

func (f *fakeImages) Remove(_ context.Context, harnesses []string, dryRun bool) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var tags []string
	var kept []image.Record
	for _, r := range f.recs {
		if harnessOf(harnesses, r.Connector) {
			tags = append(tags, r.Tag)
		} else {
			kept = append(kept, r)
		}
	}
	if !dryRun {
		f.removed = append(f.removed, tags...)
		f.recs = kept
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
	undo *workspace.UndoApplyResult
	// pending is what PendingWork answers per sandbox, with an execer
	// (running) or without one (stopped); pendingPulled the pull it says a
	// running sandbox's copy is in the state of.
	pending, pendingStopped map[string]workspace.CopyWork
	pendingPulled           map[string]string
	// checks are the CheckApply calls; checkErr and held its answer.
	checks   []workspace.ApplyOptions
	checkErr error
	held     bool
	// reuseErr is what a Pull with Reuse fails with (it reuses f.pull
	// otherwise).
	reuseErr error
}

func (f *fakeCopy) Discard(_, name string) error {
	f.step("discard " + name)
	return nil
}

func (f *fakeCopy) PendingWork(_ context.Context, _, name string, ex workspace.Execer) (workspace.CopyStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ex == nil {
		return workspace.CopyStatus{Work: f.pendingStopped[name]}, nil
	}
	return workspace.CopyStatus{Work: f.pending[name], Pulled: f.pendingPulled[name]}, nil
}

func (f *fakeCopy) CheckApply(_ context.Context, o workspace.ApplyOptions) (bool, error) {
	f.step("check " + string(o.Mode))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, o)
	return f.held, f.checkErr
}

func (f *fakeCopy) UndoApply(_ context.Context, o workspace.UndoApplyOptions) (*workspace.UndoApplyResult, error) {
	f.step(fmt.Sprintf("undo-apply %s preview=%v", o.Name, o.Preview))
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

func (f *fakeCopy) Upload(_ context.Context, _, name string, _ workspace.Uploader, _ workspace.Execer) (*workspace.CopyRecord, error) {
	f.step("upload " + name)
	return &workspace.CopyRecord{Name: name, Files: 3, Bytes: 1024, HeldBack: []string{".env"}, Warnings: []string{"nested repository vendor/lib is not copied"}}, nil
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
	if o.Reuse != "" {
		f.step("reuse " + o.Name + " " + o.Reuse)
		if f.reuseErr != nil || f.pull == nil || f.pull.Result != o.Reuse {
			return nil, errors.Join(f.reuseErr, workspace.ErrNoReusablePull)
		}
		r := *f.pull
		r.Reused = true
		return &r, nil
	}
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
	restarts  int
	// stateErr, when set, fails State (a configuration that cannot be read).
	stateErr error
}

func (f *fakeGateway) Restart(context.Context) error { f.restarts++; return nil }

func (f *fakeGateway) State() (*openshell.GatewayConfigState, error) {
	if f.stateErr != nil {
		return nil, f.stateErr
	}
	s := f.state
	return &s, nil
}

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
	// gitConfig answers App.GitConfig by key.
	gitConfig map[string]string
	// live is the stderr liveErr set.
	live *lockedBuffer
	// diskFree is the free space App.DiskFree reports anywhere, and
	// diskProbed the path it was last asked about.
	diskFree   uint64
	diskProbed string
	// dockerEngine is the operating system App.DockerEngine reports ("":
	// not Docker Desktop), and dockerAsked how often it was asked.
	dockerEngine string
	dockerAsked  int
}

// newTestApp is an App wired to fakes, whose daemon holds sandboxes and
// whose terminal types input.
func newTestApp(t *testing.T, input string, sandboxes ...sandboxapi.Sandbox) *testApp {
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
		diskFree: 100 << 30,
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
		GOARCH:     "arm64", // a test that makes this a Mac makes it an Apple-silicon one
		WSL:        func() bool { return false },
		Geteuid:    func() int { return 1000 },
		DiskFree:   func(p string) (uint64, error) { ta.diskProbed = p; return ta.diskFree, nil },
		DockerEngine: func(context.Context) (string, error) {
			ta.dockerAsked++
			return ta.dockerEngine, nil
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
		OpenShell: func(context.Context) (openshell.Client, *openshell.Registration, error) {
			return nil, nil, io.ErrClosedPipe
		},
		// Never the developer's own git identity.
		GitConfig: func(_ context.Context, _, key string) string { return ta.gitConfig[key] },
	}
	for _, sb := range sandboxes {
		ta.daemon.add(sb)
	}
	return ta
}

func (ta *testApp) output() string { return ta.out.String() }

// bg is the context the tests run commands in.
var bg = context.Background()

// errOf is the error of a call that also returns a value.
func errOf[T any](_ T, err error) error { return err }

const (
	// sbName is the name the fake daemon gives a run's sandbox.
	sbName = "dc-claude-proj-1a2b"
	sbPath = sandboxapi.PathSandboxes + "/" + sbName
)

// ok stops the test if a command failed, with what it printed.
func (ta *testApp) ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%v\n%s", err, ta.output())
	}
}

// fresh empties ta's stdout for the command that follows:
// ta.ok(t, ta.fresh().Status(...)).
func (ta *testApp) fresh() *testApp {
	ta.out.Reset()
	return ta
}

// calls counts the fake daemon's requests to a sandbox endpoint: "box" (the
// sandbox itself) or "box/stop".
func (ta *testApp) calls(method, rel string) int { return len(ta.bodies(method, rel)) }

// wantCalls stops the test unless the fake daemon got n requests to a
// sandbox endpoint.
func (ta *testApp) wantCalls(t *testing.T, n int, method, rel string) {
	t.Helper()
	if got := ta.calls(method, rel); got != n {
		t.Fatalf("%s %s calls = %d, want %d\n%s", method, rel, got, n, ta.output())
	}
}

// bodies are the bodies of the requests to a sandbox endpoint.
func (ta *testApp) bodies(method, rel string) []string {
	var out []string
	for _, c := range ta.daemon.callsTo(method, sandboxapi.PathSandboxes+"/"+rel) {
		out = append(out, string(c.Body))
	}
	return out
}

// creates counts the create requests the fake daemon got.
func (ta *testApp) creates() int { return len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)) }

// has fails the test unless s holds every want.
func has(t *testing.T, s string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("lacks %q:\n%s", w, s)
		}
	}
}

// lacks fails the test if s holds any of bad.
func lacks(t *testing.T, s string, bad ...string) {
	t.Helper()
	for _, b := range bad {
		if strings.Contains(s, b) {
			t.Errorf("holds %q:\n%s", b, s)
		}
	}
}

// wantErr stops the test unless err holds every want.
func wantErr(t *testing.T, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %q", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("err = %v, want %q", err, w)
		}
	}
}

func wantExit(t *testing.T, err error, code int) {
	t.Helper()
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != code {
		t.Fatalf("err = %v, want exit status %d", err, code)
	}
}

// edit changes a sandbox of the fake daemon, as the daemon does during a
// session.
func (d *fakeDaemon) edit(name string, f func(*sandboxapi.Sandbox)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(d.sandboxes[name])
}

func (ta *testApp) mustGet(t *testing.T, name string) *sandboxapi.Sandbox {
	t.Helper()
	ta.daemon.mu.Lock()
	defer ta.daemon.mu.Unlock()
	sb, ok := ta.daemon.sandboxes[name]
	if !ok {
		t.Fatalf("no sandbox %s", name)
	}
	cp := *sb
	return &cp
}

// noChanges makes the fake review report an unchanged folder.
func noChanges(ta *testApp) {
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
}

func sampleSandbox(name string) sandboxapi.Sandbox {
	return sandboxapi.Sandbox{
		Name: name, ID: "sb-" + name, Harness: "claudecode", HarnessName: "Claude Code", Phase: "ready", Profile: "open",
		Pack: "open", NetworkMode: "open", Yolo: true, WorkdirMode: "mount", Project: "/home/u/proj", Workdir: "/work/proj",
		UptimeSeconds: 3700, Launch: sandboxapi.Launch{Yolo: true}, TamperTier: "managed", HookContract: "claude-code-hooks-v1",
		Hooks:  sandboxapi.HookCoverage{LastHookAt: time.Now(), HookRequests: 9, ToolCalls: 4, ToolBlocked: 1, LastBlocked: "marker"},
		Egress: sandboxapi.EgressStats{Destinations: 3, Blocked: 1, BytesUp: 2048, BytesDown: 1 << 20},
	}
}

func copySandbox(name string) sandboxapi.Sandbox {
	sb := sampleSandbox(name)
	sb.WorkdirMode, sb.Workdir, sb.Phase = "copy", "/sandbox/work/proj", "stopped"
	return sb
}

// folderSandbox is a sandbox that holds ta's project folder: a run there
// offers to resume it.
func folderSandbox(ta *testApp, phase string) sandboxapi.Sandbox {
	sb := sampleSandbox("proj-0a1b")
	sb.Phase, sb.Project, sb.CreatedAt = phase, ta.project, time.Now()
	return sb
}

func createRequest(t *testing.T, d *fakeDaemon) sandboxapi.CreateRequest {
	t.Helper()
	calls := d.callsTo("POST", sandboxapi.PathSandboxes)
	if len(calls) != 1 {
		t.Fatalf("create calls = %d (calls: %v)", len(calls), d.paths())
	}
	var req sandboxapi.CreateRequest
	if err := json.Unmarshal(calls[0].Body, &req); err != nil {
		t.Fatal(err)
	}
	return req
}

func harnessSpec(t *testing.T, name string) *harness.Spec {
	t.Helper()
	spec, ok := harness.Get(name)
	if !ok {
		t.Fatalf("no harness %s", name)
	}
	return spec
}

// writeConfig writes a minimal valid v8 config.yaml.
func writeConfig(t *testing.T, ta *testApp, extra string) {
	t.Helper()
	body := "config_version: 8\ndata_dir: " + ta.Cfg.DataDir + "\ngateway:\n  host: 127.0.0.1\n  api_port: 18970\nopenshell:\n  enabled: true\n" + extra
	if err := os.WriteFile(ta.ConfigPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadConfig(t *testing.T, ta *testApp) *config.Config {
	t.Helper()
	c, err := config.LoadRuntimeV8File(ta.ConfigPath)
	if err != nil {
		t.Fatalf("load %s: %v", ta.ConfigPath, err)
	}
	return c
}

// writeFile writes data to path, making its directory.
func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// isRunStatus reports whether cmd reads a detached run's status.
func isRunStatus(cmd []string) bool {
	return len(cmd) > 2 && cmd[0] == "sh" && strings.Contains(cmd[2], "latest.exit")
}

// runAnswers makes the fake sandbox report its latest detached run as state
// (the run-state script's key=value answer), log as the run's log, and
// answers everything else with success.
func runAnswers(ta *testApp, state, log string) {
	ta.stream.answer = func(argv []string) (int, string) {
		cmd := sandboxCommand(argv)
		switch {
		case len(cmd) > 2 && cmd[0] == "sh" && cmd[2] == runStateScript:
			return 0, state
		case len(cmd) > 2 && cmd[0] == "sh" && cmd[2] == runFollowScript:
			return 0, log
		case len(cmd) > 0 && cmd[0] == "tail":
			return 0, log
		}
		return 0, ""
	}
}

func ranScript(ta *testApp, script string) bool {
	return slices.ContainsFunc(ta.stream.runs, func(argv []string) bool {
		cmd := sandboxCommand(argv)
		return len(cmd) > 2 && cmd[0] == "sh" && cmd[2] == script
	})
}

// execSession splits a `sandbox exec` command into its session id and the
// user's command, without the session shell and the sandbox-env wrapper.
func execSession(cmd []string) (string, []string) {
	if len(cmd) < 4 || cmd[0] != "/bin/sh" || cmd[1] != "-c" || cmd[2] != execSessionShell ||
		!strings.HasPrefix(cmd[3], execSessionMark) {
		return "", cmd
	}
	session, rest := strings.TrimPrefix(cmd[3], execSessionMark), cmd[4:]
	if len(rest) > 0 && rest[0] == harness.SandboxEnvPath {
		rest = rest[1:]
	}
	return session, rest
}

// lockedBuffer is a stderr the session's notice goroutines write while the
// test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// liveErr gives ta a stderr that is safe to read during the session.
func liveErr(ta *testApp) *lockedBuffer {
	ta.live = &lockedBuffer{}
	ta.IO.Err = ta.live
	return ta.live
}

// waitFor polls cond until it holds or the test's patience runs out.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// runCase is a command of a fresh testApp (a run unless do says otherwise)
// and what it must print.
type runCase struct {
	name  string
	input string
	setup func(*testApp)
	// during runs while the harness owns the terminal.
	during func(*testing.T, *testApp)
	opts   RunOptions
	do     func(*testApp) error
	exit   int      // the exit status the command must end with, 0 for success
	want   []string // in its output
	not    []string // not in its output
	// live and notLive are what stderr, written during the session, must
	// and must not hold.
	live, notLive []string
	check         func(*testing.T, *testApp)
}

func runCases(t *testing.T, cases []runCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, c.input)
			liveErr(ta)
			if c.setup != nil {
				c.setup(ta)
			}
			if c.during != nil {
				ta.term.during = func() { c.during(t, ta) }
			}
			var err error
			if c.do != nil {
				err = c.do(ta)
			} else {
				err = ta.Run(bg, c.opts)
			}
			if c.exit != 0 {
				wantExit(t, err, c.exit)
			} else {
				ta.ok(t, err)
			}
			has(t, ta.output(), c.want...)
			lacks(t, ta.output(), c.not...)
			has(t, ta.live.String(), c.live...)
			lacks(t, ta.live.String(), c.notLive...)
			if c.check != nil {
				c.check(t, ta)
			}
		})
	}
}

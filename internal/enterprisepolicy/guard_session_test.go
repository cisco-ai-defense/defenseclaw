// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func sessionDeny(path, digest string) GuardDecision {
	return GuardDecision{
		Deny:     true,
		Reason:   "enterprise_foreign_hook_blocked: the project file " + path + " defines a hook.",
		Findings: []Finding{{Connector: "claudecode", Scope: ScopeProject, Path: path, Event: "PreToolUse", Digest: digest}},
	}
}

type sessionHarness struct {
	t       *testing.T
	home    string
	now     time.Time
	process string
	// stateDir, when set, is the gateway store (SessionUpdate.StateDir).
	stateDir string
}

func newSessionHarness(t *testing.T) *sessionHarness {
	return &sessionHarness{t: t, home: t.TempDir(), now: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
}

func (h *sessionHarness) apply(session string, start bool, decision GuardDecision) GuardDecision {
	h.t.Helper()
	h.now = h.now.Add(time.Second)
	return ApplyForeignHookSession(SessionUpdate{
		AccountHome:  h.home,
		StateDir:     h.stateDir,
		Key:          SessionKey{Connector: "claudecode", Session: session, Process: h.process},
		SessionStart: start,
		Decision:     decision,
		Now:          h.now,
	})
}

func (h *sessionHarness) path(kind, id string) string {
	if h.stateDir != "" {
		return sessionPathInDir(h.stateDir, "claudecode", kind, id)
	}
	return SessionPath(h.home, "claudecode", kind, id)
}

func (h *sessionHarness) record(kind, id string) SessionRecord {
	h.t.Helper()
	data, err := os.ReadFile(h.path(kind, id))
	if err != nil {
		h.t.Fatalf("read %s record %q: %v", kind, id, err)
	}
	var record SessionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		h.t.Fatal(err)
	}
	return record
}

// A session that started with a foreign hook keeps being denied after the
// file is cleaned: the agent still runs the hook it loaded at start.
func TestSessionStateKeepsDenyingASessionAfterTheHookIsRemoved(t *testing.T) {
	h := newSessionHarness(t)
	hookFile := "/work/repo/.claude/settings.local.json"
	first := h.apply("s-1", true, sessionDeny(hookFile, "aa11"))
	if !first.Deny || !strings.Contains(first.Reason, "restart the agent") || !strings.Contains(first.Reason, hookFile) {
		t.Fatalf("the session-start denial must name the file and say to restart the agent: %+v", first)
	}
	record := h.record(sessionKindSession, "s-1")
	if !record.Blocked || record.Path != hookFile || record.Digest != "aa11" || record.State != ForeignHookStateHash(first.Findings) {
		t.Fatalf("the session snapshot must record the block and the state hash: %+v", record)
	}

	later := h.apply("s-1", false, GuardDecision{})
	if !later.Deny || !strings.HasPrefix(later.Reason, "enterprise_foreign_hook_blocked:") {
		t.Fatalf("a clean scan later in the session must still deny: %+v", later)
	}
	// The block was recorded at session start, so the user's first prompt
	// may get this message: it says when, and names the allowlist key.
	for _, want := range []string{"When this agent session started, the", hookFile, "sha256:aa11", "connectors.claudecode.allowed_hooks", "restart the agent"} {
		if !strings.Contains(later.Reason, want) {
			t.Fatalf("the session denial must say %q: %s", want, later.Reason)
		}
	}
	if len(later.Findings) == 0 || later.Findings[0].Allowed || later.Findings[0].Path != hookFile {
		t.Fatalf("the session denial carries the recorded finding for the block record: %+v", later.Findings)
	}
	if other := h.apply("s-2", false, GuardDecision{}); other.Deny {
		t.Fatalf("another session with no recorded block and no shared process is not affected: %+v", other)
	}
}

// The process key carries the block into sessions the same agent process
// runs later (a cleared, compacted or resumed session). A restarted agent
// resuming the session starts clean, while the old process stays blocked.
func TestSessionStateFollowsTheAgentProcess(t *testing.T) {
	h := newSessionHarness(t)
	oldProcess := runtime.GOOS + "::4242:100"
	h.process = oldProcess
	h.apply("s-1", true, sessionDeny("/r/.claude/settings.json", "bb22"))
	if cleared := h.apply("s-2", true, GuardDecision{}); !cleared.Deny || !strings.Contains(cleared.Reason, "/r/.claude/settings.json") {
		t.Fatalf("a new session of the same agent process keeps the block: %+v", cleared)
	}
	if !h.record(sessionKindSession, "s-2").Blocked {
		t.Fatal("the block must be carried to the new session's record")
	}
	if resumed := h.apply("s-1", true, GuardDecision{}); !resumed.Deny {
		t.Fatalf("the same process resuming the session keeps the block: %+v", resumed)
	}

	// A restarted agent loaded its hooks from the clean files.
	h.process = runtime.GOOS + "::6262:300"
	if resumed := h.apply("s-2", true, GuardDecision{}); resumed.Deny {
		t.Fatalf("a restarted agent resuming the session must start clean: %+v", resumed)
	}
	if record := h.record(sessionKindSession, "s-2"); record.Blocked || record.Process != h.process {
		t.Fatalf("the resumed session's record must be the new process's clean snapshot: %+v", record)
	}
	if later := h.apply("s-2", false, GuardDecision{}); later.Deny {
		t.Fatalf("the resumed session stays clean: %+v", later)
	}
	// The old process may still run (a second terminal): it stays blocked,
	// without blocking the restarted agent's session.
	restarted := h.process
	h.process = oldProcess
	if call := h.apply("s-2", false, GuardDecision{}); !call.Deny {
		t.Fatalf("the process that loaded the hook stays blocked: %+v", call)
	}
	h.process = restarted
	if later := h.apply("s-2", false, GuardDecision{}); later.Deny {
		t.Fatalf("the old process must not block the restarted agent's session: %+v", later)
	}

	// Only a session start resets: a tool call of the old session in a new
	// process still denies.
	h.process = runtime.GOOS + "::7373:400"
	if call := h.apply("s-1", false, GuardDecision{}); !call.Deny {
		t.Fatalf("a blocked session is reset only at a session start: %+v", call)
	}
	// A session start whose process cannot be named may be the blocked
	// process compacting or resuming the session: the block holds.
	h.process = ""
	if start := h.apply("s-1", true, GuardDecision{}); !start.Deny {
		t.Fatalf("a session start with an unknown process must keep the session's block: %+v", start)
	}
}

// With no session ID in the payload the process key alone holds the block.
func TestSessionStateUsesTheProcessWithoutASessionID(t *testing.T) {
	h := newSessionHarness(t)
	h.process = runtime.GOOS + "::99:1"
	h.apply("", true, sessionDeny("/r/.github/hooks/x.json", "cc33"))
	if later := h.apply("", false, GuardDecision{}); !later.Deny {
		t.Fatalf("the agent process keeps the block: %+v", later)
	}
	h.process = ""
	if unknown := h.apply("", false, GuardDecision{}); unknown.Deny {
		t.Fatalf("with neither key the scan alone decides: %+v", unknown)
	}
}

// A clean session start records its snapshot; an allowed hook present at
// start is part of the state hash.
func TestSessionStateRecordsTheSnapshotAtSessionStart(t *testing.T) {
	h := newSessionHarness(t)
	h.process = runtime.GOOS + "::11:1"
	if decision := h.apply("s-1", true, GuardDecision{}); decision.Deny {
		t.Fatalf("a clean start allows: %+v", decision)
	}
	clean := h.record(sessionKindSession, "s-1")
	if clean.Blocked || clean.State != ForeignHookStateHash(nil) || clean.Started == "" || clean.Process != h.process {
		t.Fatalf("clean snapshot: %+v", clean)
	}
	if process := h.record(sessionKindProcess, h.process); process.Blocked || process.Session != "s-1" {
		t.Fatalf("process snapshot: %+v", process)
	}
	approved := GuardDecision{Findings: []Finding{{Connector: "claudecode", Scope: ScopeProject, Path: "/r/x.json", Digest: "dd44", Allowed: true}}}
	h.apply("s-2", true, approved)
	if state := h.record(sessionKindSession, "s-2").State; state == ForeignHookStateHash(nil) || state != ForeignHookStateHash(approved.Findings) {
		t.Fatalf("the state hash must cover an approved hook: %q", state)
	}
	// Later calls keep the start snapshot.
	h.apply("s-2", false, GuardDecision{})
	if state := h.record(sessionKindSession, "s-2").State; state != ForeignHookStateHash(approved.Findings) {
		t.Fatalf("a later call must not replace the start snapshot: %q", state)
	}
}

// A record that exists but cannot be read proves nothing: deny.
func TestSessionStateDeniesOnAnUnreadableRecord(t *testing.T) {
	h := newSessionHarness(t)
	path := SessionPath(h.home, "claudecode", sessionKindSession, "s-1")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := h.apply("s-1", false, GuardDecision{}); !decision.Deny || !strings.Contains(decision.Reason, "could not verify") {
		t.Fatalf("a corrupt record must deny: %+v", decision)
	}
	// It is not a foreign hook: the agent process is not blocked for it.
	h.process = runtime.GOOS + "::31:1"
	if decision := h.apply("s-1", false, GuardDecision{}); !decision.Deny {
		t.Fatalf("a corrupt record must deny: %+v", decision)
	}
	if _, err := os.Stat(h.path(sessionKindProcess, h.process)); !os.IsNotExist(err) {
		t.Fatalf("an unreadable record must not be carried to the agent process: %v", err)
	}
	if call := h.apply("s-2", false, GuardDecision{}); call.Deny {
		t.Fatalf("another session of the process is not blocked by the unreadable record: %+v", call)
	}
	h.process = ""
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if decision := h.apply("s-1", false, GuardDecision{}); !decision.Deny {
		t.Fatalf("a directory at the record path must deny: %+v", decision)
	}
	if runtime.GOOS != "windows" {
		linked := SessionPath(h.home, "claudecode", sessionKindSession, "s-9")
		target := filepath.Join(h.home, "elsewhere.json")
		if err := os.WriteFile(target, []byte(`{"v":1,"connector":"claudecode","blocked":false}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, linked); err != nil {
			t.Fatal(err)
		}
		if decision := h.apply("s-9", false, GuardDecision{}); !decision.Deny {
			t.Fatalf("a linked record must deny: %+v", decision)
		}
		if data, _ := os.ReadFile(target); !strings.Contains(string(data), `"blocked":false`) {
			t.Fatalf("nothing may be written through the link: %s", data)
		}
	}
}

// Records written more than the retention period ago are pruned at a
// session start. A denial does not refresh a blocked record.
func TestSessionStatePrunesOldRecords(t *testing.T) {
	h := newSessionHarness(t)
	h.apply("old", true, GuardDecision{})
	h.apply("blocked", true, sessionDeny("/r/x.json", "ee55"))
	h.apply("recent", true, GuardDecision{})
	old := SessionPath(h.home, "claudecode", sessionKindSession, "old")
	blocked := SessionPath(h.home, "claudecode", sessionKindSession, "blocked")
	recent := SessionPath(h.home, "claudecode", sessionKindSession, "recent")
	stale := h.now.Add(-sessionRecordTTL - time.Hour)
	for path, when := range map[string]time.Time{old: stale, blocked: stale, recent: h.now} {
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	if decision := h.apply("blocked", false, GuardDecision{}); !decision.Deny {
		t.Fatalf("the block lasts from BlockedAt, not from the file time: %+v", decision)
	}
	if info, err := os.Stat(blocked); err != nil || !info.ModTime().Equal(stale) {
		t.Fatalf("a denial must not refresh the blocked record: %v", err)
	}
	h.apply("new", true, GuardDecision{})
	for _, path := range []string{old, blocked} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s: a record past the retention period must be pruned: %v", filepath.Base(path), err)
		}
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatalf("a recent record must survive: %v", err)
	}
}

func TestGatewaySessionStateDeniesWhenRecordCannotBeWrittenOrRead(t *testing.T) {
	root := t.TempDir()
	blockedParent := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	update := SessionUpdate{
		StateDir: filepath.Join(blockedParent, "records"),
		Key:      SessionKey{Connector: "claudecode", Session: "s-1"},
		Decision: GuardDecision{},
	}
	if decision := ApplyForeignHookSession(update); !decision.Deny || !strings.Contains(decision.Reason, "cannot verify") {
		t.Fatalf("unwritable gateway record must deny: %+v", decision)
	}

	update.StateDir = filepath.Join(root, "records")
	if err := os.MkdirAll(update.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := sessionPathInDir(update.StateDir, "claudecode", sessionKindSession, "s-1")
	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := ApplyForeignHookSession(update); !decision.Deny || !strings.Contains(decision.Reason, "cannot verify") {
		t.Fatalf("unreadable gateway record must deny: %+v", decision)
	}
	if err := os.WriteFile(path, []byte(`{"v":1,"connector":"claudecode","session":"s-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := ApplyForeignHookSession(update); !decision.Deny || !strings.Contains(decision.Reason, "cannot verify") {
		t.Fatalf("incomplete gateway record must deny: %+v", decision)
	}
}

// A hook file DefenseClaw cannot read or parse denies the call, but it is
// not a foreign hook: no session block is recorded, and once the file reads
// cleanly the next call of the same session is allowed.
func TestSessionStateFileErrorsDoNotBlock(t *testing.T) {
	h := newSessionHarness(t)
	h.process = runtime.GOOS + "::111:1"
	unreadable := GuardDecision{
		Deny:   true,
		Reason: "enterprise_foreign_hook_blocked: the project file /r/.claude/settings.json cannot be verified",
		Findings: []Finding{{
			Connector: "claudecode",
			Scope:     ScopeProject,
			Path:      "/r/.claude/settings.json",
			Digest:    "unverifiable",
			Reason:    "cannot verify hook file: file truncated",
		}},
	}
	if result := h.apply("s-1", true, unreadable); !result.Deny {
		t.Fatalf("an unreadable hook file must deny the call: %+v", result)
	}
	record, exists, err := readSessionRecord(SessionPath(h.home, "claudecode", sessionKindSession, "s-1"))
	if err != nil || !exists {
		t.Fatalf("the session snapshot must be recorded at session start: exists=%v err=%v", exists, err)
	}
	if record.Blocked {
		t.Fatalf("an unreadable file must not block the session: %+v", record)
	}
	if later := h.apply("s-1", false, GuardDecision{}); later.Deny {
		t.Fatalf("once the file reads cleanly the session must be allowed: %+v", later)
	}
}

// An unapproved plugin names no event, and still blocks the session (OpenCode
// and Amp load plugins once per process).
func TestSessionStateBlocksForAnUnapprovedPlugin(t *testing.T) {
	h := newSessionHarness(t)
	h.process = runtime.GOOS + "::121:1"
	plugin := GuardDecision{
		Deny:     true,
		Reason:   "enterprise_foreign_hook_blocked: the project file /r/.opencode/plugins/x.js added a plugin.",
		Findings: []Finding{{Connector: "claudecode", Scope: ScopeProject, Path: "/r/.opencode/plugins/x.js", Digest: "dd44", Reason: "plugin"}},
	}
	h.apply("s-1", true, plugin)
	if record := h.record(sessionKindProcess, h.process); !record.Blocked || record.Reason != "plugin" {
		t.Fatalf("an unapproved plugin must block the agent process: %+v", record)
	}
	if later := h.apply("s-1", false, GuardDecision{}); !later.Deny || !strings.Contains(later.Reason, "added a plugin") {
		t.Fatalf("the process that loaded the plugin must stay blocked: %+v", later)
	}
}

// Without a process identity DefenseClaw cannot tell a restarted agent from
// a clear, compact or resume inside the process that loaded the hook, so a
// blocked session stays blocked through a session start that reuses its
// session ID. Only a new session ID starts clean.
func TestSessionStateKeepsABlockThroughASessionStartWithUnknownProcess(t *testing.T) {
	sessionStores(t, func(t *testing.T, h *sessionHarness) {
		h.process = ""
		hookFile := "/r/.claude/hooks.json"
		if start := h.apply("s-1", true, sessionDeny(hookFile, "bb22")); !start.Deny {
			t.Fatalf("a session start with a foreign hook denies: %+v", start)
		}
		// The user removes the hook and compacts the session: a session
		// start with the same session ID, in a process that cannot be named.
		compacted := h.apply("s-1", true, GuardDecision{})
		for _, want := range []string{hookFile, "restart the agent", "start a new session"} {
			if !compacted.Deny || !strings.Contains(compacted.Reason, want) {
				t.Fatalf("a compact without a process identity keeps the block and says %q: %+v", want, compacted)
			}
		}
		if record := h.record(sessionKindSession, "s-1"); !record.Blocked || record.Path != hookFile {
			t.Fatalf("the session's block must be kept: %+v", record)
		}
		if later := h.apply("s-1", false, GuardDecision{}); !later.Deny {
			t.Fatalf("later calls of the session stay denied: %+v", later)
		}

		// A block recorded with a process identity holds through a resume
		// whose process cannot be named.
		h.process = runtime.GOOS + "::222:2"
		h.apply("s-2", true, sessionDeny(hookFile, "cc33"))
		h.process = ""
		if resumed := h.apply("s-2", true, GuardDecision{}); !resumed.Deny {
			t.Fatalf("a resume without a process identity keeps the block: %+v", resumed)
		}

		// A new session ID starts clean.
		if fresh := h.apply("s-3", true, GuardDecision{}); fresh.Deny {
			t.Fatalf("a new session starts clean: %+v", fresh)
		}
		if later := h.apply("s-3", false, GuardDecision{}); later.Deny {
			t.Fatalf("the new session stays clean: %+v", later)
		}
	})
}

// sessionStores runs a test against the account-home store and the gateway
// store (SessionUpdate.StateDir).
func sessionStores(t *testing.T, run func(t *testing.T, h *sessionHarness)) {
	for _, store := range []string{"account-home", "gateway"} {
		t.Run(store, func(t *testing.T) {
			h := newSessionHarness(t)
			if store == "gateway" {
				h.stateDir = filepath.Join(t.TempDir(), "records")
			}
			run(t, h)
		})
	}
}

// Only a session start that finds an unapproved hook blocks the session. A
// hook found later denies the calls that find it, until it is removed.
func TestSessionStateBlocksOnlyForAHookPresentAtSessionStart(t *testing.T) {
	sessionStores(t, func(t *testing.T, h *sessionHarness) {
		h.process = runtime.GOOS + "::666:6"
		if start := h.apply("s-1", true, GuardDecision{}); start.Deny {
			t.Fatalf("a clean session start allows: %+v", start)
		}
		later := sessionDeny("/r/.cursor/hooks.json", "ff66")
		if call := h.apply("s-1", false, later); !call.Deny || strings.Contains(call.Reason, "restart the agent") {
			t.Fatalf("a hook found after the session start denies the call without blocking the session: %+v", call)
		}
		for kind, id := range map[string]string{sessionKindSession: "s-1", sessionKindProcess: h.process} {
			if record := h.record(kind, id); record.Blocked {
				t.Fatalf("%s record: a hook found after the session start must not block: %+v", kind, record)
			}
		}
		if call := h.apply("s-1", false, GuardDecision{}); call.Deny {
			t.Fatalf("once the hook is removed the session is allowed: %+v", call)
		}
		// A session start with the hook present blocks the session.
		if start := h.apply("s-2", true, later); !start.Deny || !strings.Contains(start.Reason, "restart the agent") {
			t.Fatalf("a hook present at the session start blocks the session: %+v", start)
		}
		if call := h.apply("s-2", false, GuardDecision{}); !call.Deny {
			t.Fatalf("the session that started with the hook stays blocked: %+v", call)
		}
	})
}

// A block lasts sessionRecordTTL from when it was recorded. Denials in
// between neither rewrite the record nor extend the block.
func TestSessionStateBlockExpiresAfterTheRetentionPeriod(t *testing.T) {
	sessionStores(t, func(t *testing.T, h *sessionHarness) {
		h.process = runtime.GOOS + "::555:5"
		h.apply("s-1", true, sessionDeny("/r/.claude/hooks.json", "ee55"))
		blockedAt := h.now
		written := map[string]time.Time{}
		for _, path := range []string{h.path(sessionKindSession, "s-1"), h.path(sessionKindProcess, h.process)} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			written[path] = info.ModTime()
		}
		for h.now.Sub(blockedAt) < sessionRecordTTL-12*time.Hour {
			h.now = h.now.Add(12 * time.Hour)
			if call := h.apply("s-1", false, GuardDecision{}); !call.Deny {
				t.Fatalf("%v after the block the session must still be denied: %+v", h.now.Sub(blockedAt), call)
			}
		}
		for path, mod := range written {
			if info, err := os.Stat(path); err != nil || !info.ModTime().Equal(mod) {
				t.Fatalf("%s: a denial must not rewrite the blocked record: %v", filepath.Base(path), err)
			}
		}
		h.now = blockedAt.Add(sessionRecordTTL + time.Hour)
		if call := h.apply("s-1", false, GuardDecision{}); call.Deny {
			t.Fatalf("the block ends %v after it was recorded: %+v", sessionRecordTTL, call)
		}
		for kind, id := range map[string]string{sessionKindSession: "s-1", sessionKindProcess: h.process} {
			if record := h.record(kind, id); record.Blocked {
				t.Fatalf("%s record: an expired block must be replaced by a clean snapshot: %+v", kind, record)
			}
		}
	})
}

// A session-start scan that stops on its file budget or its deadline before
// it reaches every source may have missed a hook the agent loaded, so the
// session and its agent process stay blocked after the files are cleared,
// until the agent restarts.
func TestSessionStateBlocksWhenTheSessionStartScanStopsOnABudget(t *testing.T) {
	sessionStores(t, func(t *testing.T, h *sessionHarness) {
		req := guardRequest(t, "copilot", config.ForeignHooksRemove)
		project := filepath.Dir(req.WorkingDir)
		if err := os.MkdirAll(req.WorkingDir, 0o755); err != nil {
			t.Fatal(err)
		}
		// Copilot reads the user hooks folder, then the project hooks folder,
		// then .github/copilot/settings.json: the flood ahead of the hook
		// uses up the file budget without passing any folder's entry limit.
		var planted []string
		for _, dir := range []string{filepath.Join(req.Home, ".copilot", "hooks"), filepath.Join(project, ".github", "hooks")} {
			for i := 0; i < guardDirEntryLimit; i++ {
				path := filepath.Join(dir, fmt.Sprintf("f%03d.json", i))
				writeFile(t, path, `{"hooks": {}}`)
				planted = append(planted, path)
			}
		}
		hook := filepath.Join(project, ".github", "copilot", "settings.json")
		writeFile(t, hook, `{"hooks": {"preToolUse": [{"type": "command", "bash": "./rewrite-args.sh"}]}}`)
		planted = append(planted, hook)

		start := EvaluateForeignHooks(req)
		if !start.Deny || !strings.Contains(start.Reason, "more than 512 files") || hasBlockableFindings(start) {
			t.Fatalf("premise: the flood stops the scan before it reaches the hook: %+v", start)
		}
		h.process = runtime.GOOS + "::777:7"
		if got := h.apply("s-1", true, start); !got.Deny || !strings.Contains(got.Reason, "restart the agent") {
			t.Fatalf("a session start whose scan stopped on a budget must block the session: %+v", got)
		}
		for kind, id := range map[string]string{sessionKindSession: "s-1", sessionKindProcess: h.process} {
			if record := h.record(kind, id); !record.Blocked || !strings.Contains(record.Reason, "more than 512 files") {
				t.Fatalf("%s record: the budget stop must be recorded as a block: %+v", kind, record)
			}
		}

		// The user clears the files; the agent still runs the hook it loaded.
		for _, path := range planted {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		clean := EvaluateForeignHooks(req)
		if clean.Deny {
			t.Fatalf("premise: the cleared files scan clean: %+v", clean)
		}
		later := h.apply("s-1", false, clean)
		for _, want := range []string{"enterprise_foreign_hook_blocked:", "When this agent session started", "more than 512 files", "restart the agent"} {
			if !later.Deny || !strings.Contains(later.Reason, want) {
				t.Fatalf("a later call of the session must still deny and say %q: %+v", want, later)
			}
		}
		if cleared := h.apply("s-2", true, clean); !cleared.Deny {
			t.Fatalf("a new session of the same agent process keeps the block: %+v", cleared)
		}

		// A restarted agent loaded its hooks from the cleared files.
		h.process = runtime.GOOS + "::778:8"
		if restarted := h.apply("s-3", true, clean); restarted.Deny {
			t.Fatalf("a restarted agent starts clean: %+v", restarted)
		}

		// A scan that runs past its deadline at the session start blocks too.
		slow := guardRequest(t, "copilot", config.ForeignHooksRemove)
		writeFile(t, filepath.Join(slow.Home, ".copilot", "hooks", "a.json"), `{"hooks": {}}`)
		slow.Deadline = time.Now().Add(-time.Second)
		stopped := EvaluateForeignHooks(slow)
		if !stopped.Deny || !strings.Contains(stopped.Reason, "time limit") || hasBlockableFindings(stopped) {
			t.Fatalf("premise: the scan stops on its deadline: %+v", stopped)
		}
		h.process = runtime.GOOS + "::779:9"
		h.apply("s-4", true, stopped)
		if call := h.apply("s-4", false, GuardDecision{}); !call.Deny || !strings.Contains(call.Reason, "time limit") {
			t.Fatalf("a session whose start scan ran past its deadline stays blocked: %+v", call)
		}
	})
}

// A folder over its entry limit or a hook file over its size limit stops
// the scan of that source, and the agent may still have loaded a hook past
// the limit: like a budget stop, the session start blocks the session and
// its agent process until the agent restarts, instead of denying only that
// call. A file that is merely unreadable or unparsable still denies only the
// call.
func TestSessionStateBlocksWhenASourceStopsOnItsLimit(t *testing.T) {
	sessionStores(t, func(t *testing.T, h *sessionHarness) {
		hook := `{"hooks": {"preToolUse": [{"type": "command", "bash": "./rewrite-args.sh"}]}}`
		for name, plant := range map[string]func(req GuardRequest) []string{
			"folder entry limit": func(req GuardRequest) []string {
				dir := filepath.Join(req.Home, ".copilot", "hooks")
				var planted []string
				for i := 0; i < guardDirEntryLimit; i++ {
					path := filepath.Join(dir, fmt.Sprintf("f%03d.json", i))
					writeFile(t, path, `{"hooks": {}}`)
					planted = append(planted, path)
				}
				path := filepath.Join(dir, "zz-rewrite.json")
				writeFile(t, path, hook)
				return append(planted, path)
			},
			"file size limit": func(req GuardRequest) []string {
				path := filepath.Join(req.Home, ".copilot", "hooks", "rewrite.json")
				writeFile(t, path, hook+strings.Repeat(" ", guardFileLimit))
				return []string{path}
			},
		} {
			t.Run(name, func(t *testing.T) {
				req := guardRequest(t, "copilot", config.ForeignHooksRemove)
				if err := os.MkdirAll(req.WorkingDir, 0o755); err != nil {
					t.Fatal(err)
				}
				planted := plant(req)
				start := EvaluateForeignHooks(req)
				if !start.Deny || !start.Incomplete || hasBlockableFindings(start) {
					t.Fatalf("premise: the limit stops the scan of that source: %+v", start)
				}
				h.process = runtime.GOOS + "::" + name
				session := "s-" + strings.ReplaceAll(name, " ", "-")
				if got := h.apply(session, true, start); !got.Deny || !strings.Contains(got.Reason, "restart the agent") {
					t.Fatalf("a session start that met a limit must block the session: %+v", got)
				}
				for _, path := range planted {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				clean := EvaluateForeignHooks(req)
				if clean.Deny {
					t.Fatalf("premise: the cleared files scan clean: %+v", clean)
				}
				if later := h.apply(session, false, clean); !later.Deny || !strings.Contains(later.Reason, "restart the agent") {
					t.Fatalf("a later call of the session must stay blocked: %+v", later)
				}
			})
		}

		// An unparsable file denies the call but is no limit stop.
		req := guardRequest(t, "copilot", config.ForeignHooksRemove)
		writeFile(t, filepath.Join(req.Home, ".copilot", "hooks", "broken.json"), `{"hooks": `)
		if broken := EvaluateForeignHooks(req); !broken.Deny || broken.Incomplete {
			t.Fatalf("an unparsable hook file must deny the call without marking the scan incomplete: %+v", broken)
		}
	})
}

func newGatewaySessionHarness(t *testing.T) *sessionHarness {
	h := newSessionHarness(t)
	h.now = time.Now().UTC()
	h.stateDir = filepath.Join(t.TempDir(), "records")
	return h
}

func (h *sessionHarness) applyAs(process, session string, start bool, decision GuardDecision) GuardDecision {
	h.t.Helper()
	h.process = process
	return h.apply(session, start, decision)
}

func sessionRecordCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			count++
		}
	}
	return count
}

// The gateway's session store is bounded. Each new agent process and session
// writes two records, so the limit used to refuse every new session of a user
// after 256 of them within the retention period, and a restart only asked for
// more records: the oldest clean records now make room. A caller that
// creates any number of session IDs must not push a blocked session's record
// out, and only when live blocked records alone fill the store is a new
// record refused (the call is denied) rather than dropping a block.
func TestGatewaySessionStoreEvictsOnlyCleanRecords(t *testing.T) {
	h := newGatewaySessionHarness(t)
	blockedProcess := "linux::900:1"
	if call := h.applyAs(blockedProcess, "blocked", true, sessionDeny("/r/.claude/settings.json", "ab12")); !call.Deny {
		t.Fatalf("session with a foreign hook at start not denied: %+v", call)
	}
	for i := 0; i < 2*sessionDirLimit; i++ {
		id := strconv.Itoa(i)
		if call := h.applyAs("linux::"+id+":2", "flood-"+id, true, GuardDecision{}); call.Deny {
			t.Fatalf("clean session %d denied: %s", i, call.Reason)
		}
	}
	if count := sessionRecordCount(t, h.stateDir); count > sessionDirLimit {
		t.Fatalf("store holds %d records, over the %d limit", count, sessionDirLimit)
	}
	newest := "flood-" + strconv.Itoa(2*sessionDirLimit-1)
	if record := h.record(sessionKindSession, newest); record.Blocked || record.Session != newest {
		t.Fatalf("newest session record = %+v", record)
	}
	for kind, id := range map[string]string{sessionKindSession: "blocked", sessionKindProcess: blockedProcess} {
		if record := h.record(kind, id); !record.Blocked {
			t.Fatalf("%s record lost its block: %+v", kind, record)
		}
	}
	if call := h.applyAs(blockedProcess, "blocked", false, GuardDecision{}); !call.Deny ||
		!strings.Contains(call.Reason, "When this agent session started") {
		t.Fatalf("blocked session allowed after the flood: %+v", call)
	}

	for i := 1; i < sessionDirLimit/2; i++ {
		id := strconv.Itoa(i)
		if call := h.applyAs("linux::"+id+":3", "b-"+id, true, sessionDeny("/r/.claude/settings.json", "cd34")); !call.Deny {
			t.Fatalf("blocked session %d not denied", i)
		}
	}
	if count := sessionRecordCount(t, h.stateDir); count != sessionDirLimit {
		t.Fatalf("store holds %d records, want %d blocked records", count, sessionDirLimit)
	}
	call := h.applyAs("linux::new:3", "new", true, GuardDecision{})
	if !call.Deny || !strings.Contains(call.Reason, "cannot verify this agent session's hook record") {
		t.Fatalf("a store full of blocks admitted a new record: %+v", call)
	}
	if count := sessionRecordCount(t, h.stateDir); count != sessionDirLimit {
		t.Fatalf("a block was evicted: %d records", count)
	}
}

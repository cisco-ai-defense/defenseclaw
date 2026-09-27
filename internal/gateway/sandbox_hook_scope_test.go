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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// sandboxProject is a host project folder mounted at /work/app, plus a
// sibling "home" directory standing in for host files outside the mount.
type sandboxProject struct {
	root    string
	outside string
	mount   sandboxauth.Binding
	copy    sandboxauth.Binding
}

func newSandboxProject(t *testing.T) sandboxProject {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "app")
	outside := filepath.Join(base, "home")
	for _, dir := range []string{filepath.Join(root, "src"), outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mount := sandboxauth.Binding{
		ID:             "sb_00000000000000000000000000000001",
		SandboxName:    "dc-claude-app",
		SandboxID:      "sbx-mount",
		Connector:      "claudecode",
		AgentVersion:   "2.1.156",
		HookContractID: "claudecode-hooks-v1",
		PolicyProfile:  "open",
		Routes:         []sandboxauth.Route{sandboxauth.RouteHook},
		Workdir: sandboxauth.Workdir{
			Mode:   sandboxauth.WorkdirMount,
			Mounts: []sandboxauth.Mount{{SandboxPath: "/work/app", HostPath: root}},
			Masks:  []string{"/work/app/.env"},
		},
		HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
	}
	cp := mount
	cp.ID = "sb_00000000000000000000000000000002"
	cp.SandboxName = "dc-claude-copy"
	cp.Workdir = sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}
	return sandboxProject{root: root, outside: outside, mount: mount, copy: cp}
}

func (p sandboxProject) write(t *testing.T, rel, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(p.root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func sandboxCtx(b sandboxauth.Binding) context.Context {
	ctx := sandboxauth.WithRequest(context.Background(), b, nil)
	return withAuthenticatedHookConnector(ctx, b.Connector)
}

func TestHookProfileForRequestUsesBindingContract(t *testing.T) {
	dataDir := t.TempDir()
	// The host has its own, different Codex install recorded.
	if err := connector.SaveHookContractLockEntry(dataDir, connector.HookContractLockEntry{
		Connector: "codex", RawAgentVersion: "0.130.0", ContractID: "codex-hooks-v2",
	}); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{scannerCfg: &config.Config{DataDir: dataDir}}
	if got := api.hookProfileForConnector("codex").ContractID; got != "codex-hooks-v2" {
		t.Fatalf("host profile contract = %q, want the host lock", got)
	}
	binding := sandboxauth.Binding{
		ID: "sb_00000000000000000000000000000003", Connector: "codex",
		AgentVersion: "0.128.0", HookContractID: "codex-hooks-v1",
		Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
	}
	ctx := sandboxauth.WithRequest(context.Background(), binding, nil)
	profile := api.hookProfileForRequest(ctx, "codex")
	if profile.ContractID != "codex-hooks-v1" || profile.AgentVersion != "0.128.0" {
		t.Fatalf("sandbox profile = %q/%q, want the binding's contract", profile.ContractID, profile.AgentVersion)
	}
	if !slices.Contains(profile.SupportedEvents, "SessionStart") {
		t.Fatalf("sandbox profile events = %v", profile.SupportedEvents)
	}
	if other := api.hookProfileForRequest(ctx, "claudecode"); other.ContractID != "" || len(other.SupportedEvents) != 0 {
		t.Fatalf("foreign connector profile = %+v, want empty", other)
	}
	// Host requests are unchanged.
	if got := api.hookProfileForRequest(context.Background(), "codex").ContractID; got != "codex-hooks-v2" {
		t.Fatalf("host request contract = %q", got)
	}
	if _, err := api.correlationSpecForRequestV8(ctx, "codex"); err != nil {
		t.Fatalf("sandbox correlation spec: %v", err)
	}
	if _, err := api.correlationSpecForRequestV8(ctx, "claudecode"); err == nil {
		t.Fatal("sandbox resolved another connector's correlation spec")
	}
}

func TestHookCWDForContext(t *testing.T) {
	p := newSandboxProject(t)
	p.write(t, "src/main.go", "package main\n", 0o644)
	if err := os.Symlink(p.outside, filepath.Join(p.root, "escape")); err != nil {
		t.Fatal(err)
	}
	mount := sandboxCtx(p.mount)
	for in, want := range map[string]string{
		"/work/app":             p.root,
		"/work/app/src":         filepath.Join(p.root, "src"),
		" /work/app/src/ ":      filepath.Join(p.root, "src"),
		"/work/app/escape":      "",
		"/work/app/src/main.go": "",
		"/work/app/missing":     "",
		p.root:                  "",
		"/sandbox":              "",
		"":                      "",
	} {
		if got := hookCWDForContext(mount, in); got != want {
			t.Errorf("mount cwd %q = %q, want %q", in, got, want)
		}
	}
	if got := hookCWDForContext(sandboxCtx(p.copy), p.root); got != "" {
		t.Fatalf("copy-mode cwd resolved to host path %q", got)
	}
	if got := hookCWDForContext(context.Background(), p.root); got != p.root {
		t.Fatalf("host cwd = %q, want unchanged host behaviour", got)
	}

	raw := []byte(`{"hook_event_name":"CwdChanged","cwd":"/work/app","old_cwd":"/work/app","new_cwd":"/work/app/src"}`)
	req := decodeClaudeCodeRequestForContext(mount, raw, map[string]interface{}{})
	if req.CWD != p.root || req.NewCWD != filepath.Join(p.root, "src") || req.OldCWD != p.root || req.sandboxView == nil {
		t.Fatalf("decoded claude request = %q %q %q view=%v", req.CWD, req.NewCWD, req.OldCWD, req.sandboxView != nil)
	}
	cx := decodeCodexRequestForContext(sandboxCtx(p.copy), []byte(`{"hook_event_name":"Stop","cwd":"`+p.root+`"}`), nil)
	if cx.CWD != "" || cx.sandboxView == nil {
		t.Fatalf("decoded copy-mode codex request cwd=%q", cx.CWD)
	}
	if host := decodeCodexRequestFromBytes([]byte(`{"cwd":"`+p.root+`"}`), nil); host.CWD != p.root || host.sandboxView != nil {
		t.Fatalf("host decode changed: %+v", host.CWD)
	}
}

func TestSandboxClaudeEventFileScanStaysInProject(t *testing.T) {
	p := newSandboxProject(t)
	p.write(t, "src/creds.go", "var k = \"AKIA"+"ABCDEFGHIJKLMNOP\"\n", 0o644)
	secret := filepath.Join(p.outside, "id_ed25519")
	if err := os.WriteFile(secret, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(p.root, "src", "key")); err != nil {
		t.Fatal(err)
	}
	p.write(t, ".env", "-----BEGIN OPENSSH PRIVATE KEY-----\n", 0o600)
	api := &APIServer{scannerCfg: &config.Config{}}
	scan := func(b sandboxauth.Binding, cwd, filePath string) *ToolInspectVerdict {
		view := sandboxauth.NewFSView(b, nil)
		return api.scanClaudeCodeEventFile(context.Background(), claudeCodeHookRequest{
			HookEventName: "FileChanged", CWD: cwd, FilePath: filePath, sandboxView: view,
		})
	}
	if v := scan(p.mount, p.root, "/work/app/src/creds.go"); v == nil || !slices.Contains(v.Findings, "CG-CRED-002") {
		t.Fatalf("in-project sandbox path not scanned: %+v", v)
	}
	if v := scan(p.mount, p.root, "src/creds.go"); v == nil || !slices.Contains(v.Findings, "CG-CRED-002") {
		t.Fatalf("relative path under the mapped cwd not scanned: %+v", v)
	}
	for _, filePath := range []string{"/work/app/src/key", secret, "/work/app/.env", "/work/app/../home/id_ed25519"} {
		if v := scan(p.mount, p.root, filePath); v != nil {
			t.Errorf("%s: read outside the project or a masked file: %+v", filePath, v)
		}
	}
	// Copy mode never reads the host, even when the path exists there.
	for _, filePath := range []string{filepath.Join(p.root, "src", "creds.go"), "/work/app/src/creds.go", secret} {
		if v := scan(p.copy, "", filePath); v != nil {
			t.Errorf("copy mode read host file %s: %+v", filePath, v)
		}
	}
	// Host behaviour is unchanged.
	if v := api.scanClaudeCodeEventFile(context.Background(), claudeCodeHookRequest{
		HookEventName: "FileChanged", FilePath: secret,
	}); v == nil || !slices.Contains(v.Findings, "CG-CRED-003") {
		t.Fatalf("host scan changed: %+v", v)
	}
}

func TestSandboxStopTargetsNeverRunGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	p := newSandboxProject(t)
	p.write(t, "src/tracked.go", "package src\n", 0o644)
	for _, args := range [][]string{
		{"init", "-q"}, {"add", "."},
		{"-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = p.root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	p.write(t, "src/tracked.go", "package src\n// changed\n", 0o644)
	p.write(t, "src/untracked.go", "package src\n", 0o644)
	p.write(t, "notes.txt", "configured\n", 0o644)

	cfg := &config.Config{}
	cfg.ClaudeCode.ScanPaths = []string{"notes.txt", filepath.Join(p.outside, "x"), "../home"}
	api := &APIServer{scannerCfg: cfg}
	host := api.claudeCodeStopTargets(context.Background(), claudeCodeHookRequest{CWD: p.root})
	if !slices.Contains(host, "src/tracked.go") && !slices.Contains(host, filepath.Join(p.root, "src", "tracked.go")) {
		t.Fatalf("host stop targets %v do not include git changes; the test proves nothing", host)
	}
	view := sandboxauth.NewFSView(p.mount, nil)
	got := api.claudeCodeStopTargets(context.Background(), claudeCodeHookRequest{CWD: p.root, sandboxView: view})
	if !slices.Equal(got, []string{filepath.Join(p.root, "notes.txt")}) {
		t.Fatalf("sandbox stop targets = %v, want only the configured in-project path", got)
	}
	if got := api.codexStopTargets(context.Background(), codexHookRequest{CWD: p.root, sandboxView: view}); len(got) != 0 {
		t.Fatalf("codex sandbox stop targets = %v, want none (no codex scan paths, no git)", got)
	}
	if n := api.scanClaudeCodeComponents(context.Background(), claudeCodeHookRequest{CWD: p.root, ScanComponents: true, sandboxView: view}); n != 0 {
		t.Fatalf("sandbox claude component scans = %d", n)
	}
	if n := api.scanCodexComponents(context.Background(), codexHookRequest{CWD: p.root, ScanComponents: true, sandboxView: view}); n != 0 {
		t.Fatalf("sandbox codex component scans = %d", n)
	}
}

func TestSandboxWatchPathsUseSandboxNamespace(t *testing.T) {
	p := newSandboxProject(t)
	view := sandboxauth.NewFSView(p.mount, nil)
	paths := claudeCodeWatchPathsForRequest(claudeCodeHookRequest{sandboxView: view}, p.root)
	if len(paths) == 0 {
		t.Fatal("no watch paths for the mapped project")
	}
	for _, path := range paths {
		if !strings.HasPrefix(path, "/work/app/") {
			t.Errorf("watch path %q is not a sandbox path", path)
		}
	}
	copyPaths := claudeCodeWatchPathsForRequest(claudeCodeHookRequest{sandboxView: sandboxauth.NewFSView(p.copy, nil)}, "")
	if copyPaths == nil || len(copyPaths) != 0 {
		t.Fatalf("copy-mode watch paths = %#v, want an empty list", copyPaths)
	}
	out := claudeCodeOutput(claudeCodeHookRequest{HookEventName: "SessionStart", sandboxView: view, CWD: p.root}, "allow", "allow", "", "")
	specific, _ := out["hookSpecificOutput"].(map[string]interface{})
	if got, _ := specific["watchPaths"].([]string); len(got) == 0 || !strings.HasPrefix(got[0], "/work/app/") {
		t.Fatalf("SessionStart output watch paths = %#v", specific["watchPaths"])
	}
}

func TestSandboxPromotedArtifactReadsOnlyProject(t *testing.T) {
	p := newSandboxProject(t)
	inside := p.write(t, "build.sh", "#!/bin/sh\necho hi\n", 0o755)
	outside := filepath.Join(p.outside, "evil.sh")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\nrm -rf ~\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	mount := sandboxCtx(p.mount)
	for _, path := range []string{inside, "/work/app/build.sh"} {
		body, dialect, ok := readPromotedArtifactBounded(mount, path, actionfacts.DialectNone)
		if !ok || dialect != actionfacts.DialectPOSIX || !bytes.Contains(body, []byte("echo hi")) {
			t.Fatalf("in-project artifact %s: ok=%v dialect=%v", path, ok, dialect)
		}
	}
	for _, path := range []string{outside, "/tmp/evil.sh", "/work/app/../home/evil.sh"} {
		if _, _, ok := readPromotedArtifactBounded(mount, path, actionfacts.DialectPOSIX); ok {
			t.Errorf("sandbox artifact %s read from outside the project", path)
		}
	}
	if _, _, ok := readPromotedArtifactBounded(sandboxCtx(p.copy), inside, actionfacts.DialectPOSIX); ok {
		t.Fatal("copy-mode artifact read from the host")
	}
	nonExec := p.write(t, "plain.sh", "#!/bin/sh\necho x\n", 0o644)
	if _, _, ok := readPromotedArtifactBounded(mount, nonExec, actionfacts.DialectNone); ok {
		t.Fatal("non-executable direct script accepted")
	}
	if _, _, ok := readPromotedArtifactBounded(context.Background(), outside, actionfacts.DialectNone); !ok {
		t.Fatal("host artifact read changed")
	}
}

func TestSandboxActiveAgentContextIsScopedAndProved(t *testing.T) {
	p := newSandboxProject(t)
	hostFile := p.write(t, "CLAUDE.md", "instructions\n", 0o644)
	api := activeClaudeCodeTestAPI()
	const session = "shared-session-id"

	// A host session with the same ID holds its own authority.
	hostAgentFile := writeActiveAgentTestFile(t, t.TempDir(), "AGENTS.md")
	api.applyClaudeCodeActiveAgentContext(authenticatedClaudeCodeTestContext(),
		claudeCodeHookRequest{HookEventName: "InstructionsLoaded", SessionID: session, FilePath: hostAgentFile})

	mount := sandboxCtx(p.mount)
	api.applyClaudeCodeActiveAgentContext(mount, claudeCodeHookRequest{HookEventName: "SessionStart", SessionID: session})
	api.applyClaudeCodeActiveAgentContext(mount, claudeCodeHookRequest{
		HookEventName: "InstructionsLoaded", SessionID: session, FilePath: "/work/app/CLAUDE.md",
	})
	snap := api.applyClaudeCodeActiveAgentContext(mount, claudeCodeHookRequest{HookEventName: "PreToolUse", SessionID: session})
	if !slices.Contains(snap.files, "/work/app/CLAUDE.md") || !slices.Contains(snap.files, hostFile) || snap.uncertain {
		t.Fatalf("sandbox snapshot = %+v, want sandbox and host spellings", snap)
	}
	host := api.activeAgentContext.snapshot("claudecode", session)
	if !slices.Equal(host.files, []string{hostAgentFile}) {
		t.Fatalf("sandbox SessionStart touched the host session: %+v", host)
	}

	// Copy mode cannot prove a file, so the session fails closed.
	cp := sandboxCtx(p.copy)
	api.applyClaudeCodeActiveAgentContext(cp, claudeCodeHookRequest{
		HookEventName: "InstructionsLoaded", SessionID: session, FilePath: "/work/app/CLAUDE.md",
	})
	snap = api.applyClaudeCodeActiveAgentContext(cp, claudeCodeHookRequest{HookEventName: "PreToolUse", SessionID: session})
	if !snap.uncertain || len(snap.files) != 0 {
		t.Fatalf("copy-mode snapshot = %+v, want uncertain", snap)
	}
	// A symlinked instruction file pointing outside cannot be proved either.
	if err := os.Symlink(hostAgentFile, filepath.Join(p.root, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	api.applyClaudeCodeActiveAgentContext(mount, claudeCodeHookRequest{
		HookEventName: "InstructionsLoaded", SessionID: "other", FilePath: "/work/app/AGENTS.md",
	})
	if snap := api.applyClaudeCodeActiveAgentContext(mount, claudeCodeHookRequest{HookEventName: "PreToolUse", SessionID: "other"}); !snap.uncertain {
		t.Fatalf("escaping instruction file was trusted: %+v", snap)
	}
}

func TestCorrelationMiddlewareUsesBindingIdentity(t *testing.T) {
	p := newSandboxProject(t)
	reg := NewAgentRegistry("agent-x", "agent-x")
	var got AgentIdentity
	var env audit.CorrelationEnvelope
	h := CorrelationMiddleware(reg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = AgentIdentityFromContext(r.Context())
		env = audit.EnvelopeFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set(llmEventUserIDHeader, "0")
	req.Header.Set(llmEventUserNameHeader, "root")
	h.ServeHTTP(httptest.NewRecorder(), req.WithContext(sandboxauth.WithRequest(req.Context(), p.mount, nil)))
	if got.UserID != "1000" || got.UserName != "dev" || got.UserIDKind == "" {
		t.Fatalf("sandbox identity = %+v, want the binding host user", got)
	}
	if env.SandboxID != "sbx-mount" || env.SandboxName != "dc-claude-app" || env.Connector != "claudecode" {
		t.Fatalf("sandbox envelope = %+v", env)
	}
	// Host loopback traffic keeps its trusted identity headers.
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got.UserID != "0" || got.UserName != "root" || env.SandboxID != "" {
		t.Fatalf("host identity changed: %+v %+v", got, env)
	}

	user := resolveHookUserIdentity(sandboxCtx(p.mount), "cursor", map[string]interface{}{
		"user_id": "evil", "user_email": "evil@example.com",
	})
	if user.ID != "1000" || user.Name != "dev" || user.Email != "" {
		t.Fatalf("sandbox hook user = %+v", user)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`{"user":"evil"}`))
	r.Header.Set(llmEventUserIDHeader, "0")
	r = r.WithContext(sandboxauth.WithRequest(r.Context(), p.mount, nil))
	if u := resolveHTTPUserIdentity(r, []byte(`{"user":"evil"}`)); u.ID != "1000" {
		t.Fatalf("sandbox OTLP user = %+v", u)
	}
}

func TestSandboxHookAuditExtra(t *testing.T) {
	p := newSandboxProject(t)
	profile := connector.HookProfile{ContractID: "claudecode-hooks-v1"}
	extra := hookRequestAuditExtra(sandboxCtx(p.mount), profile)
	for key, want := range map[string]string{
		"hook_contract_id":   "claudecode-hooks-v1",
		"sandbox_binding_id": p.mount.ID,
		"sandbox_id":         "sbx-mount",
		"sandbox_name":       "dc-claude-app",
		"sandbox_workdir":    "mount",
		"sandbox_profile":    "open",
	} {
		if extra[key] != want {
			t.Errorf("extra[%s] = %q, want %q", key, extra[key], want)
		}
	}
	host := hookRequestAuditExtra(context.Background(), profile)
	for key := range host {
		if strings.HasPrefix(key, "sandbox_") {
			t.Fatalf("host audit extra carries %s", key)
		}
	}
}

func TestCodexSessionStartSkipsHostRegistrationRepairInSandbox(t *testing.T) {
	api := &APIServer{scannerCfg: &config.Config{DataDir: t.TempDir()}}
	var mu sync.Mutex
	var repairs []string
	api.SetHookRegistrationRepair(func(_ context.Context, name string) error {
		mu.Lock()
		repairs = append(repairs, name)
		mu.Unlock()
		return nil
	})
	handler := api.handleUnifiedConnectorHook("codex")
	post := func(ctx context.Context, contract string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook",
			strings.NewReader(`{"hook_event_name":"SessionStart","session_id":"s1"}`))
		req.Header.Set("X-DefenseClaw-Hook-Event", "SessionStart")
		req.Header.Set("X-DefenseClaw-Hook-Contract", contract)
		rec := httptest.NewRecorder()
		handler(rec, req.WithContext(ctx))
		return rec.Code
	}
	hostContract := api.hookProfileForConnector("codex").ContractID
	if code := post(withAuthenticatedHookConnector(context.Background(), "codex"), hostContract); code != http.StatusOK {
		t.Fatalf("host SessionStart: %d", code)
	}
	binding := sandboxauth.Binding{
		ID: "sb_00000000000000000000000000000004", Connector: "codex",
		AgentVersion: "0.128.0", HookContractID: "codex-hooks-v1",
		Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
	}
	if code := post(sandboxCtx(binding), "codex-hooks-v1"); code != http.StatusOK {
		t.Fatalf("sandbox SessionStart: %d", code)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(repairs, []string{"codex"}) {
		t.Fatalf("registration repairs = %v, want exactly the host SessionStart", repairs)
	}
}

// countingFS wraps OSFS and records every call, to prove a code path used
// the view rather than the host filesystem.
type countingFS struct {
	mu    sync.Mutex
	calls int
}

func (c *countingFS) bump() { c.mu.Lock(); c.calls++; c.mu.Unlock() }
func (c *countingFS) Lstat(name string) (fs.FileInfo, error) {
	c.bump()
	return sandboxauth.OSFS{}.Lstat(name)
}
func (c *countingFS) EvalSymlinks(name string) (string, error) {
	c.bump()
	return sandboxauth.OSFS{}.EvalSymlinks(name)
}
func (c *countingFS) OpenInRoot(root, name string) (fs.File, error) {
	c.bump()
	return sandboxauth.OSFS{}.OpenInRoot(root, name)
}

func TestSandboxCodeGuardScanGoesThroughTheView(t *testing.T) {
	p := newSandboxProject(t)
	p.write(t, "src/creds.go", "var k = \"AKIA"+"ABCDEFGHIJKLMNOP\"\n", 0o644)
	fsys := &countingFS{}
	view := sandboxauth.NewFSView(p.mount, fsys)
	results := sandboxCodeGuardScan(view, "", []string{"/work/app/src/creds.go", "/work/app/src/creds.go", "", "/etc/passwd"})
	if len(results) != 1 || results[0].Target != "/work/app/src/creds.go" || len(results[0].Findings) == 0 {
		t.Fatalf("results = %+v", results)
	}
	if fsys.calls == 0 {
		t.Fatal("scan bypassed the view")
	}
	if got := sandboxCodeGuardScan(sandboxauth.NewFSView(p.copy, fsys), "", []string{"/work/app/src/creds.go"}); got != nil {
		t.Fatalf("copy-mode scan = %+v", got)
	}
}

// TestSandboxToolResultsSkipHostSourceProofs covers Observe mode's
// source-scope downgrade for tool results. On the host it verifies a git
// diff by reading the current file under the working directory. For a
// sandbox that file may be masked (the agent sees it empty), so a verdict
// that depended on the file's real lines would be an oracle on the secret.
// Sandbox tool results must be inspected as untrusted, without the host
// read, whatever the file holds.
func TestSandboxToolResultsSkipHostSourceProofs(t *testing.T) {
	root, err := filepath.EvalSymlinks(codexObserveTestWorkspace(t))
	if err != nil {
		t.Fatal(err)
	}
	literal := codexObserveSourceTrustLiteral()
	// The masked file's real content matches the diff the agent reports.
	if err := os.WriteFile(filepath.Join(root, "internal", "gateway", "rules.go"),
		[]byte("package gateway\n"+literal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	diff := strings.Join([]string{
		"diff --git a/internal/gateway/rules.go b/internal/gateway/rules.go",
		"index 1111111..2222222 100644",
		"--- a/internal/gateway/rules.go",
		"+++ b/internal/gateway/rules.go",
		"@@ -1 +1,2 @@",
		" package gateway",
		"+" + literal,
	}, "\n")
	input := map[string]interface{}{"command": "git diff -- internal/gateway/rules.go"}
	output := map[string]interface{}{"stdout": diff}

	for _, connectorName := range []string{"codex", "claudecode"} {
		t.Run(connectorName, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.Connector = connectorName
			api := &APIServer{scannerCfg: cfg}
			binding := sandboxauth.Binding{
				ID:             "sb_00000000000000000000000000000003",
				SandboxName:    "dc-" + connectorName + "-masked",
				Connector:      connectorName,
				AgentVersion:   "0.128.0",
				HookContractID: "codex-hooks-v1",
				Routes:         []sandboxauth.Route{sandboxauth.RouteHook},
				Workdir: sandboxauth.Workdir{
					Mode:   sandboxauth.WorkdirMount,
					Mounts: []sandboxauth.Mount{{SandboxPath: "/work/app", HostPath: root}},
					Masks:  []string{"/work/app/internal/gateway/rules.go"},
				},
			}
			if connectorName == "claudecode" {
				binding.AgentVersion, binding.HookContractID = "2.1.156", "claudecode-hooks-v1"
			}
			fsys := &countingFS{}
			view := sandboxauth.NewFSView(binding, fsys)
			sandbox := withAuthenticatedHookConnector(sandboxauth.WithRequest(t.Context(), binding, view), connectorName)
			// The working directory is already mapped to the host, exactly as
			// the request decoders leave it.
			evaluate := func(ctx context.Context, session string) string {
				if connectorName == "codex" {
					return api.evaluateCodexHook(ctx, codexHookRequest{
						HookEventName: "PostToolUse", SessionID: session, ToolName: "Bash",
						ToolInput: input, ToolResponse: output, CWD: root,
						sandboxView: viewFor(ctx),
					}).Severity
				}
				return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
					HookEventName: "PostToolUse", SessionID: session, ToolName: "Bash",
					ToolInput: input, ToolResponse: output, CWD: root,
					sandboxView: viewFor(ctx),
				}).Severity
			}
			// On the host the physical proof downgrades the verified line.
			if got := evaluate(t.Context(), "host-diff"); got != "LOW" {
				t.Fatalf("host severity = %s, want the source-scope LOW", got)
			}
			if got := evaluate(sandbox, "sandbox-diff"); severityRank[got] < severityRank["HIGH"] {
				t.Fatalf("sandbox severity = %s, want the untrusted verdict", got)
			}
			if fsys.calls != 0 {
				t.Fatalf("tool-result inspection used the sandbox view %d times", fsys.calls)
			}
			// The verdict is the same whatever the masked file holds.
			if err := os.WriteFile(filepath.Join(root, "internal", "gateway", "rules.go"),
				[]byte("package gateway\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			first := evaluate(sandbox, "sandbox-diff-2")
			if err := os.WriteFile(filepath.Join(root, "internal", "gateway", "rules.go"),
				[]byte("package gateway\n"+literal+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if second := evaluate(sandbox, "sandbox-diff-3"); first != second {
				t.Fatalf("sandbox verdict depends on the masked file: %s vs %s", first, second)
			}
		})
	}
}

func viewFor(ctx context.Context) *sandboxauth.FSView {
	view, _ := sandboxauth.ViewFromContext(ctx)
	return view
}

func sessionScopeBinding(id, connectorName string) sandboxauth.Binding {
	b := sandboxauth.Binding{
		ID:          id,
		SandboxName: "dc-" + id[len(id)-4:],
		Connector:   connectorName,
		Routes:      []sandboxauth.Route{sandboxauth.RouteHook},
		Workdir:     sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
		CreatedAt:   time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC),
	}
	switch connectorName {
	case "claudecode":
		b.AgentVersion, b.HookContractID = "2.1.156", "claudecode-hooks-v1"
	case "codex":
		b.AgentVersion, b.HookContractID = "0.128.0", "codex-hooks-v1"
	}
	return b
}

func TestSandboxConnectorInstanceID(t *testing.T) {
	a := sessionScopeBinding("sb_0000000000000000000000000000000a", "claudecode")
	b := sessionScopeBinding("sb_0000000000000000000000000000000b", "claudecode")
	id := sandboxConnectorInstanceID(a)
	parsed, err := uuid.Parse(string(id))
	if err != nil || parsed.Version() != 7 || parsed.Variant() != uuid.RFC4122 || parsed.String() != string(id) {
		t.Fatalf("instance id %q is not a canonical UUIDv7: %v", id, err)
	}
	if sec, nsec := parsed.Time().UnixTime(); time.Unix(sec, nsec).UTC().Truncate(time.Millisecond) != a.CreatedAt {
		t.Fatalf("instance id time = %v, want the binding creation", time.Unix(sec, nsec).UTC())
	}
	rotated := a
	rotated.Generation, rotated.TokenHash = 7, strings.Repeat("f", 64)
	if sandboxConnectorInstanceID(rotated) != id {
		t.Fatal("rotation changed the instance")
	}
	if sandboxConnectorInstanceID(b) == id {
		t.Fatal("two bindings share an instance")
	}
	zero := a
	zero.CreatedAt = time.Time{}
	if parsed, err := uuid.Parse(string(sandboxConnectorInstanceID(zero))); err != nil || parsed.Version() != 7 {
		t.Fatalf("zero creation time: %v", err)
	}
}

// TestSandboxCorrelationStateIsPerBinding names the host's session ID from
// two sandboxes and checks neither can reach the host's correlation cursor,
// replay receipts or connector instance, nor each other's.
func TestSandboxCorrelationStateIsPerBinding(t *testing.T) {
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	promptBody := []byte(`{"hook_event_name":"UserPromptSubmit","session_id":"shared-session","prompt":"hello"}`)
	toolBody := []byte(`{"hook_event_name":"PreToolUse","session_id":"shared-session","tool_name":"Read"}`)
	correlate := func(ctx context.Context, body []byte) agentHookRequest {
		t.Helper()
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		profile := server.hookProfileForRequest(ctx, "claudecode")
		req := normalizeAgentHookRequestWithProfile("claudecode", payload, profile)
		_, req, err := server.correlateHookOccurrence(ctx, profile, req, body)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	host := correlate(t.Context(), promptBody)
	a := sessionScopeBinding("sb_0000000000000000000000000000000a", "claudecode")
	b := sessionScopeBinding("sb_0000000000000000000000000000000b", "claudecode")
	ctxA, ctxB := sandboxCtx(a), sandboxCtx(b)

	toolA := correlate(ctxA, toolBody)
	if toolA.ConnectorInstanceID != string(sandboxConnectorInstanceID(a)) ||
		toolA.ConnectorInstanceID == host.ConnectorInstanceID {
		t.Fatalf("sandbox instance = %s, host = %s", toolA.ConnectorInstanceID, host.ConnectorInstanceID)
	}
	if toolA.AgentID == host.AgentID || toolA.TurnID == host.TurnID {
		t.Fatalf("sandbox attached to the host session cursor: agent=%s turn=%s", toolA.AgentID, toolA.TurnID)
	}
	// Replaying the host's exact delivery is a new occurrence, not a replay
	// that would suppress the host's telemetry.
	replay := correlate(ctxA, promptBody)
	if replay.SuppressCorrelationEmit || replay.SemanticEventID == host.SemanticEventID {
		t.Fatalf("sandbox replay matched the host occurrence: %+v", replay)
	}
	// A second sandbox is isolated from the first.
	toolB := correlate(ctxB, toolBody)
	if toolB.ConnectorInstanceID == toolA.ConnectorInstanceID || toolB.AgentID == replay.AgentID && toolB.AgentID != "" {
		t.Fatalf("sandboxes share correlation state: a=%+v b=%+v", replay, toolB)
	}
	// The host session keeps its own cursor.
	hostTool := correlate(t.Context(), toolBody)
	if hostTool.ConnectorInstanceID != host.ConnectorInstanceID ||
		hostTool.AgentID != host.AgentID || hostTool.TurnID != host.TurnID {
		t.Fatalf("host cursor disturbed: prompt=%+v tool=%+v", host, hostTool)
	}
	// A request for another connector cannot resolve any instance.
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveConnectorInstanceForRequest(ctxA, repo, "codex", "codex-profile-v1",
		audit.ConnectorCustodyExternal); err == nil {
		t.Fatal("sandbox resolved another connector's instance")
	}
}

func TestSandboxInMemorySessionStateIsPerBinding(t *testing.T) {
	a := sessionScopeBinding("sb_0000000000000000000000000000000a", "codex")
	b := sessionScopeBinding("sb_0000000000000000000000000000000b", "codex")
	const session = "shared-session"
	host := ContextWithSessionID(context.Background(), session)
	ctxA := ContextWithSessionID(sandboxCtx(a), session)
	ctxB := ContextWithSessionID(sandboxCtx(b), session)

	if got := sandboxSessionStateKey(host, session); got != session {
		t.Fatalf("host key = %q", got)
	}
	if keyA, keyB := sandboxSessionStateKey(ctxA, session), sandboxSessionStateKey(ctxB, session); keyA == session ||
		keyB == session || keyA == keyB {
		t.Fatalf("sandbox keys a=%q b=%q", keyA, keyB)
	}
	if sandboxSessionStateKey(ctxA, "") != "" {
		t.Fatal("an empty session must stay empty")
	}

	reg := NewAgentRegistry("agent", "Agent")
	hostID := reg.Resolve(host, session, "").AgentInstanceID
	if peek := reg.ResolvePeek(ctxA, session, "").AgentInstanceID; peek != "" {
		t.Fatalf("sandbox peeked the host session instance %q", peek)
	}
	idA := reg.Resolve(ctxA, session, "").AgentInstanceID
	idB := reg.Resolve(ctxB, session, "").AgentInstanceID
	if hostID == "" || idA == "" || idA == hostID || idB == idA || reg.Resolve(host, session, "").AgentInstanceID != hostID {
		t.Fatalf("registry instances host=%q a=%q b=%q", hostID, idA, idB)
	}

	judge := &LLMJudge{}
	judge.ObserveSessionPrompt(host, "HOST-INTENT-MARKER")
	if sample := judge.toolJudgeContextSample(ctxA, "Bash", `{"command":"ls"}`); strings.Contains(sample, "HOST-INTENT-MARKER") {
		t.Fatal("sandbox judge sample carries the host session's intent")
	}
	judge.ResetToolJudgeSession(sandboxSessionStateKey(ctxA, session))
	if sample := judge.toolJudgeContextSample(host, "Bash", `{"command":"ls"}`); !strings.Contains(sample, "HOST-INTENT-MARKER") {
		t.Fatal("a sandbox reset cleared the host session's judge context")
	}

	api := &APIServer{}
	api.rememberHookPromptID(host, "codex", session, "turn-1", "prompt-host")
	if got := api.lastHookPromptID(ctxA, "codex", session); got != "" {
		t.Fatalf("sandbox read the host prompt id %q", got)
	}
	api.rememberHookPromptID(ctxA, "codex", session, "turn-1", "prompt-a")
	if got := api.lastHookPromptIDForTurn(host, "codex", session, "turn-1"); got != "prompt-host" {
		t.Fatalf("host prompt id = %q after a sandbox wrote its own", got)
	}

	if api.stepIndexForTurn(sandboxSessionStateKey(ctxA, session), "t1", "UserPromptSubmit") != 1 ||
		api.stepIndexForTurn(sandboxSessionStateKey(host, session), "t9", "UserPromptSubmit") != 1 {
		t.Fatal("step index shared between the host and a sandbox")
	}
}

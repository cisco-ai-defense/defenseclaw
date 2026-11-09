// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// GAP-2591: on managed Linux and macOS the gateway service may not read the
// home folders, so the install watcher had no MCP source at all: a server an
// enrolled user added with claude mcp add was never scanned and its tool
// calls were allowed in action mode. The URL server the hook reports with
// the call (read as the user) is now listed for the watcher, so the pending
// check refuses the call and admission scans it; a local server, another
// account and a per-user gateway are left as before.
func TestManagedUnixHookReportedMCPServerIsAdmittedBeforeItsCalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: "managed_enterprise",
		Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.Watcher.Enabled = true
	if !watcherUsesHookReportedMCP(cfg) || !WatcherWatchesDirs(cfg) {
		t.Fatal("a standalone managed Unix gateway does not run the watcher for hook-reported MCP servers")
	}
	reported := &hookReportedMCPServers{}
	api := &APIServer{scannerCfg: cfg, hookMCP: reported}
	// Stands in for the watcher: a listed server without a baseline is pending.
	admitted := map[string]bool{}
	api.SetMCPAdmissionPending(func(connector, server, home, _ string) (string, bool) {
		servers, _ := reported.list()
		for _, entry := range servers {
			if entry.Connector == connector && entry.Name == server && entry.Home == home && !admitted[home+"|"+server] {
				return server, true
			}
		}
		return "", false
	})
	call := func(uid int, home string, facts assetfacts.Facts, event string) string {
		ctx := context.WithValue(withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, Home: home}),
			claimedAssetFactsContextKey{}, facts)
		resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: event,
			ToolName: "mcp__fcctx7__resolve-library-id", ToolInput: map[string]interface{}{}, CWD: home + "/proj"})
		return resp.Action
	}
	url := assetfacts.Facts{MCP: &assetfacts.MCPServer{Name: "fcctx7", URL: "https://mcp.example.com/mcp", Transport: "http"}}
	if got := call(1001, "/home/eng1", url, "PreToolUse"); got != "block" {
		t.Fatalf("first call of a reported URL server: action=%q, want block until admitted", got)
	}
	servers, _ := reported.list()
	if len(servers) != 1 || servers[0].URL != "https://mcp.example.com/mcp" || servers[0].Home != "/home/eng1" ||
		servers[0].Connector != "claudecode" || servers[0].Command != "" || servers[0].RunAsSID != "" {
		t.Fatalf("watched servers %+v, want the URL server of /home/eng1", servers)
	}
	admitted["/home/eng1|fcctx7"] = true
	if got := call(1001, "/home/eng1", url, "PreToolUse"); got == "block" {
		t.Fatalf("admitted server: action=%q, want its verdict to decide", got)
	}
	// Another account with the same name is its own server.
	if got := call(1002, "/home/eng2", url, "PreToolUse"); got != "block" {
		t.Fatalf("other account: action=%q, want its own admission first", got)
	}
	// A changed definition replaces the listed one (the watcher re-admits it).
	if !reported.note(config.MCPServerEntry{Name: "fcctx7", URL: "https://other.example.com/mcp", Connector: "claudecode", Home: "/home/eng1"}) {
		t.Fatal("a changed URL was not recorded")
	}
	// A local server would start as the gateway service account: not listed.
	local := assetfacts.Facts{MCP: &assetfacts.MCPServer{Name: "fcctx7", Command: "npx", Args: []string{"-y", "pkg"}}}
	call(1003, "/home/eng3", local, "PreToolUse")
	// A tool result never lists a server.
	call(1004, "/home/eng4", url, "PostToolUse")
	servers, _ = reported.list()
	for _, entry := range servers {
		if entry.Home == "/home/eng3" || entry.Home == "/home/eng4" {
			t.Fatalf("listed %+v, want no local server and nothing from a tool result", entry)
		}
	}

	// A per-user gateway reads its own files; Secure Client keeps main.
	for _, other := range []*config.Config{
		{AssetPolicy: config.DefaultAssetPolicy()},
		{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: "managed_enterprise"},
	} {
		if watcherUsesHookReportedMCP(other) {
			t.Fatalf("config %q/%q lists hook-reported MCP servers", other.DeploymentMode, other.Enterprise.Profile)
		}
	}
}

// One account reporting many servers (its hook facts are its own claim)
// must not use up the list for the other accounts, whose new servers would
// then be left unscanned (GAP-2591 review).
func TestHookReportedMCPServersCapIsPerAccount(t *testing.T) {
	reported := &hookReportedMCPServers{}
	for i := 0; i < hookReportedMCPLimit; i++ {
		reported.note(config.MCPServerEntry{Name: fmt.Sprintf("forged%d", i), URL: "https://mcp.example.com/mcp",
			Connector: "claudecode", Home: "/home/eng1"})
	}
	if servers, _ := reported.list(); len(servers) >= hookReportedMCPLimit {
		t.Fatalf("one account filled the list of every account (%d servers)", len(servers))
	}
	if !reported.note(config.MCPServerEntry{Name: "fcctx7", URL: "https://mcp.example.com/mcp", Connector: "claudecode", Home: "/home/eng2"}) {
		t.Fatal("a new server of another account was not listed after one account reported many")
	}
	// A changed definition of a listed server is still recorded at the cap.
	if !reported.note(config.MCPServerEntry{Name: "forged0", URL: "https://other.example.com/mcp", Connector: "claudecode", Home: "/home/eng1"}) {
		t.Fatal("a changed URL of a listed server was not recorded at the per-account cap")
	}
}

// reportedMCPHarness is a managed Linux or macOS gateway whose hooks report
// servers. issue is the ScanIssue its stand-in watcher records for a listed
// server once scanned is set.
type reportedMCPHarness struct {
	api      *APIServer
	reported *hookReportedMCPServers
	scanned  bool
	issue    string
}

func newReportedMCPHarness() *reportedMCPHarness {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: "managed_enterprise",
		Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.Watcher.Enabled = true
	h := &reportedMCPHarness{reported: &hookReportedMCPServers{}, issue: watcher.MCPScanIssueLauncher}
	h.api = &APIServer{scannerCfg: cfg, hookMCP: h.reported}
	// Stands in for the watcher: a listed server is pending until its scan
	// is done, and a refused definition is a failed admission.
	h.api.SetMCPAdmissionStatus(func(connector, server, home, _ string) watcher.MCPAdmissionStatus {
		servers, _ := h.reported.list()
		for _, entry := range servers {
			if entry.Connector == connector && entry.Name == server && entry.Home == home {
				// The watcher answers failed, with the cause, for a server whose
				// listed definition carries a stated refusal, before any scan.
				if !h.scanned && (entry.LocalRefusal == "" || !watcher.MCPLocalRefused(entry)) {
					return watcher.MCPAdmissionStatus{Name: server, Pending: true, RetryAfter: 30 * time.Second}
				}
				return watcher.MCPAdmissionStatus{Name: server, Failed: true, ScanIssue: h.issue}
			}
		}
		return watcher.MCPAdmissionStatus{}
	})
	return h
}

func (h *reportedMCPHarness) call(home string, server *assetfacts.MCPServer) claudeCodeHookResponse {
	ctx := context.WithValue(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home}),
		claimedAssetFactsContextKey{}, assetfacts.Facts{MCP: server})
	return h.api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse",
		ToolName: "mcp__" + server.Name + "__ping", ToolInput: map[string]interface{}{}, CWD: home + "/proj"})
}

// callFacts is call with the facts carried as the standalone hook sends them:
// encoded and decoded, so the argument bound of the header applies.
func (h *reportedMCPHarness) callFacts(t *testing.T, home string, server assetfacts.MCPServer) claudeCodeHookResponse {
	t.Helper()
	facts, ok := assetfacts.Decode(assetfacts.Encode(assetfacts.Facts{MCP: &server}))
	if !ok || facts.MCP == nil {
		t.Fatal("the hook facts lost the server")
	}
	ctx := context.WithValue(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home}),
		claimedAssetFactsContextKey{}, facts)
	return h.api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse",
		ToolName: "mcp__" + server.Name + "__ping", ToolInput: map[string]interface{}{}, CWD: home + "/proj"})
}

// GAP-0925: a local (stdio) server added with claude mcp add whose launcher
// the scanner refuses (python3, node, a command path) was never listed, so
// it had no admission record and its calls were allowed on a managed device,
// where a URL server is admitted or blocked. It is listed like a URL server,
// the first call waits for the admission, and the recorded refusal blocks
// with the cause and the administrator step. A launcher a scan would start
// (npx, uvx) stays unlisted: nothing here starts it as its user.
func TestManagedUnixHookReportedRefusedLauncherServerIsAdmittedAndBlocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	reported := h.reported
	call := h.call
	python := &assetfacts.MCPServer{Name: "localpy", Command: "python3", Args: []string{"/home/eng1/server.py"}}
	if got := call("/home/eng1", python); got.Action != "block" {
		t.Fatalf("first call of a reported python3 server: action=%q, want block until admitted", got.Action)
	}
	servers, _ := reported.list()
	if len(servers) != 1 || servers[0].Command != "python3" || len(servers[0].Args) != 1 || servers[0].URL != "" ||
		servers[0].Home != "/home/eng1" || servers[0].Connector != "claudecode" || servers[0].RunAsSID != "" {
		t.Fatalf("watched servers %+v, want the python3 server of /home/eng1", servers)
	}
	first := call("/home/eng1", python)
	h.scanned = true
	later := call("/home/eng1", python)
	if later.Action != "block" || !strings.Contains(later.Reason, "asset_policy.mcp.allowed") ||
		!strings.Contains(later.Reason, "launcher") {
		t.Fatalf("later call: action=%q reason=%q, want a block naming the launcher and asset_policy.mcp.allowed", later.Action, later.Reason)
	}
	// The call that lists the server is blocked with the same cause and the
	// same administrator step, not a retry message.
	if first.Action != "block" || first.Reason != later.Reason {
		t.Fatalf("call that lists the server: action=%q reason=%q, want the later block %q", first.Action, first.Reason, later.Reason)
	}
	// A changed definition is recorded again (the watcher re-admits it).
	if !reported.note(config.MCPServerEntry{Name: "localpy", Command: "python3", Args: []string{"/home/eng1/other.py"},
		Connector: "claudecode", Home: "/home/eng1"}) {
		t.Fatal("a changed argument list was not recorded")
	}
	// Benign twins: a launcher a scan would start, and an account that has no
	// server of that name, stay as before.
	for _, server := range []*assetfacts.MCPServer{
		{Name: "localnpx", Command: "npx", Args: []string{"-y", "pkg"}},
		{Name: "localuvx", Command: "uvx", Args: []string{"mcp-server-time"}},
	} {
		if got := call("/home/eng2", server); got.Action == "block" {
			t.Fatalf("%s server: action=%q reason=%q, want it left to the asset_policy lists", server.Command, got.Action, got.Reason)
		}
	}
	servers, _ = reported.list()
	for _, entry := range servers {
		if entry.Home == "/home/eng2" {
			t.Fatalf("listed %+v, want no server whose launcher a scan starts", entry)
		}
	}
}

// The scanner refuses an npx or uvx server for what its arguments run or
// leave out, from the definition alone, as it refuses a python3 server for its
// launcher; the managed gateway lists it the same way, so its calls are blocked
// with the cause and the administrator step and never fall through to allow
// (GAP-0925). The servers a scan starts stay with the asset_policy lists.
func TestManagedUnixHookReportedRefusedArgumentsServerIsAdmittedAndBlocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"npx -c", []string{"-c", "echo hi"}},
		{"npx --eval", []string{"--eval=1"}},
		{"npx -y with -x and a package", []string{"-y", "-x", "pkg"}},
		{"npx without a package", nil},
		{"npx with options only", []string{"-y", "--quiet"}},
		{"uvx --script", []string{"--script", "pkg"}},
		{"uvx without a package", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newReportedMCPHarness()
			h.issue = watcher.MCPScanIssueArguments
			command := "npx"
			if strings.HasPrefix(tc.name, "uvx") {
				command = "uvx"
			}
			server := &assetfacts.MCPServer{Name: "localargs", Command: command, Args: tc.args}
			if got := h.call("/home/eng1", server); got.Action != "block" {
				t.Fatalf("first call: action=%q, want block until admitted", got.Action)
			}
			if servers, _ := h.reported.list(); len(servers) != 1 || servers[0].Command != command || servers[0].Home != "/home/eng1" {
				t.Fatalf("watched servers %+v, want the %s server of /home/eng1", servers, command)
			}
			h.scanned = true
			later := h.call("/home/eng1", server)
			if later.Action != "block" || !strings.Contains(later.Reason, "asset_policy.mcp.allowed") ||
				!strings.Contains(later.Reason, "arguments") {
				t.Fatalf("later call: action=%q reason=%q, want a block naming the arguments and asset_policy.mcp.allowed", later.Action, later.Reason)
			}
		})
	}
	// Benign twins: the same launchers with a package stay unlisted and allowed.
	h := newReportedMCPHarness()
	for _, server := range []*assetfacts.MCPServer{
		{Name: "twinnpx", Command: "npx", Args: []string{"-y", "@scope/pkg", "--port", "3000"}},
		{Name: "twinuvx", Command: "uvx", Args: []string{"--from", "git-pkg", "mcp-server-time"}},
		{Name: "twineq", Command: "npx", Args: []string{"--yes", "pkg@1.2.3"}},
	} {
		if got := h.call("/home/eng2", server); got.Action == "block" {
			t.Fatalf("%s server %v: action=%q reason=%q, want it left to the asset_policy lists", server.Command, server.Args, got.Action, got.Reason)
		}
	}
	if servers, _ := h.reported.list(); len(servers) != 0 {
		t.Fatalf("listed %+v, want no server whose launcher and arguments a scan starts", servers)
	}
}

// The facts keep at most 32 arguments, and the scanner refuses a local server
// for what the complete list holds: an execution flag after the 32nd argument
// is refused, and a package after 32 options is accepted. The managed gateway
// decides from the verdict the hook took from the complete definition, never
// from the arguments the header carried (GAP-0925).
func TestManagedUnixHookReportedMCPJudgesTheCompleteDefinitionNotTheBoundedArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	filler := func(n int, arg string, tail ...string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = arg
		}
		return append(out, tail...)
	}
	for _, tc := range []struct {
		name    string
		command string
		args    []string
		blocked bool
	}{
		{"flag after the bound", "npx", append([]string{"-y", "pkg"}, filler(30, "--quiet", "-c", "echo hi")...), true},
		{"flag after the bound without a package before", "uvx", filler(33, "--quiet", "--eval=1"), true},
		{"no package within a long list", "npx", filler(40, "-y"), true},
		{"package after 32 options", "npx", filler(32, "-y", "pkg"), false},
		{"package first in a long list", "npx", append([]string{"pkg"}, filler(40, "--quiet")...), false},
		{"short definition with a package", "npx", []string{"-y", "pkg"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newReportedMCPHarness()
			h.issue = watcher.MCPScanIssueArguments
			server := assetfacts.MCPServer{Name: "longargs", Command: tc.command, Args: tc.args}
			got := h.callFacts(t, "/home/eng1", server)
			listed, _ := h.reported.list()
			if tc.blocked {
				if got.Action != "block" || len(listed) != 1 || listed[0].LocalRefusal != "arguments" {
					t.Fatalf("action=%q listed=%+v, want the refused definition listed and blocked", got.Action, listed)
				}
				h.scanned = true
				if later := h.callFacts(t, "/home/eng1", server); later.Action != "block" || !strings.Contains(later.Reason, "asset_policy.mcp.allowed") {
					t.Fatalf("later call: action=%q reason=%q, want the block with the administrator step", later.Action, later.Reason)
				}
				return
			}
			if got.Action == "block" || len(listed) != 0 {
				t.Fatalf("action=%q reason=%q listed=%+v, want the server a scan starts left to the asset_policy lists", got.Action, got.Reason, listed)
			}
		})
	}
}

// A claim from a hook that stated no verdict, whose arguments are as many as
// the header keeps, cannot show the verdict: it is neither listed nor blocked
// for the arguments it holds. Editing a listed server into one a scan starts
// takes it off the list, so the refusal recorded for the old definition does
// not block the new one.
func TestManagedUnixHookReportedMCPUnstatedCutClaimIsNotJudgedAndAFixedServerIsForgotten(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	cut := make([]string, 32)
	for i := range cut {
		cut[i] = "--quiet"
	}
	cut[31] = "-c"
	if got := h.call("/home/eng2", &assetfacts.MCPServer{Name: "oldhook", Command: "npx", Args: cut}); got.Action == "block" {
		t.Fatalf("unstated cut claim: action=%q reason=%q, want it not judged by the arguments it holds", got.Action, got.Reason)
	}
	if listed, _ := h.reported.list(); len(listed) != 0 {
		t.Fatalf("listed %+v, want an unstated cut claim left to the asset_policy lists", listed)
	}
	if got := h.call("/home/eng1", &assetfacts.MCPServer{Name: "edited", Command: "python3", Args: []string{"server.py"}}); got.Action != "block" {
		t.Fatalf("python3 server: action=%q, want block", got.Action)
	}
	if got := h.call("/home/eng1", &assetfacts.MCPServer{Name: "edited", Command: "npx", Args: []string{"-y", "pkg"}}); got.Action == "block" {
		t.Fatalf("server edited to npx with a package: action=%q reason=%q, want it allowed", got.Action, got.Reason)
	}
	if listed, _ := h.reported.list(); len(listed) != 0 {
		t.Fatalf("listed %+v, want the edited server off the list", listed)
	}
}

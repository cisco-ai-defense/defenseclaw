// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestAuthorizedKeysSymlinkWriteStatementsAndClientResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX authorized_keys matcher is separate from the Windows enterprise path")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	input := actionfacts.Input{Tool: "Bash", CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
	for _, row := range []struct {
		name, command string
		want          bool
	}{
		{"semicolon x", "ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./x.cfg", true},
		{"newline z", "ln -sf $HOME/.ssh/authorized_keys ./z.cfg\necho marker >> ./z.cfg", true},
		{"and ak", "ln -s ~/.ssh/authorized_keys ./ak.lnk && echo marker >> ./ak.lnk", true},
		{"truncate", "ln -s ~/.ssh/authorized_keys ./ak.lnk; echo marker > ./ak.lnk", true},
		{"tee", "ln -s ~/.ssh/authorized_keys ./ak.lnk; echo marker | tee -a ./ak.lnk", true},
		{"copy", "ln -s ~/.ssh/authorized_keys ./ak.lnk; cp marker.pub ./ak.lnk", true},
		{"dd", "ln -s ~/.ssh/authorized_keys ./ak.lnk; dd if=marker.pub of=./ak.lnk", true},
		{"sed", "ln -s ~/.ssh/authorized_keys ./ak.lnk; sed -i s/old/new/ ./ak.lnk", true},
		{"or x", "ln -sf ~/.ssh/authorized_keys ./x.cfg || echo marker >> ./x.cfg", true},
		{"intervening command", "ln -s ~/.ssh/authorized_keys ./z.cfg; true; echo marker >> ./z.cfg", true},
		{"brace group", "{ ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./x.cfg; }", true},
		{"subshell", "(ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./x.cfg)", true},
		{"if body", "if true; then ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./x.cfg; fi", true},
		{"for body", "for i in 1; do ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./x.cfg; done", true},
		{"different target", "ln -s ~/proj/notes.txt ./x.cfg; echo marker >> ./x.cfg", false},
		{"different name", "ln -s ~/.ssh/authorized_keys ./x.cfg; echo marker >> ./z.cfg", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input.Command = row.command
			if got := trustedAuthorizedKeysSymlinkWrite(input); got != row.want {
				t.Fatalf("symlink write proof = %v, want %v", got, row.want)
			}
		})
	}
	t.Run("protected home leaves gateway cwd empty", func(t *testing.T) {
		input.Tool = "exec_command"
		input.Command = ""
		input.CWD = ""
		input.Args = json.RawMessage(`{"cmd":"echo marker >> ~/proj/x.cfg"}`)
		facts := actionfacts.Analyze(input)
		request := trustedActionRequest{Input: input, Connector: "codex", ResolvedWriteTargets: map[string]string{
			hookpaths.CWDKey:                     cwd,
			filepath.Join(home, "proj", "x.cfg"): filepath.Join(home, ".ssh", "authorized_keys"),
		}}
		if !trustedExistingAuthorizedKeysSymlinkWrite(request, facts) {
			t.Fatal("client-resolved home write was allowed without a gateway-visible cwd")
		}
		input.CWD = cwd
	})
	t.Run("relative write with protected gateway cwd", func(t *testing.T) {
		input.Tool = "exec_command"
		input.Command, input.CWD = "", ""
		input.Args = json.RawMessage(`{"cmd":"echo marker >> ./x.cfg"}`)
		facts := actionfacts.Analyze(input)
		request := trustedActionRequest{Input: input, Connector: "codex", ResolvedWriteTargets: map[string]string{
			hookpaths.CWDKey:            cwd,
			filepath.Join(cwd, "x.cfg"): filepath.Join(home, ".ssh", "authorized_keys"),
		}}
		if !trustedExistingAuthorizedKeysSymlinkWrite(request, facts) {
			t.Fatal("client-resolved relative write was allowed without a gateway-visible cwd")
		}
		input.CWD = cwd
	})
	for _, row := range []struct {
		name, command, target string
		want                  bool
	}{
		{"existing link", "echo marker >> ./x.cfg", filepath.Join(home, ".ssh", "authorized_keys"), true},
		{"home tilde link", "echo marker >> ~/proj/x.cfg", filepath.Join(home, ".ssh", "authorized_keys"), true},
		{"resolution failed", "echo marker >> ./x.cfg", "", false},
		{"regular file", "echo marker >> ./x.cfg", filepath.Join(cwd, "x.cfg"), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input.Command = row.command
			facts := actionfacts.Analyze(input)
			request := trustedActionRequest{Input: input, ResolvedWriteTargets: map[string]string{filepath.Join(cwd, "x.cfg"): row.target}}
			if got := trustedExistingAuthorizedKeysSymlinkWrite(request, facts); got != row.want {
				t.Fatalf("existing symlink proof = %v, want %v; paths=%v", got, row.want, facts.Paths)
			}
		})
	}
	t.Run("partial cmd projection uses client target", func(t *testing.T) {
		input.Tool = "exec_command"
		input.Command = ""
		input.Args = json.RawMessage(`{"cmd":"echo marker >> ~/proj/x.cfg"}`)
		facts := actionfacts.Analyze(input)
		request := trustedActionRequest{Input: input, Connector: "codex", ResolvedWriteTargets: map[string]string{
			filepath.Join(cwd, "x.cfg"): filepath.Join(home, ".ssh", "authorized_keys"),
		}}
		if !trustedExistingAuthorizedKeysSymlinkWrite(request, facts) {
			t.Fatal("partial command did not use the client-resolved write target")
		}
	})
	for _, connector := range []string{"codex", "claudecode"} {
		t.Run("older "+connector+" client has no positive path proof", func(t *testing.T) {
			input.Command = "echo marker >> ./missing.cfg"
			facts := actionfacts.Analyze(input)
			request := trustedActionRequest{Input: input, Connector: connector, ProtectedHomeHook: true}
			if trustedExistingAuthorizedKeysSymlinkWrite(request, facts) {
				t.Fatal("missing client evidence was treated as a protected write")
			}
		})
	}
	keys := filepath.Join(home, "authorized_keys")
	link := filepath.Join(home, "existing.cfg")
	if err := os.WriteFile(keys, []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "tool_input": map[string]any{"command": "echo marker >> " + link},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok || targets[link] != keys {
		t.Fatalf("hook client target = %q, want %q", targets[link], keys)
	}
	if err := os.Mkdir(filepath.Join(home, "proj"), 0o700); err != nil {
		t.Fatal(err)
	}
	homeLink := filepath.Join(home, "proj", "x.cfg")
	if err := os.Symlink(keys, homeLink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	payload, err = json.Marshal(map[string]any{
		"tool_name": "Bash", "tool_input": map[string]any{"command": "echo marker >> ~/proj/x.cfg"},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok = hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok || targets[homeLink] != keys {
		t.Fatalf("hook client home target = %q, want %q; all=%v", targets[homeLink], keys, targets)
	}
	payload, err = json.Marshal(map[string]any{
		"toolName": "Bash", "toolInput": map[string]any{"cmd": "echo marker >> ~/proj/x.cfg"},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok = hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok || targets[homeLink] != keys {
		t.Fatalf("hook client cmd target = %q, want %q; all=%v", targets[homeLink], keys, targets)
	}
}

func TestAuthorizedKeysWriteTargetCap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hook write targets")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	external := filepath.Join(root, "external")
	for _, dir := range []string{filepath.Join(home, ".ssh"), external} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(external, "linked.cfg")
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, count := range []int{31, 32, 40, hookpaths.MaxWriteTargets} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			writes := make([]string, 0, count+1)
			for i := range count {
				writes = append(writes, fmt.Sprintf("echo marker > %s", filepath.Join(external, fmt.Sprintf("benign-%02d", i))))
			}
			writes = append(writes, "echo marker >> "+link)
			command := strings.Join(writes, "; ")
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok || targets[hookpaths.CWDKey] == "" {
				t.Fatalf("hook evidence lost cwd or failed to decode: ok=%v", ok)
			}
			if count < hookpaths.MaxWriteTargets && targets[link] != keys {
				t.Fatalf("final write resolved to %q, want %q", targets[link], keys)
			}
			if count >= hookpaths.MaxWriteTargets && targets[hookpaths.TruncatedKey] != "1" {
				t.Fatal("omitted write target was not marked as truncated")
			}
			input := actionfacts.Input{Tool: "Bash", Command: command, CWD: root, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			request := trustedActionRequest{Input: input, Connector: "codex", ProtectedHomeHook: true, ResolvedWriteTargets: targets}
			if !trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)) {
				t.Fatal("protected linked write was allowed")
			}
		})
	}

}

func TestClaudeWriteTargetMarkerRule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell paths")
	}
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	installToolCallCorpusProfileConnector(t, "claudecode", "default")
	for _, row := range []struct {
		name, command, cwd string
		block              bool
	}{
		{"known hosts", "hostname > ~/.ssh/known_hosts", project, false},
		{"ssh config", "hostname > ~/.ssh/config", project, false},
		{"known hosts again", "date > ~/.ssh/known_hosts", project, false},
		{"relative known hosts", "date > known_hosts", filepath.Join(home, ".ssh"), false},
		{"project redirect", "echo hi > ~/proj/e1.txt", project, false},
		{"absolute project", "hostname > " + filepath.Join(project, "h1.txt"), project, false},
		{"project tee", "echo hi | tee ~/proj/t2.txt", project, false},
		{"external redirect", "hostname > /tmp/x", project, false},
		{"read keys", "hostname < ~/.ssh/authorized_keys", project, false},
		{"keys redirect", "hostname > ~/.ssh/authorized_keys", project, true},
		{"home variable keys", "hostname > $HOME/.ssh/authorized_keys", project, true},
		{"keys append", "uptime >> ~/.ssh/authorized_keys", project, true},
		{"keys stderr append", "uptime 2>> ~/.ssh/authorized_keys", project, true},
		{"empty command redirect", ": > ~/.ssh/authorized_keys", project, true},
		{"true redirect", "true > ~/.ssh/authorized_keys", project, true},
		{"absolute keys", "hostname > " + filepath.Join(home, ".ssh", "authorized_keys"), project, true},
		{"normalized keys", "hostname > " + filepath.Join(project, "..", ".ssh", "authorized_keys"), project, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: row.cwd,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			// A complete client map: no listed operand is a link.
			targets := map[string]string{hookpaths.CWDKey: row.cwd}
			findings := dispatchTrustedAction(ctx, trustedActionRequest{
				Input: input, Connector: "claudecode", EnforcementCapable: true,
				ResolvedWriteTargets: targets,
			})
			want := guardrailActionAllow
			if row.block {
				want = guardrailActionBlock
			}
			if got := buildVerdict(findings, "tool_call").Action; got != want {
				t.Fatalf("verdict = %s, want %s; findings=%v", got, want, findingIDs(findings))
			}
			if row.block {
				found := false
				for _, finding := range findings {
					found = found || finding.RuleID == "persistence.ssh_authorized_keys_command" &&
						finding.Severity == "CRITICAL" && finding.contributesToEnforcement()
				}
				if !found {
					t.Fatalf("protected redirect lacked enforced marker rule: %v", findingIDs(findings))
				}
			}
		})
	}
}

func TestClaudeResolvedWriteHeaderMarkerRule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hook paths")
	}
	root := t.TempDir()
	home, project, external := filepath.Join(root, "home"), filepath.Join(root, "home", "proj"), filepath.Join(root, "external")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project, external} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	externalLink, homeLink, relativeLink := filepath.Join(external, "kfile"), filepath.Join(project, "inside"), filepath.Join(project, "relative")
	for _, link := range []string{externalLink, homeLink} {
		if err := os.Symlink(keys, link); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("..", ".ssh", "authorized_keys"), relativeLink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Chdir(project)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	for _, row := range []struct {
		name, link string
		count      int
		block      bool
	}{
		{"external one", externalLink, 0, true},
		{"external thirty one", externalLink, 31, true},
		{"external thirty three", externalLink, 33, true},
		{"home link", homeLink, 0, true},
		{"relative link", "./relative", 0, true},
		{"benign home", filepath.Join(project, "notes.txt"), 0, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			writes := make([]string, 0, row.count+1)
			for i := range row.count {
				writes = append(writes, fmt.Sprintf("echo marker > %s", filepath.Join(external, fmt.Sprintf("note-%02d", i))))
			}
			writes = append(writes, "echo marker >> "+row.link)
			command := strings.Join(writes, "; ")
			body, err := json.Marshal(map[string]any{"session_id": "marker-session", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			header := hookpaths.Resolve(body)
			targets, ok := hookpaths.Decode(header)
			if !ok || targets[hookpaths.CWDKey] != project {
				t.Fatalf("write header lacks cwd: %v", targets)
			}
			if row.block {
				operand := row.link
				if !filepath.IsAbs(operand) {
					operand = filepath.Join(project, operand)
				}
				operand = filepath.Clean(operand)
				if row.count < hookpaths.MaxWriteTargets && targets[operand] != keys {
					t.Fatalf("resolved operand = %q, want %q", targets[operand], keys)
				}
				if row.count >= hookpaths.MaxWriteTargets && targets[hookpaths.TruncatedKey] != "1" {
					t.Fatal("omitted target lacked truncation marker")
				}
			}
			if row.block {
				// The managed gateway runs under a different account and may
				// not see the caller's link. Keep only the client's header proof.
				if err := os.Remove(row.link); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Symlink(keys, row.link); err != nil {
						t.Error(err)
					}
				})
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(string(body)))
			req.Header.Set(hookpaths.Header, header)
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			recorder := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
			want := `"raw_action":"allow"`
			if row.block {
				want = `"raw_action":"block"`
			}
			if !strings.Contains(recorder.Body.String(), want) {
				t.Fatalf("response = %d %s, want %s", recorder.Code, recorder.Body.String(), want)
			}
		})
	}
	if err := os.Remove(keys); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{
		"command": "echo marker >> " + externalLink,
	}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok || targets[externalLink] != keys {
		t.Fatalf("missing final file resolved to %q, want %q", targets[externalLink], keys)
	}
}

// TestResolvedWriteHeaderNeverDropsTarget covers the live && chains that
// exceeded the client shell analysis limits and sent a map without the
// final linked operand or a truncation marker (GAP-1370).
func TestResolvedWriteHeaderNeverDropsTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hook paths")
	}
	root := t.TempDir()
	home, project, external := filepath.Join(root, "home"), filepath.Join(root, "home", "proj"), filepath.Join(root, "external")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project, external} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(external, "kfile")
	t.Setenv("HOME", home)
	t.Chdir(project)
	post := func(t *testing.T, connector, mode, command, header string) string {
		t.Helper()
		cfg := &config.Config{}
		cfg.Guardrail.Mode = mode
		cfg.Guardrail.Connector = connector
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		body := string(mustJSON(t, map[string]any{"session_id": "marker-session", "hook_event_name": "PreToolUse",
			"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command, "description": "d"}}))
		if header == "" {
			header = hookpaths.Resolve([]byte(body))
		}
		// The managed gateway may not see the link of the caller: keep only
		// the header evidence of the hook client.
		_ = os.Remove(link)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(body))
		req.Header.Set(hookpaths.Header, header)
		if connector == "codex" {
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
		}
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
		recorder := httptest.NewRecorder()
		api.handleAgentHook(connector).ServeHTTP(recorder, req)
		return recorder.Body.String()
	}
	chain := func(count int, final string) string {
		writes := make([]string, 0, count+1)
		for i := range count {
			writes = append(writes, fmt.Sprintf("echo x > %s", filepath.Join(external, fmt.Sprintf("t%03d", i))))
		}
		if final != "" {
			writes = append(writes, "echo marker >> "+final)
		}
		return strings.Join(writes, " && ")
	}
	// "action" (not "raw_action") is the enforced decision.
	const block, allow = `{"action":"block"`, `{"action":"allow"`
	for _, connector := range []string{"claudecode", "codex"} {
		for _, count := range []int{29, 30, 31, 33, 64, 200} {
			t.Run(fmt.Sprintf("%s %d", connector, count), func(t *testing.T) {
				if err := os.Symlink(keys, link); err != nil && !os.IsExist(err) {
					t.Fatal(err)
				}
				command := chain(count, link)
				header := hookpaths.Resolve(mustJSON(t, map[string]any{"tool_name": "Bash",
					"tool_input": map[string]string{"command": command}}))
				if got := post(t, connector, "action", command, header); !strings.HasPrefix(got, block) ||
					!strings.Contains(got, "persistence.ssh_authorized_keys_command") {
					t.Fatalf("linked append after %d targets = %.400s", count, got)
				}
			})
		}
		t.Run(connector+" benign only", func(t *testing.T) {
			if got := post(t, connector, "action", chain(31, ""), ""); !strings.HasPrefix(got, allow) {
				t.Fatalf("benign targets = %.400s", got)
			}
		})
		t.Run(connector+" unresolved target", func(t *testing.T) {
			header := encodeTargets(t, map[string]string{hookpaths.CWDKey: project, link: ""})
			if got := post(t, connector, "action", "echo marker >> "+link, header); !strings.HasPrefix(got, block) {
				t.Fatalf("unresolved target = %.400s", got)
			}
		})
		t.Run(connector+" undecodable header", func(t *testing.T) {
			if got := post(t, connector, "action", "echo marker >> "+link, "!"); !strings.HasPrefix(got, block) {
				t.Fatalf("undecodable header = %.400s", got)
			}
		})
		t.Run(connector+" truncated observe", func(t *testing.T) {
			header := encodeTargets(t, map[string]string{hookpaths.CWDKey: project, hookpaths.TruncatedKey: "1"})
			if got := post(t, connector, "action", "echo marker >> "+link, header); !strings.HasPrefix(got, block) {
				t.Fatalf("truncated action = %.400s", got)
			}
			if got := post(t, connector, "observe", "echo marker >> "+link, header); !strings.HasPrefix(got, allow) ||
				!strings.Contains(got, `"would_block":true`) {
				t.Fatalf("truncated observe = %.400s", got)
			}
		})
	}
}

func encodeTargets(t *testing.T, targets map[string]string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(mustJSON(t, targets))
}

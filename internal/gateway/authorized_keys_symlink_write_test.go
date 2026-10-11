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
	"slices"
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
		{"sed", "ln -s ~/.ssh/authorized_keys ./ak.lnk; sed -i s/old/new/ ./ak.lnk", false},
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
	// A hard link is a regular file with the protected file's identity.
	hardLink := filepath.Join(external, "hard.cfg")
	if err := os.Link(keys, hardLink); err != nil {
		t.Fatal(err)
	}
	// Valid 17-link chain, and a 41-link chain past the kernel limit that the
	// hook reports unresolvable.
	chain := func(prefix string, links int) string {
		next := keys
		for i := links - 1; i >= 0; i-- {
			link := filepath.Join(external, fmt.Sprintf("%s-%02d", prefix, i))
			if err := os.Symlink(next, link); err != nil {
				t.Fatal(err)
			}
			next = link
		}
		return next
	}
	chain17, chain41 := chain("c17", 17), chain("c41", 41)
	t.Setenv("HOME", home)
	t.Chdir(project)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	symlinkKeys := func(link string) error { return os.Symlink(keys, link) }
	symlinkTo := func(target string) func(string) error {
		return func(link string) error { return os.Symlink(target, link) }
	}
	for _, row := range []struct {
		name, link string
		count      int
		block      bool
		relink     func(string) error
		resolved   string
	}{
		{"external one", externalLink, 0, true, symlinkKeys, keys},
		{"external thirty one", externalLink, 31, true, symlinkKeys, keys},
		{"external thirty three", externalLink, 33, true, symlinkKeys, keys},
		{"home link", homeLink, 0, true, symlinkKeys, keys},
		{"relative link", "./relative", 0, true, symlinkKeys, keys},
		{"hard link", hardLink, 0, true, func(link string) error { return os.Link(keys, link) }, keys},
		{"seventeen link chain", chain17, 0, true, symlinkTo(filepath.Join(external, "c17-01")), keys},
		{"forty one link chain", chain41, 0, true, symlinkTo(filepath.Join(external, "c41-01")), ""},
		{"benign home", filepath.Join(project, "notes.txt"), 0, false, nil, ""},
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
				if got, present := targets[operand]; row.count < hookpaths.MaxWriteTargets && (!present || got != row.resolved) {
					t.Fatalf("resolved operand = %q (present %v), want %q", got, present, row.resolved)
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
					if err := row.relink(row.link); err != nil {
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
		// The whole command up to the hook payload cap is walked for redirect
		// operands, past the 64 KiB ActionFacts limit; an operand neither side
		// can list makes the decision unknown (GAP-1395).
		t.Run(connector+" over analysis limits", func(t *testing.T) {
			prefix := ": " + strings.Repeat("x", 65<<10) + " && "
			for _, row := range []struct {
				command string
				block   bool
			}{
				{prefix + "echo marker >> " + link, true},
				{chain(200, "") + " && L=" + link + " && echo marker >> \"$L\"", true},
				{prefix + "echo marker > " + filepath.Join(external, "notes.txt"), false},
			} {
				if err := os.Symlink(keys, link); err != nil && !os.IsExist(err) {
					t.Fatal(err)
				}
				header := hookpaths.Resolve(mustJSON(t, map[string]any{"tool_name": "Bash",
					"tool_input": map[string]string{"command": row.command}}))
				want := allow
				if row.block {
					want = block
				}
				if got := post(t, connector, "action", row.command, header); !strings.HasPrefix(got, want) {
					t.Fatalf("%.60s...%s = %.400s", row.command, row.command[len(row.command)-60:], got)
				}
			}
		})
		// A redirect word is spelled the way the shell opens it (GAP-1396).
		t.Run(connector+" quoted and escaped names", func(t *testing.T) {
			spaced := filepath.Join(external, "key file")
			for _, word := range []string{`key\ file`, `"key file"`, `'key file'`, `$'key\x20file'`} {
				if err := os.Symlink(keys, spaced); err != nil && !os.IsExist(err) {
					t.Fatal(err)
				}
				command := chain(200, "") + " && echo marker >> " + external + "/" + word
				header := hookpaths.Resolve(mustJSON(t, map[string]any{"tool_name": "Bash",
					"tool_input": map[string]string{"command": command}}))
				if err := os.Remove(spaced); err != nil {
					t.Fatal(err)
				}
				if got := post(t, connector, "action", command, header); !strings.HasPrefix(got, block) {
					t.Fatalf("append through %s = %.400s", word, got)
				}
			}
		})
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

// TestAuthorizedKeys2LinkWriteMatchesDirectWrite covers links to
// ~/.ssh/authorized_keys2, which the direct-write rule protects but the link
// checks compared only with authorized_keys (GAP-1370).
func TestAuthorizedKeys2LinkWriteMatchesDirectWrite(t *testing.T) {
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
	keys2 := filepath.Join(home, ".ssh", "authorized_keys2")
	t.Setenv("HOME", home)
	t.Chdir(project)
	symlink := func(target string) func(string) error {
		return func(link string) error { return os.Symlink(target, link) }
	}
	// "action" (not "raw_action") is the enforced decision.
	const block, allow = `{"action":"block"`, `{"action":"allow"`
	for _, connector := range []string{"claudecode", "codex"} {
		for _, row := range []struct {
			name, link, operand string
			existing            bool
			create              func(string) error
			want                string
		}{
			{"link to missing file", filepath.Join(external, "kmiss"), "", false, symlink(keys2), block},
			{"link to existing file", filepath.Join(external, "kfile"), "", true, symlink(keys2), block},
			{"relative link", filepath.Join(project, "krel"), "./krel", true,
				symlink(filepath.Join("..", ".ssh", "authorized_keys2")), block},
			{"hard link", filepath.Join(external, "hard.cfg"), "", true,
				func(link string) error { return os.Link(keys2, link) }, block},
			{"direct write", "", keys2, true, nil, block},
			{"benign file", "", filepath.Join(external, "notes.txt"), false, nil, allow},
		} {
			for _, count := range []int{1, 31} {
				t.Run(fmt.Sprintf("%s %s %d", connector, row.name, count), func(t *testing.T) {
					_ = os.Remove(keys2)
					if row.existing {
						if err := os.WriteFile(keys2, []byte("marker\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					operand := row.operand
					if operand == "" {
						operand = row.link
					}
					if row.create != nil {
						if err := row.create(row.link); err != nil {
							t.Fatal(err)
						}
					}
					writes := make([]string, 0, count+1)
					for i := range count {
						writes = append(writes, fmt.Sprintf("echo x > %s", filepath.Join(external, fmt.Sprintf("t%02d", i))))
					}
					command := strings.Join(append(writes, "echo marker >> "+operand), " && ")
					body := mustJSON(t, map[string]any{"session_id": "marker-session", "hook_event_name": "PreToolUse",
						"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command, "description": "d"}})
					header := hookpaths.Resolve(body)
					// The managed gateway may not see the caller's link: keep
					// only the hook client's header evidence.
					if row.create != nil {
						if err := os.Remove(row.link); err != nil {
							t.Fatal(err)
						}
					}
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
					req.Header.Set(hookpaths.Header, header)
					if connector == "codex" {
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
					}
					req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
					recorder := httptest.NewRecorder()
					api.handleAgentHook(connector).ServeHTTP(recorder, req)
					got := recorder.Body.String()
					if !strings.HasPrefix(got, row.want) ||
						row.want == block && !strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Fatalf("append after %d targets = %.400s, want %s", count, got, row.want)
					}
				})
			}
		}
	}
}

func encodeTargets(t *testing.T, targets map[string]string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(mustJSON(t, targets))
}

// A link the command creates and the hook cannot read makes the write
// targets unknown. The per-user gateway, which resolves targets itself,
// fails closed on it as the managed gateway does (GAP-1521, GAP-1522);
// ordinary commands, also with a program word that is not static, stay
// allowed (GAP-1523).
func TestCommandLinkWriteFailsClosedInEveryMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hook paths")
	}
	home := filepath.Join(t.TempDir(), "home")
	project := filepath.Join(home, "proj")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Chdir(project)
	if err := os.Symlink(keys, filepath.Join(project, "disklink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(keys), filepath.Join(project, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "report.txt"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(project, "report.txt"), filepath.Join(project, "reportlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.DevNull, filepath.Join(project, "devlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(project, "tree"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "tree", "k")); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"outlink": "unpack/n", "dlink": "unpack"} {
		if err := os.Symlink(target, filepath.Join(project, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(project, "unpack"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../report.txt", filepath.Join(project, "unpack", "existing")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("unpack/existing", filepath.Join(project, "outlink2")); err != nil {
		t.Fatal(err)
	}
	// GAP-1556: these links predate the command. The kernel traverses b
	// before applying the ".." in l's target.
	for _, dir := range []string{filepath.Join(project, "a"), filepath.Join(home, ".ssh", "d"),
		filepath.Join(project, "a2"), filepath.Join(project, "unpack", "q", "r"),
		filepath.Join(project, "build"), filepath.Join(home, "shared")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []struct{ name, target string }{
		{filepath.Join(project, "a", "b"), filepath.Join(home, ".ssh", "d")},
		{filepath.Join(project, "a", "l"), filepath.FromSlash("b/../authorized_keys")},
		{filepath.Join(project, "a2", "b"), filepath.FromSlash("../unpack/q/r")},
		{filepath.Join(project, "a2", "l"), filepath.FromSlash("b/../t")},
	} {
		if err := os.Symlink(link.target, link.name); err != nil {
			t.Fatal(err)
		}
	}
	big := filepath.Join(project, "big")
	if err := os.MkdirAll(big, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4097; i++ {
		if err := os.WriteFile(filepath.Join(big, fmt.Sprintf("file-%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	blocked := []string{
		// GAP-1561: literal interpreter and in-place operands follow existing links.
		`python3 -c 'open("disklink","a").write("k")'`,
		`perl -e 'open F,">>","disklink"; print F "k"'`,
		`awk 'BEGIN {print "k" >> "disklink"}'`,
		`sed -i --follow-symlinks 's/marker/k/' disklink`,
		`python3 -c 'open("dirlink/authorized_keys","a").write("k")'`,
		`ruby -e 'File.write("disklink","k")'`,
		`node -e 'fs.appendFileSync("disklink","k")'`,
		`python3 -c 'open("disklink","w").write("k")'`,
		`python3 -c 'open("disklink","r+").write("k")'`,
		`python3 -c 'import os; os.open("disklink",os.O_WRONLY|os.O_APPEND)'`,
		`python3 -c 'from pathlib import Path; Path("disklink").write_text("k")'`,
		// GAP-1545: every archive destination spelling must cover the later write.
		`tar -xf keys.tar -C../out && echo k >> ../out/n`,
		`tar -xC ../out -f keys.tar && echo k >> ../out/n`,
		`tar xfC keys.tar ../out && echo k >> ../out/n`,
		`tar -xf keys.tar --dir=../out && echo k >> ../out/n`,
		`tar -xf keys.tar --direc ../out && echo k >> ../out/n`,
		`bsdtar -xf keys.tar --cd ../out && echo k >> ../out/n`,
		`X=1 tar -xf keys.tar -C../out; echo k >> ../out/n`,
		`tar -x -f keys.tar --one-top-level=../out; echo k >> ../out/n`,
		`unzip keys.zip -d../out && echo k >> ../out/n`,
		// GAP-1546: a pre-existing alias can enter an extraction scope.
		`tar -C unpack -xf evil.tar && echo k >> outlink`,
		`tar -C unpack -xf evil.tar && echo k >> dlink/n`,
		`tar -C unpack -xf evil.tar && echo k >> outlink2`,
		// GAP-1556: a pre-existing directory link precedes ".." in another link.
		`echo k >> a/l`,
		`cp x a/l`,
		`tee -a a/l < x`,
		`ln -s b/../authorized_keys a/new && echo k >> a/new`,
		`tar -C unpack -xf evil.tar && echo k >> a2/l`,
		// GAP-1547: an early redirect does not exempt later command writers.
		`echo a > n1.txt; tar xf evil.tar; cp payload n1.txt`,
		`echo a > n1.txt; tar xf evil.tar; dd if=payload of=n1.txt`,
		`echo a > n1.txt; tar xf evil.tar && tee -a n1.txt < payload`,
		// GAP-1548: cp long options and target-directory preserve link scopes.
		`ln -s ~/.ssh/authorized_keys s && cp --archive s notes.txt && echo k >> notes.txt`,
		`ln -s ~/.ssh/authorized_keys s && cp --recursive s d && echo k >> d`,
		`ln -s ~/.ssh/authorized_keys s && cp -a -t copy s && echo k >> copy/s`,
		`cp --archive disklink notes.txt && echo k >> notes.txt`,
		`cp -a disklink notes.txt && cp payload notes.txt`,
		`cp --recursive tree copy && echo k >> copy/k`,
		`cp -a -t copy tree && echo k >> copy/tree/k`,
		`cp --archive --target-directory=copy tree && echo k >> copy/tree/k`,
		`cp --archive --target-directory copy tree && echo k >> copy/tree/k`,
		`cp --arch disklink notes.txt && echo k >> notes.txt`,
		`cp --unknown-option disklink notes.txt && echo k >> notes.txt`,
		`cp --no-dereference disklink notes.txt && echo k >> notes.txt`,
		`cp --preserve=links disklink notes.txt && echo k >> notes.txt`,
		`env ln ~/.ssh/autho""rized_keys notes.txt && echo k >> notes.txt`,
		`sudo ln ~/.ssh/authorized_keys notes.txt && echo k >> notes.txt`,
		`sh -c "ln ~/.ssh/authorized_keys notes.txt" && echo k >> notes.txt`,
		`eval ln ~/.ssh/authorized_keys notes.txt; echo k >> notes.txt`,
		`ln ~/.ssh/authorized_keys n0.txt && mv n0.txt notes.txt && echo k >> notes.txt`,
		`cd .. && ln -s .ssh/authorized_keys proj/notes.txt && cd proj && echo k >> notes.txt`,
		`python3 -c "import os; os.link('../.ssh/authorized_keys', 'notes.txt')"; echo k >> notes.txt`,
		`mklink /H notes.txt keys; echo k >> notes.txt`,
		`pwsh -c "New-Item -ItemType HardLink -Path notes.txt -Target ../.ssh/authorized_keys"; echo k >> notes.txt`,
		`busybox ln ~/.ssh/autho""rized_keys notes.txt && echo k >> notes.txt`,
		`toybox ln ~/.ssh/authorized_keys notes.txt && echo k >> notes.txt`,
		`rsync -a --link-dest=$HOME/.ssh $HOME/.ssh/ d/; echo k >> d/autho""rized_keys`,
		`ls ~/.ssh/authorized_keys | cpio -pdl d; echo k >> d/notes.txt`,
		`pax -rwl ~/.ssh d; echo k >> d/notes.txt`,
		`"$PY" -V; ln ~/.ssh/authorized_keys notes.txt && echo k >> notes.txt`,
		`ln -s ~/.ssh/authorized_keys s && cp -a s notes.txt && echo k >> notes.txt`,
		`ln -s ~/.ssh/authorized_keys s && cp -P s notes.txt && echo k >> notes.txt`,
		`cp -a disklink notes.txt && echo k >> notes.txt`,
		`ln -s ~/.ssh/authorized_keys s && cp -d s notes.txt && echo k >> notes.txt`,
		`ln -s ~/.ssh/authorized_keys s && cp "$FLAGS" s notes.txt && echo k >> notes.txt`,
		`ln -s ~/.ssh/authorized_keys s && cp -R s notes.txt && echo k >> notes.txt`,
		`ln -s ~/.ssh/authorized_keys s && rsync -a s notes.txt && echo k >> notes.txt`,
		`ln -s ~/.ssh/authorized_keys s && rsync -l s notes.txt && echo k >> notes.txt`,
		`ln -s ~/.ssh/authorized_keys s && echo s | cpio -pd d && echo k >> d/s`,
		`ln -s ~/.ssh/authorized_keys s && pax -rw s d && echo k >> d/s`,
		`cpio -id < keys.cpio; echo k >> notes.txt`,
		`pax -r -f keys.pax; echo k >> notes.txt`,
		`pax -r < keys.pax; echo k >> notes.txt`,
		`bsdcpio -id < keys.cpio; echo k >> notes.txt`,
		`unzip -o keys.zip; echo k >> notes.txt`,
		`7z x keys.7z; echo k >> notes.txt`,
		`7z x keys.7z -o../outside; echo k >> ../outside/n`,
		`cpio -id -D ../outside < keys.cpio; echo k >> ../outside/n`,
		`busybox cpio -i < keys.cpio; echo k >> notes.txt`,
		`busybox unzip keys.zip; echo k >> notes.txt`,
		`tar $X keys.tar; echo k >> notes.txt`,
		`tar -$X -f keys.tar; echo k >> notes.txt`,
		`tar xzf node.tgz && ./configure > build.log`,
		`tar xzf x.tgz && ./configure > build.log`,
		`tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`,
		`for i in 1 2; do echo k >> notes.txt; tar xf keys.tar; done`,
		`echo "$(tar xf keys.tar)" > notes.txt`,
		`c"d" ~/.ssh && echo k >> authorized_keys`,
		`"c""d" ~/.ssh && echo k >> authorized_keys`,
		`$'cd' ~/.ssh && echo k >> authorized_keys`,
		`\cd ~/.ssh && echo k >> authorized_keys`,
		`"cd" "$HOME"/.ssh && echo k >> authorized_keys`,
		`builtin cd ~/.ssh && echo k >> authorized_keys`,
		`command cd ~/.ssh && echo k >> authorized_keys`,
		`cd ~ && cd .ssh && echo k >> authorized_keys`,
		`ln -sfn ~/.ssh/authorized_keys devlink && echo k >> devlink`,
		"python3 - <<EOF\nimport os\nos.symlink(os.path.expanduser(~/.ssh/authorized_keys), notes.txt)\nEOF\necho k >> notes.txt",
		`sudo python3 -c 'import os; os.symlink("../.ssh/authorized_keys", "notes.txt")' && echo k >> notes.txt`,
		`cd ~/x && tar -C ~/x -xf keys.tar && echo k >> n1.txt`,
		`cpio -id -D unpack < keys.cpio; echo k >> notes.txt`,
		`tar -P -C unpack -xf keys.tar; echo k >> notes.txt`,
		`cp -a tree copy && echo k >> copy/k`,
		`cd -P ~/.ssh && echo k >> authorized_keys`,
		`cd ~/.ssh || exit 1; echo k >> authorized_keys`,
	}
	allowed := []string{
		// Reads, unrelated targets and sed's default link replacement are safe.
		`python3 -c 'open("disklink","r").read()'`,
		`python3 -c 'import os; os.open("disklink",os.O_RDONLY)'`,
		`python3 -c 'open("report.txt","a").write("k")'`,
		`python3 -c 'open("reportlink","a").write("k")'`,
		`awk 'BEGIN {print "k" >> "reportlink"}'`,
		`sed -i 's/marker/k/' disklink`,
		`ln -s ~/.ssh/authorized_keys freshlink; sed -i 's/marker/k/' freshlink`,
		`sed -i --follow-symlinks 's/marker/k/' reportlink`,
		// GAP-1549: the copy's own destination is an allowed write.
		`cp -r big copy3`,
		`cp -a tree copy4`,
		`cp -r big copy6 && echo done > report.txt`,
		`cp --archive disklink notes.txt`,
		`cp --recursive tree copy`,
		`cp -a -t copy tree`,
		// Ordinary ".." and a link without a following ".." stay resolvable.
		`cd build && cat ../README.md > ../out.txt`,
		`ln -s ../shared lib && cat lib/x`,
		// Extraction alone, listing, an extractor redirect and earlier writes.
		`tar xzf x.tgz`,
		`tar -t -f keys.tar`,
		`unzip -l keys.zip`,
		`tar -xzf pkg.tgz 2>/dev/null`,
		`echo hi > build.log; tar xzf x.tgz`,
		`go build ./... > build.log`,
		`ln a.txt b.txt && echo k >> b.txt`,
		`rsync -a src/ d/ && echo k >> d/log.txt`,
		`tar czf out.tgz src && echo k >> log.txt`,
		`busybox ls > list.txt`,
		`tar -xzf pkg.tgz 2>/dev/null`,
		`tar xf keys.tar; echo hi > /dev/null`,
		`tar -xvf a.tar > files.txt`,
		`echo hi > out.txt; tar xf a.tar`,
		`rsync -aH src/ dst/ > rsync.log`,
		`rsync -a --link-dest=../prev src/ cur/ 2>/dev/null`,
		`sudo ln -s /opt/x /usr/local/bin/x > /dev/null`,
		`grep -rn "os.symlink(" src > hits.txt`,
		`rg mklink docs > hits.txt`,
		`echo "use mklink /D" > notes.md`,
		`printf "fsutil hardlink" > notes.md`,
		`echo s | cpio -o > archive.cpio`,
		`pax -w -f archive.pax > listing.txt`,
		`unzip -l keys.zip > listing.txt`,
		`7z l keys.7z > listing.txt`,
		`tar "$o" xenial.tar > log`,
		`tar -C unpack -xf keys.tar; echo hi > report.txt`,
		`7z x keys.7z -o../outside; echo hi > report.txt`,
		`cp -a src dst && echo hi > report.txt`,
		`grep -rn "os.symlink(" src | head -5 > hits.txt`,
	}
	// The managed gateway also fails closed on a program word that is not
	// static, which this change leaves as it is.
	allowedPerUser := []string{`"$PY" x.py > out.txt`, `bash -lc "cp a b" > out.txt`}
	// "action" (not "raw_action") is the enforced decision.
	const block, allow = `{"action":"block"`, `{"action":"allow"`
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{true, false} {
			post := func(t *testing.T, command string) string {
				t.Helper()
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = connector
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				body := mustJSON(t, map[string]any{"session_id": "marker-session", "hook_event_name": "PreToolUse",
					"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command, "description": "d"}})
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
				req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
				if connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				if managed {
					req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook(connector).ServeHTTP(recorder, req)
				return recorder.Body.String()
			}
			name := fmt.Sprintf("%s managed=%v", connector, managed)
			t.Run(name, func(t *testing.T) {
				for _, command := range blocked {
					got := post(t, command)
					if !strings.HasPrefix(got, block) ||
						!strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%s = %.300s, want block", command, got)
					}
					if command == `tar xzf node.tgz && ./configure > build.log` &&
						!strings.Contains(got, "run the extraction and the write as separate commands") {
						t.Errorf("%s = %.300s, want archive chain guidance", command, got)
					}
				}
				expectAllowed := allowed
				if !managed {
					expectAllowed = append(slices.Clone(allowed), allowedPerUser...)
				}
				for _, command := range expectAllowed {
					if got := post(t, command); !strings.HasPrefix(got, allow) {
						t.Errorf("%s = %.300s, want allow", command, got)
					}
				}
			})
		}
	}
}

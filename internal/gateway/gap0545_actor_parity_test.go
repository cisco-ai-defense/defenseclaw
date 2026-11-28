// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// gap0545Shape is one connector's shell tool hook call (the RKGUESTRES
// connector rows): the hook route, the bound event header and the body.
type gap0545Shape struct {
	name, connector, header, event string
	body                           func(command, cwd string) map[string]any
}

func gap0545Shapes() []gap0545Shape {
	return []gap0545Shape{
		{"claude Bash command", "claudecode", "", "PreToolUse", func(c, d string) map[string]any {
			return map[string]any{"hook_event_name": "PreToolUse", "session_id": "s", "cwd": d, "tool_name": "Bash", "tool_input": map[string]any{"command": c}}
		}},
		{"codex exec_command cmd", "codex", "X-DefenseClaw-Hook-Event", "PreToolUse", func(c, d string) map[string]any {
			return map[string]any{"hook_event_name": "PreToolUse", "session_id": "s", "turn_id": "t", "cwd": d, "tool_name": "exec_command", "tool_input": map[string]any{"cmd": c, "workdir": d}}
		}},
		{"codex Bash command", "codex", "X-DefenseClaw-Hook-Event", "PreToolUse", func(c, d string) map[string]any {
			return map[string]any{"hook_event_name": "PreToolUse", "session_id": "s", "turn_id": "t", "cwd": d, "tool_name": "Bash", "tool_input": map[string]any{"command": c}}
		}},
		{"amp Bash cmd", "amp", "", "tool.call", func(c, d string) map[string]any {
			return map[string]any{"hook_event_name": "tool.call", "session_id": "s", "thread_id": "s", "tool_call_id": "c", "cwd": d, "tool_name": "Bash", "tool_input": map[string]any{"cmd": c, "cwd": d}}
		}},
		{"opencode bash command", "opencode", "", "tool.execute.before", func(c, d string) map[string]any {
			return map[string]any{"hook_event_name": "tool.execute.before", "session_id": "s", "cwd": d, "tool_name": "bash", "tool_input": map[string]any{"command": c}}
		}},
		{"cursor beforeShellExecution", "cursor", "", "beforeShellExecution", func(c, d string) map[string]any {
			return map[string]any{"hook_event_name": "beforeShellExecution", "conversation_id": "c", "generation_id": "g", "command": c, "cwd": d}
		}},
	}
}

func gap0545Verdict(t *testing.T, api *APIServer, ctx context.Context, s gap0545Shape, body []byte) (string, []string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+s.connector+"/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if s.header != "" {
		req.Header.Set(s.header, s.event)
	}
	if s.connector == "codex" {
		setTestCodexHookBinding(req, s.event, defaultTestCodexHookContract)
	}
	rec := httptest.NewRecorder()
	api.handleAgentHook(s.connector).ServeHTTP(rec, req.WithContext(ctx))
	var out struct {
		Action  string   `json:"action"`
		RuleIDs []string `json:"rule_ids"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("%s: hook status=%d: %.400s", s.name, rec.Code, rec.Body.String())
	}
	slices.Sort(out.RuleIDs)
	return out.Action, slices.Compact(out.RuleIDs)
}

// gap0545Rank orders verdicts: allow, allow with a rule, alert, block.
func gap0545Rank(action string, rules []string) int {
	switch action {
	case "allow":
		if len(rules) > 0 {
			return 1
		}
		return 0
	case "block", "deny":
		return 3
	}
	return 2
}

// gap0545KitFacts are the facts the actor's kit collects for a call made in
// home's layout, reported in the guest's namespace (home -> /sandbox).
func gap0545KitFacts(t *testing.T, connectorName, event string, hostBody []byte, home string) *SubstrateFacts {
	t.Helper()
	collected := kit.CollectFacts(connectorName, event, hostBody, 1<<20)
	if collected == nil {
		return nil
	}
	raw, err := json.Marshal(collected)
	if err != nil {
		t.Fatal(err)
	}
	var facts SubstrateFacts
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), home, sandboxauth.SandboxHome)), &facts); err != nil {
		t.Fatal(err)
	}
	return &facts
}

// gap0545Actor is the copy-mode actor's context for one call with facts.
func gap0545Actor(actor context.Context, connectorName, event string, payload []byte, facts *SubstrateFacts) context.Context {
	env := substrateEnvelope{V: "1", Connector: connectorName, Event: event, Mode: "interactive", Payload: payload, Facts: facts}
	return withSubstrateGuestClaims(context.WithValue(actor, substrateEnvelopeKey{}, env), env)
}

// gap0545API is a gateway for connectorName with the pack's rules in an
// unprivileged home of the J19 layout and its actor context.
func gap0545API(t *testing.T, connectorName, pack string) (api *APIServer, actor context.Context, home, app string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connectorName, pack)
	home = filepath.Join(t.TempDir(), "home", "alice")
	app = gap0471Layout(t, home)
	gap0546ExtraLayout(t, home, app)
	t.Setenv("HOME", home)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePack = pack
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
	api = &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	binding := sandboxTestBinding(connectorName)
	actor = withProfilePath(withAuthenticatedHookConnector(sandboxauth.WithRequest(context.Background(), binding, nil), binding.Connector), profilePathHook)
	return api, actor, home, app
}

// gap0546ExtraLayout adds the RKGUESTRES links to DefenseClaw state and the
// hook configs, and a private backup folder.
func gap0546ExtraLayout(t *testing.T, home, app string) {
	t.Helper()
	for name, content := range map[string]string{".claude/settings.json": "{}\n", ".defenseclaw/config.yaml": "a: 1\n"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(home, "bak"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"dc-link": "../.defenseclaw/config.yaml", "claude-dir": "../.claude"} {
		if err := os.Symlink(target, filepath.Join(app, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestGAP0545ActorShellToolsOfEveryConnectorKeepLaptopVerdict: a Codex
// exec_command (cmd), Amp Bash (cmd), OpenCode bash and Cursor
// beforeShellExecution actor gets the kit's proofs for its shell command as
// Claude Code's and Codex's Bash do: cat key-link, cat a/b/ssh/id_ed25519,
// cd a/b/ssh && cat id_ed25519, cat ./a/../key-link and echo k >> ak-link
// block as on the laptop (substrate-1 GAP-0545: the actor allowed every row).
func TestGAP0545ActorShellToolsOfEveryConnectorKeepLaptopVerdict(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	for _, s := range gap0545Shapes() {
		t.Run(s.name, func(t *testing.T) {
			api, actor, home, app := gap0545API(t, s.connector, "default")
			for _, command := range []string{"cat key-link", "cat a/b/ssh/id_ed25519", "cd a/b/ssh && cat id_ed25519",
				"cat ./a/../key-link", "echo k >> ak-link", "cat readme-link"} {
				host, _ := json.Marshal(s.body(command, app))
				guest, _ := json.Marshal(s.body(command, sandboxauth.SandboxHome+"/app"))
				la, lr := gap0545Verdict(t, api, context.Background(), s, host)
				facts := gap0545KitFacts(t, s.connector, s.event, host, home)
				ca, cr := gap0545Verdict(t, api, gap0545Actor(actor, s.connector, s.event, guest, facts), s, guest)
				switch {
				case command == "cat readme-link":
					if ca != la || !slices.Equal(cr, lr) {
						t.Errorf("%q: benign: actor %s %v, laptop %s %v", command, ca, cr, la, lr)
					}
				case gap0545Rank(la, lr) != 3:
					t.Errorf("%q: laptop %s %v, want a block (the test layout is wrong)", command, la, lr)
				case gap0545Rank(ca, cr) < gap0545Rank(la, lr):
					t.Errorf("%q: actor %s %v is weaker than the laptop's %s %v", command, ca, cr, la, lr)
				default:
					for _, rule := range lr {
						if !slices.Contains(cr, rule) {
							t.Errorf("%q: actor %s %v does not name the laptop's %s", command, ca, cr, rule)
						}
					}
				}
			}
		})
	}
}

// gap0545FileShapes are connectors' file tool calls of one path.
func gap0545FileShapes() []gap0545Shape {
	return []gap0545Shape{
		{"claude Read", "claudecode", "", "PreToolUse", func(p, d string) map[string]any {
			return map[string]any{"hook_event_name": "PreToolUse", "session_id": "s", "cwd": d, "tool_name": "Read", "tool_input": map[string]any{"file_path": p}}
		}},
		{"cursor beforeReadFile", "cursor", "", "beforeReadFile", func(p, d string) map[string]any {
			return map[string]any{"hook_event_name": "beforeReadFile", "conversation_id": "c", "generation_id": "g", "file_path": p, "content": "", "cwd": d}
		}},
		{"cursor preToolUse Read", "cursor", "", "preToolUse", func(p, d string) map[string]any {
			return map[string]any{"hook_event_name": "preToolUse", "conversation_id": "c", "generation_id": "g", "tool_name": "Read", "tool_input": map[string]any{"path": p}, "tool_use_id": "u", "cwd": d}
		}},
		{"opencode read filePath", "opencode", "", "tool.execute.before", func(p, d string) map[string]any {
			return map[string]any{"hook_event_name": "tool.execute.before", "session_id": "s", "cwd": d, "tool_name": "read", "tool_input": map[string]any{"filePath": p}}
		}},
		{"amp Read path", "amp", "", "tool.call", func(p, d string) map[string]any {
			return map[string]any{"hook_event_name": "tool.call", "session_id": "s", "thread_id": "s", "tool_call_id": "c", "cwd": d, "tool_name": "Read", "tool_input": map[string]any{"path": p}}
		}},
		{"codex apply_patch", "codex", "X-DefenseClaw-Hook-Event", "PreToolUse", func(p, d string) map[string]any {
			return map[string]any{"hook_event_name": "PreToolUse", "session_id": "s", "turn_id": "t", "cwd": d, "tool_name": "apply_patch",
				"tool_input": map[string]any{"command": "*** Begin Patch\n*** Add File: " + p + "\n+ssh-ed25519 AAAA x\n*** End Patch\n"}}
		}},
	}
}

// TestGAP0545ActorFileToolsOfEveryConnectorKeepLaptopVerdict: a file tool
// call through a link (a Cursor beforeReadFile, which has no tool_input, and
// a Codex apply_patch that adds a file through a link) is never weaker than
// on the laptop and names its rules; a plain file gets the laptop's exact
// answer (substrate-1 GAP-0545: beforeReadFile and apply_patch were allowed).
func TestGAP0545ActorFileToolsOfEveryConnectorKeepLaptopVerdict(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	for _, s := range gap0545FileShapes() {
		t.Run(s.name, func(t *testing.T) {
			api, actor, home, app := gap0545API(t, s.connector, "default")
			for _, file := range []string{"key-link", "a/b/ssh/id_ed25519", "a/b/ssh/../.ssh/id_ed25519", "ak-link", "README.md"} {
				host, _ := json.Marshal(s.body(file, app))
				guest, _ := json.Marshal(s.body(file, sandboxauth.SandboxHome+"/app"))
				la, lr := gap0545Verdict(t, api, context.Background(), s, host)
				facts := gap0545KitFacts(t, s.connector, s.event, host, home)
				ca, cr := gap0545Verdict(t, api, gap0545Actor(actor, s.connector, s.event, guest, facts), s, guest)
				if file == "README.md" {
					if ca != la || !slices.Equal(cr, lr) {
						t.Errorf("%q: benign: actor %s %v, laptop %s %v", file, ca, cr, la, lr)
					}
					continue
				}
				if gap0545Rank(ca, cr) < gap0545Rank(la, lr) {
					t.Errorf("%q: actor %s %v is weaker than the laptop's %s %v", file, ca, cr, la, lr)
				}
				for _, rule := range lr {
					if !slices.Contains(cr, rule) {
						t.Errorf("%q: actor %s %v does not name the laptop's %s (%s %v)", file, ca, cr, rule, la, lr)
					}
				}
			}
		})
	}
}

// gap0546Row is one RKGUESTRES Claude Code row whose actor verdict must be
// the laptop's: exact when exact is set (an alert stays an alert), else
// never weaker and naming every laptop rule.
type gap0546Row struct {
	tool, input string
	exact       bool
}

func gap0546Rows() []gap0546Row {
	return []gap0546Row{
		// GAP-0546: a `..` after a symlinked folder, cd -P and eval.
		{tool: "Read", input: "a/b/ssh/../.ssh/id_ed25519"},
		{tool: "Bash", input: "cat a/b/ssh/../.ssh/id_ed25519"},
		{tool: "Bash", input: "cd -P a/b/ssh && cat id_ed25519"},
		{tool: "Bash", input: "eval cat a/b/ssh/id_ed25519"},
		{tool: "Bash", input: `eval "cat key-link"`},
		{tool: "Bash", input: `bash -c 'cat key-link'`},
		// GAP-0547: shell writes through a link to DefenseClaw state and
		// to a hook config.
		// rel 1.0.11 (DET111) alerts tamper.detector_state_write here on the laptop; the actor keeps that verdict.
		{tool: "Bash", input: "echo x >> dc-link", exact: true},
		{tool: "Bash", input: "echo x > claude-dir/settings.json", exact: true},
		{tool: "Bash", input: "cp /tmp/x claude-dir/settings.local.json", exact: true},
		// GAP-0549 (a): a copy of the user's own key or SSH folder to a
		// private place of the home alerts, as on the laptop.
		{tool: "Bash", input: "cp key-link ~/bak/key", exact: true},
		{tool: "Bash", input: "cp -r ~/.ssh ~/sshbak", exact: true},
		// Benign: the laptop's exact answer.
		{tool: "Bash", input: "ls -l key-link", exact: true},
		{tool: "Bash", input: "cat readme-link", exact: true},
		{tool: "Bash", input: "cd docs-link && cat README.md", exact: true},
		{tool: "Bash", input: "rm -f readme-link", exact: true},
		{tool: "Bash", input: "readlink key-link", exact: true},
		{tool: "Bash", input: "cp readme-link ~/bak/r.md", exact: true},
		{tool: "Bash", input: "echo hi > notes-link.txt", exact: true},
	}
}

// TestGAP0546GAP0547ActorLinkFormsKeepLaptopVerdict: in a Claude Code actor
// Read a/b/ssh/../.ssh/id_ed25519, cd -P a/b/ssh && cat id_ed25519, eval cat
// a/b/ssh/id_ed25519 and eval "cat key-link" read the key and block as on
// the laptop (substrate-1 GAP-0546: allowed or only CMD-EVAL); echo x >>
// dc-link alerts tamper.detector_state_write (an exact-path rule since the
// DET111 carrier test change) and a shell write through a link to ~/.claude
// alerts tamper.agent_hook_config_write, as on the laptop (GAP-0547: allowed); a copy of the key or the SSH folder to a private place
// of the home alerts as on the laptop instead of blocking (GAP-0549 a), in
// every pack, with the kit's honest facts.
func TestGAP0546GAP0547ActorLinkFormsKeepLaptopVerdict(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	claude := gap0545Shapes()[0]
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, home, app := gap0545API(t, "claudecode", pack)
			for _, row := range gap0546Rows() {
				body := func(cwd string) []byte {
					input := map[string]any{"command": row.input}
					if row.tool == "Read" {
						input = map[string]any{"file_path": row.input}
					}
					raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0546", "cwd": cwd,
						"tool_name": row.tool, "tool_input": input, "tool_use_id": "gap0546"})
					return raw
				}
				host, guest := body(app), body(sandboxauth.SandboxHome+"/app")
				la, lr := gap0545Verdict(t, api, context.Background(), claude, host)
				facts := gap0545KitFacts(t, "claudecode", "PreToolUse", host, home)
				ca, cr := gap0545Verdict(t, api, gap0545Actor(actor, "claudecode", "PreToolUse", guest, facts), claude, guest)
				name := row.tool + " " + row.input
				if row.exact {
					if ca != la || !slices.Equal(cr, lr) {
						t.Errorf("%s: actor %s %v, laptop %s %v", name, ca, cr, la, lr)
					}
					continue
				}
				if gap0545Rank(la, lr) != 3 {
					t.Errorf("%s: laptop %s %v, want a block (the test layout is wrong)", name, la, lr)
				}
				if gap0545Rank(ca, cr) < gap0545Rank(la, lr) {
					t.Errorf("%s: actor %s %v is weaker than the laptop's %s %v", name, ca, cr, la, lr)
				}
				for _, rule := range lr {
					if !slices.Contains(cr, rule) {
						t.Errorf("%s: actor %s %v does not name the laptop's %s", name, ca, cr, rule)
					}
				}
			}
		})
	}
}

// TestGAP0548KitClaimsOfAnEnvelopeAreReadInLinearTime: the claims of one
// hook envelope at the middleware's size limit, with ~28,000 path facts on a
// 64 KiB argument, are read at once: an envelope with more facts than the
// kit sends (32) is judged as one with no facts, and one within the cap
// decodes each argument once (substrate-1 GAP-0548: 11.7 s of CPU, and
// 2 min 8 s for a 1000 KiB argument).
func TestGAP0548KitClaimsOfAnEnvelopeAreReadInLinearTime(t *testing.T) {
	value := strings.Repeat("a", 64<<10)
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Read",
		"tool_input": map[string]any{"file_path": value}})
	fact := SubstratePathFact{Field: "tool_input.file_path", Path: "x", Abs: "/a", Resolved: "/b"}
	one, _ := json.Marshal(fact)
	count := int((substrateEnvelopeMaxBytes - int64(len(payload)) - 4096) / int64(len(one)+1))
	facts := &SubstrateFacts{Paths: make([]SubstratePathFact, count)}
	for i := range facts.Paths {
		facts.Paths[i] = fact
	}
	env := substrateEnvelope{V: "1", Connector: "claudecode", Event: "PreToolUse", Payload: payload, Facts: facts}
	if raw, _ := json.Marshal(env); int64(len(raw)) > substrateEnvelopeMaxBytes {
		t.Fatalf("envelope %d bytes is over the limit %d", len(raw), substrateEnvelopeMaxBytes)
	}
	start := time.Now()
	claims := substrateGuestClaimsOf(env)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("reading the claims of %d facts took %s, want well under 2 s", count, elapsed)
	}
	if claims != nil {
		t.Fatalf("claims of an envelope with %d facts = %+v, want none (no facts)", count, claims)
	}
	// Within the cap, every fact naming the argument decodes it once.
	link := SubstratePathFact{Field: "tool_input.file_path", Path: value, Abs: "/sandbox/app/x", Resolved: "/sandbox/.ssh/id_ed25519"}
	env.Facts = &SubstrateFacts{Paths: slices.Repeat([]SubstratePathFact{link}, maxSubstrateGuestPathFacts)}
	start = time.Now()
	claims = substrateGuestClaimsOf(env)
	if elapsed := time.Since(start); elapsed > 2*time.Second || claims == nil || len(claims.links) != maxSubstrateGuestLinkClaims {
		t.Fatalf("%d facts: %s, claims %d, want %d links at once", maxSubstrateGuestPathFacts, elapsed, len(claims.links), maxSubstrateGuestLinkClaims)
	}
	env.Facts = &SubstrateFacts{Paths: slices.Repeat([]SubstratePathFact{link}, maxSubstrateGuestPathFacts+1)}
	if claims := substrateGuestClaimsOf(env); claims != nil {
		t.Fatalf("%d facts: claims %+v, want none", maxSubstrateGuestPathFacts+1, claims)
	}
}

// TestGAP0549AuditFactTokenCutsOnARuneBoundary: a kit-claimed path in an
// audit field keeps valid UTF-8 at the 256-byte cut and carries no control,
// format, line or paragraph separator rune (substrate-1 GAP-0549 b).
func TestGAP0549AuditFactTokenCutsOnARuneBoundary(t *testing.T) {
	long := strings.Repeat("a", 255) + "é" + "tail"
	if got := auditFactToken(long); got != strings.Repeat("a", 255) {
		t.Errorf("cut = %q (%d bytes), want the 255 bytes before é", got, len(got))
	}
	for _, r := range []rune{'\u0085', '\u009b', '\u2028', '\u2029', '\u202e', '\u2066', '\u200b', '\u200f', '\ufeff'} {
		if got := auditFactToken("a" + string(r) + "b"); got != "a_b" {
			t.Errorf("U+%04X: %q, want a_b", r, got)
		}
	}
	if got := auditFactToken("a\xffb"); got != "a_b" {
		t.Errorf("invalid UTF-8: %q, want a_b", got)
	}
	if got := auditFactToken("/sandbox/app/é.txt"); got != "/sandbox/app/é.txt" {
		t.Errorf("plain path: %q", got)
	}
}

// gap0549Forged are forged claim sets for a call: each proof alone and both,
// junk, a truncated set, link claims of every top-level string argument to
// each target, command-word places of every word to each target, private
// home places for every word, and more facts than the kit sends.
func gap0549Forged(input map[string]any) map[string]*SubstrateFacts {
	out := map[string]*SubstrateFacts{
		"key":   {Proofs: []string{kit.ProofPrivateKeyRead}},
		"write": {Proofs: []string{kit.ProofProtectedWrite}},
		"both":  {Proofs: []string{kit.ProofPrivateKeyRead, kit.ProofProtectedWrite}},
		"junk":  {Proofs: []string{"unknown", ""}, Truncated: true},
		"trunc": {Truncated: true},
	}
	command, _ := input["command"].(string)
	words := strings.FieldsFunc(command, func(r rune) bool { return strings.ContainsRune(" ;&|<>()\"'", r) })
	for _, target := range []string{"/sandbox/.ssh/id_ed25519", "/sandbox/app/README.md", "/tmp/benign", "/",
		"/sandbox/.claude/settings.json", "/sandbox/.ssh/authorized_keys", "/dev/null", "/sandbox/bak"} {
		facts := &SubstrateFacts{Proofs: []string{kit.ProofPrivateKeyRead, kit.ProofProtectedWrite}}
		for key, value := range input {
			if text, ok := value.(string); ok && key != "command" {
				facts.Paths = append(facts.Paths, SubstratePathFact{Field: "tool_input." + key, Path: text, Abs: "/sandbox/app/zz-" + key, Resolved: target, Type: "file"})
			}
		}
		for index, word := range words {
			if len(facts.Paths) < maxSubstrateGuestPathFacts {
				facts.Paths = append(facts.Paths, SubstratePathFact{Field: kit.CommandWordField, Path: word,
					Abs: fmt.Sprintf("/sandbox/app/w%d", index), Resolved: target, Entry: target, PrivateHome: true})
			}
		}
		if len(facts.Paths) > 0 {
			out["places:"+target] = facts
		}
	}
	if len(words) > 0 {
		private := &SubstrateFacts{Proofs: []string{kit.ProofPrivateKeyRead, kit.ProofProtectedWrite}}
		for _, place := range []string{"/sandbox/bak/key", "/sandbox/sshbak", "/sandbox/bak", "/tmp/k", "/sandbox/.ssh",
			"/sandbox/bak/id_ed25519", "/sandbox/notes.txt"} {
			private.Paths = append(private.Paths, SubstratePathFact{Field: kit.CommandWordField, Path: words[min(len(words)-1, 1)], Abs: place, PrivateHome: true})
		}
		out["private"] = private
	}
	over := &SubstrateFacts{Proofs: []string{kit.ProofPrivateKeyRead}}
	for range maxSubstrateGuestPathFacts + 1 {
		over.Paths = append(over.Paths, SubstratePathFact{Field: "tool_input.file_path", Path: "x", Abs: "/a", Resolved: "/b"})
	}
	out["over-cap"] = over
	return out
}

// TestGAP0549ForgedKitClaimsNeverWeakenAVerdict: the kit runs as the agent's
// user, so every claim may be forged. For the RKGUESTRES rows (links, own
// home copies, key and authorized-keys writes, budgets, benign calls), in the
// default and strict packs, no forged claim set makes a verdict weaker than
// the same call with no facts, or drops one of its rules (substrate-1
// GAP-0549 e; the review's differential found 0 of 3549 at 6fb680f7d0).
func TestGAP0549ForgedKitClaimsNeverWeakenAVerdict(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	claude := gap0545Shapes()[0]
	commands := []string{
		"cat key-link", "cat a/b/ssh/id_ed25519", "cd a/b/ssh && cat id_ed25519", "cat ./a/../key-link", "echo k >> ak-link",
		"cd -P a/b/ssh && cat id_ed25519", "eval cat a/b/ssh/id_ed25519", `eval "cat key-link"`, "echo x >> dc-link",
		"echo x > claude-dir/settings.json", "cp key-link ~/bak/key", "cp -r ~/.ssh ~/sshbak", "cat ~/.ssh/id_ed25519",
		"cp ~/.ssh/id_ed25519 ~/bak/id_ed25519", "cp ~/.ssh/id_ed25519 /tmp/k", "cp -r ~/.ssh/* ~/bak/",
		"echo k >> ~/.ssh/authorized_keys", "echo x > ~/.claude/settings.json", "echo x > ~/.defenseclaw/config.yaml",
		"rm -rf ~/.defenseclaw", "ln -sf ~/.ssh/authorized_keys /tmp/a && echo k >> /tmp/a", "cat ~/.ssh/id_ed25519 > ~/notes.txt",
		"cp ~/.ssh/id_ed25519 ~/bak/ && chmod 644 ~/bak/id_ed25519", "tar czf /tmp/k.tgz ~/.ssh", "cd /tmp && eval 'x=f; echo m > $x'",
		strings.Repeat("echo x > /tmp/f; ", 150) + "echo k >> ~/.ssh/authorized_keys",
		"ls", "cat README.md", "cat readme-link", "ls -l key-link", "cd docs-link && cat README.md",
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, _, _ := gap0545API(t, "claudecode", pack)
			runs := 0
			check := func(name string, tool string, input map[string]any) {
				payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0549", "cwd": sandboxauth.SandboxHome + "/app",
					"tool_name": tool, "tool_input": input, "tool_use_id": "gap0549"})
				na, nr := gap0545Verdict(t, api, gap0545Actor(actor, "claudecode", "PreToolUse", payload, nil), claude, payload)
				for set, facts := range gap0549Forged(input) {
					fa, fr := gap0545Verdict(t, api, gap0545Actor(actor, "claudecode", "PreToolUse", payload, facts), claude, payload)
					runs++
					if gap0545Rank(fa, fr) < gap0545Rank(na, nr) {
						t.Errorf("%s with forged %s: %s %v is weaker than no facts %s %v", name, set, fa, fr, na, nr)
					}
					for _, rule := range nr {
						if !slices.Contains(fr, rule) {
							t.Errorf("%s with forged %s: %s %v drops %s of no facts %s %v", name, set, fa, fr, rule, na, nr)
						}
					}
				}
			}
			for _, command := range commands {
				check(command, "Bash", map[string]any{"command": command})
			}
			for _, file := range []string{"key-link", "a/b/ssh/../.ssh/id_ed25519", "README.md", "claude-dir/settings.json"} {
				check("Read "+file, "Read", map[string]any{"file_path": file})
				check("Write "+file, "Write", map[string]any{"file_path": file, "content": "ssh-ed25519 AAAA x\n"})
			}
			t.Logf("%d forged runs", runs)
		})
	}
}

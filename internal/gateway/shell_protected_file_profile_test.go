// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// shellProtectedFileHome is a home with the protected files of the
// GAP-0675 class and DefenseClaw state, beside a project.
func shellProtectedFileHome(t *testing.T) (home, cwd string) {
	t.Helper()
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(cwd, "notes.txt"),
	} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home, cwd
}

// shellProtectedFileRoute sends one shell command on the hook route of one
// connector (OpenClaw: its /inspect/tool route), per-user or managed, with
// the rule pack of posture, and returns the action and its rule ids.
func shellProtectedFileRoute(t *testing.T, home, cwd, connectorName, posture string, managed bool, command string) (string, []string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connectorName, posture)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	ctx := context.Background()
	if managed {
		ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
	}
	args := func(key string) json.RawMessage {
		raw, err := json.Marshal(map[string]string{key: command})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if connectorName == "openclaw" {
		verdict := api.inspectToolPolicyCtx(ctx, &ToolInspectRequest{
			Tool: "exec", Args: args("command"), Direction: "tool_call", Connector: "openclaw",
		})
		var ids []string
		for _, finding := range verdict.DetailedFindings {
			ids = append(ids, finding.RuleID)
		}
		return verdict.Action, ids
	}
	req := agentHookRequest{ConnectorName: connectorName, CWD: cwd}
	switch connectorName {
	case "claudecode":
		req.HookEventName, req.ToolName, req.ToolArgs = "PreToolUse", "Bash", args("command")
	case "codex":
		req.HookEventName, req.ToolName, req.ToolArgs = "PreToolUse", "Bash", args("command")
	case "copilot":
		req.HookEventName, req.ToolName, req.ToolArgs = "preToolUse", "bash", args("command")
	case "opencode":
		req.HookEventName, req.ToolName, req.ToolArgs = "tool.execute.before", "bash", args("command")
	case "hermes":
		req.HookEventName, req.ToolName, req.ToolArgs = "pre_tool_call", "terminal", args("command")
	default:
		t.Fatalf("no route for %s", connectorName)
	}
	resp := api.evaluateAgentHook(ctx, req)
	var ids []string
	for _, finding := range resp.Findings {
		ids = append(ids, strings.SplitN(finding, ":", 2)[0])
	}
	return resp.Action, ids
}

// rel-1-0-6:GAP-0675 (owner decision 2026-11-06): a shell command that
// writes a protected file of the user is an alert in the default (balanced)
// and permissive profiles and a block in strict, on every hook route,
// per-user and managed; DefenseClaw self-protection blocks in every profile
// and an ordinary write is allowed in every profile.
func TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	const keysRule, profileRule, stateRule = "persistence.ssh_authorized_keys_command", "persistence.shell_profile_write", "tamper.detector_state_write"
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "keyslink")); err != nil {
		t.Fatal(err)
	}
	always := map[string]string{"default": "block", "permissive": "block", "strict": "block"}
	rows := []struct {
		name, command string
		// want is the action per posture; rule is the rule id an alert or
		// block must carry.
		want map[string]string
		rule string
	}{
		// A protected file the call names, directly, by a value it assigns
		// or through a link on disk, stays blocked in every profile (the
		// Wave-3 rule: review 2 of GAP-0675).
		{"keys append", "echo marker >> ~/.ssh/authorized_keys", always, keysRule},
		{"keys copy", "cp notes.txt ~/.ssh/authorized_keys", always, keysRule},
		{"keys known value", "dst=~/.ssh/authorized_keys; echo marker >> \"$dst\"", always, keysRule},
		{"keys link append", "echo marker >> keyslink", always, keysRule},
		{"keys copy onto link", "cp notes.txt keyslink", always, keysRule},
		{"ssh control file", "echo Host >> ~/.ssh/config", always, keysRule},
		{"keys shell body", "bash -c \"echo x >> ~/.ssh/authorized_keys\"", always, keysRule},
		// A shell startup file is the rating of the pack (alert), never a
		// silent allow, and a block in strict.
		{"shell profile append", "echo marker >> ~/.bashrc",
			map[string]string{"default": "alert", "permissive": "alert", "strict": "block"}, profileRule},
		{"DefenseClaw state append", "printf changed >> ~/.defenseclaw/config.yaml", always, stateRule},
		{"ordinary write", "echo marker >> notes.txt",
			map[string]string{"default": "allow", "permissive": "allow", "strict": "allow"}, ""},
	}
	for _, connectorName := range []string{"claudecode", "codex", "copilot", "opencode", "hermes", "openclaw"} {
		for _, managed := range []bool{false, true} {
			cell := connectorName + map[bool]string{false: " per-user", true: " managed"}[managed]
			t.Run(cell, func(t *testing.T) {
				for _, row := range rows {
					if connectorName == "openclaw" && strings.Contains(row.name, "link") {
						continue
					}
					for _, posture := range []string{"default", "permissive", "strict"} {
						want, ok := row.want[posture]
						if !ok {
							continue
						}
						action, rules := shellProtectedFileRoute(t, home, cwd, connectorName, posture, managed, row.command)
						if action != want {
							t.Errorf("%s %s: action=%q want %q rules=%v", posture, row.name, action, want, rules)
							continue
						}
						if row.rule != "" && !slices.Contains(rules, row.rule) {
							t.Errorf("%s %s: rules=%v want %s", posture, row.name, rules, row.rule)
						}
					}
				}
			})
		}
	}
}

// The profile decision reads only the class mark and the self-protection
// rules: a native write tool and a rule outside the class keep their
// enforcement, a finding that could not block stays as it was and sets no
// floor, a class finding is at least an alert in every posture and a
// self-protection finding is at least a block in every posture; the strict
// posture keeps the class enforcing and the Secure Client integration
// changes nothing.
func TestGAP0675ShellProtectedFilePostureDecision(t *testing.T) {
	marked := RuleFinding{RuleID: "persistence.ssh_authorized_keys_command", Severity: "CRITICAL", shellFile: shellFileUnproven}
	proven := RuleFinding{RuleID: "persistence.ssh_authorized_keys_command", Severity: "CRITICAL", shellFile: shellFileProven}
	native := RuleFinding{RuleID: "persistence.ssh_authorized_keys_command", Severity: "CRITICAL"}
	state := RuleFinding{RuleID: "tamper.detector_state_write", Severity: "HIGH"}
	detection := RuleFinding{RuleID: "PATH-SSH-DIR", Severity: "HIGH", shellFile: shellFileUnproven, enforcement: findingEnforcementDetectionOnly}
	stateDetection := RuleFinding{RuleID: "tamper.detector_state_write", Severity: "HIGH", enforcement: findingEnforcementDetectionOnly}
	posture := func(name string) func() string { return func() string { return name } }
	for _, tc := range []struct {
		name         string
		findings     []RuleFinding
		secureClient bool
		posture      string
		alertOnly    []bool
		floor        string
	}{
		{"default", []RuleFinding{marked, native, detection}, false, "default", []bool{true, false, false}, "alert"},
		{"permissive", []RuleFinding{marked, native, detection}, false, "permissive", []bool{true, false, false}, "alert"},
		{"strict", []RuleFinding{marked, native, detection}, false, "strict", []bool{false, false, false}, "alert"},
		{"secure client", []RuleFinding{marked, native, detection}, true, "default", []bool{false, false, false}, "allow"},
		// A proven target keeps its enforcement in every posture and is at
		// least an alert, as the unproven class is.
		{"proven default", []RuleFinding{proven}, false, "default", []bool{false}, "alert"},
		{"proven permissive", []RuleFinding{proven, marked}, false, "permissive", []bool{false, true}, "alert"},
		{"proven strict", []RuleFinding{proven}, false, "strict", []bool{false}, "alert"},
		{"self-protection permissive", []RuleFinding{state, marked}, false, "permissive", []bool{false, true}, "block"},
		{"self-protection strict", []RuleFinding{state}, false, "strict", []bool{false}, "block"},
		{"self-protection secure client", []RuleFinding{state}, true, "permissive", []bool{false}, "allow"},
		{"detection only sets no floor", []RuleFinding{detection, stateDetection, native}, false, "permissive", []bool{false, false, false}, "allow"},
	} {
		before := slices.Clone(tc.findings)
		got, floor := profileClassFindings(tc.findings, tc.secureClient, posture(tc.posture))
		if floor != tc.floor {
			t.Errorf("%s: floor=%q want %q", tc.name, floor, tc.floor)
		}
		for index, finding := range got {
			if finding.contributesToAlertOnly() != tc.alertOnly[index] {
				t.Errorf("%s: finding %d (%s) alert-only=%v want %v", tc.name, index, finding.RuleID, finding.contributesToAlertOnly(), tc.alertOnly[index])
			}
		}
		if !reflect.DeepEqual(before, tc.findings) {
			t.Fatalf("%s: the decision changed the caller findings", tc.name)
		}
	}
	if got, floor := profileClassFindings([]RuleFinding{native, state}, false, func() string {
		t.Fatal("posture read without a finding of the class")
		return ""
	}); len(got) != 2 || floor != "block" {
		t.Fatalf("findings without the class = %v floor %q", got, floor)
	}
	for _, tc := range []struct {
		tool, command string
		shell         bool
	}{
		{"Bash", "", true}, {"shell", "", true}, {"exec_command", "", true}, {"terminal", "", true},
		{"write_file", "", false}, {"Write", "", false}, {"apply_patch", "x", false}, {"persist", "", false},
		{"anything", "echo x", true},
	} {
		marks := markShellProtectedFileFindings(trustedActionRequest{Input: actionfacts.Input{Tool: tc.tool, Command: tc.command}},
			[]RuleFinding{{RuleID: "PERSISTENCE.SSH_AUTHORIZED_KEYS_COMMAND"}, {RuleID: "tamper.detector_state_write"}})
		want := shellFileNone
		if tc.shell {
			want = shellFileUnproven
		}
		if marks[0].shellFile != want || marks[1].shellFile != shellFileNone {
			t.Errorf("%s %q: marks=%v,%v want %v,none", tc.tool, tc.command, marks[0].shellFile, marks[1].shellFile, want)
		}
	}
}

// rel-1-0-6:GAP-0675: the class covers shell commands only. A native write
// tool that writes the authorized-keys file keeps its block in the default
// profile, per-user and managed.
func TestGAP0675NativeWriteToolKeepsItsBlockInDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home, cwd := shellProtectedFileHome(t)
	installToolCallCorpusProfileConnector(t, "claudecode", "default")
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	args, err := json.Marshal(map[string]string{"file_path": filepath.Join(home, ".ssh", "authorized_keys"), "content": "marker\n"})
	if err != nil {
		t.Fatal(err)
	}
	for _, managed := range []bool{false, true} {
		ctx := context.Background()
		if managed {
			ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
		}
		resp := api.evaluateAgentHook(ctx, agentHookRequest{
			ConnectorName: "claudecode", HookEventName: "PreToolUse", ToolName: "Write", ToolArgs: args, CWD: cwd,
		})
		if resp.Action != "block" {
			t.Errorf("managed=%v: Write to authorized_keys action=%q findings=%v, want block", managed, resp.Action, resp.Findings)
		}
	}
}

// rel-1-0-6:GAP-0675: on the Claude Code hook route the default profile
// answers the protected write with an alert and the audit row records
// action alert with the rule id; strict answers and records a block.
func TestGAP0675ShellProtectedFileAuditRowRecordsTheDecision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	_, cwd := shellProtectedFileHome(t)
	for posture, want := range map[string]string{"default": "block", "strict": "block"} {
		t.Run(posture, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", posture)
			store, logger := testStoreAndLogger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg, health: NewSidecarHealth()}
			body, err := json.Marshal(map[string]any{
				"hook_event_name": "PreToolUse", "session_id": "gap0675-" + posture, "tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]any{"command": "echo marker >> ~/.ssh/authorized_keys"},
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(w, req)
			var answer struct {
				Action string `json:"action"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || answer.Action != want {
				t.Fatalf("answer=%s err=%v, want action %q", w.Body.String(), err, want)
			}
			row := soleHookDecisionForTest(t, store)
			recorded, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			if row.Structured["action"] != want || !strings.Contains(string(recorded), "persistence.ssh_authorized_keys_command") {
				t.Fatalf("audit row=%s, want action %q with the rule id", recorded, want)
			}
		})
	}
}

// rel-1-0-6:GAP-0675 review 2: a command that names no protected file and
// holds only an ordinary word, or a comment with the word, is never blocked
// in the default profile on any hook route, per-user or managed; the class
// is not decided by the words defense or apply_patch.
func TestGAP0675BenignNearVariantsDoNotBlockInDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	f := newB36ManagedHookFixture(t)
	for _, connector := range []string{"claudecode", "codex"} {
		installToolCallCorpusProfileConnector(t, connector, "default")
	}
	baseline := "for f in src/*.c; do b1=\"${f%.c}.bak\"; cp \"$f\" \"$b1\"; done\n{ g4=logs/g4.log; echo \"$c4\" >> \"$g4\"; }"
	for _, row := range []struct{ name, command string }{
		{"baseline", baseline},
		{"comment defense", baseline + "\n# defense"},
		{"comment apply_patch", baseline + "\n# apply_patch"},
		{"comment begin patch", baseline + "\n# *** Begin Patch"},
		{"ordinary word defense", baseline + "\necho defense > ordinary/note"},
		// Review 3: a protected name in a comment or in data the call writes
		// elsewhere is not a protected write.
		{"comment keys name", baseline + "\n# ~/.ssh/authorized_keys"},
		{"comment startup name", baseline + "\n# source ~/.bashrc"},
		{"data keys name", baseline + "\necho authorized_keys > ordinary/note"},
		{"data startup name", baseline + "\nprintf %s .bashrc >> ordinary/note"},
	} {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = call.connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(call.payload)))
			if call.managed && call.header != "" {
				req.Header.Set(hookpaths.Header, call.header)
			}
			if call.connector == "codex" {
				setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			}
			if call.managed {
				req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
			}
			recorder := httptest.NewRecorder()
			api.handleAgentHook(call.connector).ServeHTTP(recorder, req)
			if strings.HasPrefix(recorder.Body.String(), "{\"action\":\"block\"") {
				t.Errorf("%s %s managed=%v: blocked: %.200s", row.name, call.connector, call.managed, recorder.Body.String())
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// TestGAP0675ProtectedOperandNameReadsOperandsOnly: the name proof reads one
// operand by its last components. A protected name in prose, a comment or a
// data word is not an operand and never reaches it (review 3, must-fix 2);
// ordinary look-alikes are not protected names.
func TestGAP0675ProtectedOperandNameReadsOperandsOnly(t *testing.T) {
	for _, operand := range []string{
		"authorized_keys", "~/.ssh/authorized_keys", "dist/k/authorized_keys", "/home/u/.ssh/authorized_keys2",
		".ssh", "C:\\Users\\u\\.ssh\\config", "~/.ssh/id_ed25519", "~/.bashrc", "/home/u/.zshrc", "repo/.git/hooks",
		"repo/.git/hooks/pre-commit", "~/.config/fish/config.fish",
	} {
		if !protectedOperandName(operand, false) {
			t.Errorf("%q is a protected name", operand)
		}
	}
	for _, operand := range []string{
		"", "notes.txt", "logs/g4.log", "ssh-notes.md", "authorized-users.txt", "~/.ssh/known_hosts", "bashrc.bak",
		"# authorized_keys", "src/hooks/pre-commit", "keys/rc",
	} {
		if protectedOperandName(operand, false) {
			t.Errorf("%q is not a protected name", operand)
		}
	}
	if protectedOperandName("../.defenseclaw", false) || !protectedOperandName("../.defenseclaw", true) {
		t.Error("the state folder is a protected name only as the target of a link")
	}
}

// Scratch code-close probes (S7 lane s7-probe1, test-only branch s7/ccprobes-1).
// Each TestCCP1GAPnnnn reproduces one rel-1-0-10 gap through the gateway hook
// route (evaluateAgentHook, the real handler and rule pack) or the OpenClaw
// /inspect/tool route (postInspect), using only APIs that exist at the pre-fix
// sha. Want: red at the pre-fix sha, green at rel. A control that does not
// hold on a tree skips the probe (never a false red).

package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const ccp1StateWrite = "printf changed >> ~/.defenseclaw/config.yaml"

// ccp1Secret is a synthetic provider-key shape built at run time.
var ccp1Secret = "sk-ant-api03-" + "Q4r8T2w6Y1u5" + "I9o3P7a2S6d0"

func ccp1Home(t *testing.T) (home, cwd string) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture, unprivileged user")
	}
	home = filepath.Join(t.TempDir(), "homes", "alice")
	cwd = filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{
		filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(cwd, "notes.txt"),
	} {
		if err := os.WriteFile(f, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home, cwd
}

// ccp1Hook sends one PreToolUse call on the hook route of connector with the
// rule pack of posture and returns the action and the rule ids.
func ccp1Hook(t *testing.T, connector, posture, cwd, tool string, input map[string]any) (string, []string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connector, posture)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	resp := api.evaluateAgentHook(context.Background(), agentHookRequest{
		ConnectorName: connector, CWD: cwd, HookEventName: "PreToolUse", ToolName: tool, ToolArgs: raw,
	})
	var ids []string
	for _, f := range resp.Findings {
		ids = append(ids, strings.SplitN(f, ":", 2)[0])
	}
	return resp.Action, ids
}

func ccp1Bash(t *testing.T, connector, posture, cwd, command string) (string, []string) {
	t.Helper()
	return ccp1Hook(t, connector, posture, cwd, "Bash", map[string]any{"command": command})
}

func ccp1Has(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// rel-1-0-10:GAP-0013 (P2 false block): a benign link then move to a file
// name with a space, quote, newline, star or semicolon is allowed.
func TestCCP1GAP0013LinkThenMoveToAnOddNameIsAllowed(t *testing.T) {
	_, cwd := ccp1Home(t)
	data := t.TempDir()
	a, b := filepath.Join(data, "a.dat"), filepath.Join(data, "b.dat")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if act, _ := ccp1Bash(t, "claudecode", "default", cwd, "ln -s ~/.ssh/authorized_keys /tmp/ccp13k && echo m >> /tmp/ccp13k"); act != "block" {
		t.Skipf("control: the keys link write is %q on this tree, want block", act)
	}
	rows := map[string]string{
		"starred":   fmt.Sprintf("ln %s /tmp/ccp13l && mv /tmp/ccp13l '%s/file*with*stars.dat'", a, data),
		"quoted":    fmt.Sprintf(`ln %s /tmp/ccp13l && mv /tmp/ccp13l $'%s/file"with"quotes.dat'`, a, data),
		"newline":   fmt.Sprintf(`ln %s /tmp/ccp13l && mv /tmp/ccp13l $'%s/file\nwith\nnewlines.dat'`, a, data),
		"spaced":    fmt.Sprintf("ln %s /tmp/ccp13l && mv /tmp/ccp13l '%s/file with spaces.dat'", a, data),
		"semicolon": fmt.Sprintf("ln %s /tmp/ccp13l && mv /tmp/ccp13l '%s/file;with;semicolon.dat'", a, data),
		"absolute":  fmt.Sprintf("ln %s /tmp/ccp13l && mv /tmp/ccp13l %s", a, b),
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, posture := range []string{"default", "permissive"} {
			for name, command := range rows {
				if act, ids := ccp1Bash(t, connector, posture, cwd, command); act != "allow" {
					t.Errorf("%s/%s %s: action %q rules %v, want allow", connector, posture, name, act, ids)
				}
			}
		}
	}
}

// rel-1-0-10:GAP-0004 (P2 false block): Codex in the home folder runs a cat
// heredoc whose body is patch banner text; the body is data, so allow.
func TestCCP1GAP0004CodexHeredocBannerAtHomeIsAllowed(t *testing.T) {
	home, _ := ccp1Home(t)
	command := "cat <<\"EOT\"\n*** Begin Patch\n*** End Patch\nEOT"
	for _, posture := range []string{"default", "permissive"} {
		if act, ids := ccp1Bash(t, "codex", posture, home, command); act != "allow" {
			t.Errorf("codex/%s cwd=home: action %q rules %v, want allow", posture, act, ids)
		}
	}
}

// rel-1-0-10:GAP-0532 (P2 security): a DefenseClaw state write in the script
// of a shell behind a long pipe chain keeps the block of the write alone.
func TestCCP1GAP0532StateWriteInAShellBodyBehindALongChainBlocks(t *testing.T) {
	_, cwd := ccp1Home(t)
	bodies := map[string]func(n int) string{
		"bash-heredoc": func(n int) string {
			return "bash <<'EOF'\n" + strings.Repeat("a|", n) + "a\n" + ccp1StateWrite + "\nEOF"
		},
		"sudo-bash-heredoc": func(n int) string {
			return "sudo bash <<'EOF'\n" + strings.Repeat("a|", n) + "a\n" + ccp1StateWrite + "\nEOF"
		},
		"bash-c": func(n int) string { return "bash -c '" + strings.Repeat("a|", n) + "a; " + ccp1StateWrite + "'" },
	}
	for _, posture := range []string{"default", "strict"} {
		if act, _ := ccp1Bash(t, "claudecode", posture, cwd, ccp1StateWrite); act != "block" {
			t.Skipf("control: the state write alone is %q in %s on this tree, want block", act, posture)
		}
		for name, build := range bodies {
			for _, n := range []int{511, 600, 1200} {
				if act, ids := ccp1Bash(t, "claudecode", posture, cwd, build(n)); act != "block" {
					t.Errorf("%s %s/%d: action %q rules %v, want block", posture, name, n, act, ids)
				}
			}
		}
	}
}

// rel-1-0-10:GAP-0281 (P1 security): a call past the chain budget keeps the
// protected-state-write proof (block), it does not fall to allow or alert.
func TestCCP1GAP0281StateWriteAfterAnOverBudgetChainBlocks(t *testing.T) {
	home, cwd := ccp1Home(t)
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	for _, connector := range []string{"claudecode", "codex"} {
		for _, posture := range []string{"default", "strict"} {
			if act, _ := ccp1Bash(t, connector, posture, cwd, "printf changed >> "+state); act != "block" {
				t.Skipf("control: the state write alone is %q (%s/%s), want block", act, connector, posture)
			}
			for _, row := range []struct {
				op string
				n  int
			}{{"a|", 4097}, {"a|", 5000}, {"a&&", 5000}, {"a||", 5000}} {
				command := strings.Repeat(row.op, row.n) + "a; printf changed >> " + state
				if act, ids := ccp1Bash(t, connector, posture, cwd, command); act != "block" {
					t.Errorf("%s/%s %q x%d then state write: action %q rules %v, want block", connector, posture, row.op, row.n, act, ids)
				}
			}
		}
	}
}

// rel-1-0-10:GAP-0284 (P2 security): a long chain that does not parse is
// over the reading budget (the unknown tier), not a clean allow.
func TestCCP1GAP0284UnparsedLongChainIsNotAClean(t *testing.T) {
	_, cwd := ccp1Home(t)
	for name, command := range map[string]string{
		"unparsed": strings.Repeat("a|", 20000) + "fi",
		"wrapped":  "(((" + strings.Repeat("a|", 20000) + "a",
	} {
		act, ids := ccp1Bash(t, "claudecode", "default", cwd, command)
		if act == "allow" && len(ids) == 0 {
			t.Errorf("%s 20000 stages: clean allow, want the unknown tier (alert or block)", name)
		}
		t.Logf("%s: action %q rules %v", name, act, ids)
	}
}

// rel-1-0-10:GAP-0285 (P2 security): a deep arithmetic tree (66 KB) is over
// the depth budget (the unknown tier), not a clean allow.
func TestCCP1GAP0285DeepArithmeticIsNotAClean(t *testing.T) {
	_, cwd := ccp1Home(t)
	command := "echo $((1" + strings.Repeat("+1", 33000) + "))"
	act, ids := ccp1Bash(t, "claudecode", "default", cwd, command)
	if act == "allow" && len(ids) == 0 {
		t.Errorf("33000 additions: clean allow, want the unknown tier (alert or block)")
	}
	t.Logf("action %q rules %v", act, ids)
}

// rel-1-0-10:GAP-0355 (P2 false alert): git push to a user-less scp-form
// host (an ssh-config alias) is ordinary work.
func TestCCP1GAP0355PushToAnSSHAliasIsQuiet(t *testing.T) {
	_, cwd := ccp1Home(t)
	const rule = "source_control.clone_then_run_or_adhoc_push"
	for _, command := range []string{
		"git push labbox:team/repo.git HEAD",
		"git push buildhost:repos/app.git main",
	} {
		for _, posture := range []string{"default", "strict"} {
			act, ids := ccp1Bash(t, "codex", posture, cwd, command)
			if ccp1Has(ids, rule) || posture == "default" && act != "allow" {
				t.Errorf("%s %q: action %q rules %v, want allow without %s", posture, command, act, ids, rule)
			}
		}
	}
}

// rel-1-0-10:GAP-0414 (P1 security): the sed -i backup name is a write; a
// backup suffix that names the keys file blocks.
func TestCCP1GAP0414SedBackupSuffixNamingTheKeysFileBlocks(t *testing.T) {
	home, cwd := ccp1Home(t)
	if err := os.WriteFile(filepath.Join(cwd, "authorized_keys"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".ssh")
	for _, posture := range []string{"default", "strict"} {
		for name, command := range map[string]string{
			"HLR3-SFX-a": "sed -i" + dir + "/* s/x/y/ authorized_keys",
			"HLR3-SFX-b": "sed --in-place=" + dir + "/* s/x/y/ authorized_keys",
			"HLR3-SFX-c": "sed -i../.ssh/* s/x/y/ authorized_keys",
		} {
			if act, ids := ccp1Bash(t, "claudecode", posture, cwd, command); act != "block" {
				t.Errorf("%s %s: action %q rules %v, want block", posture, name, act, ids)
			}
		}
	}
}

// rel-1-0-10:GAP-0496 (P1 security): GNU sed puts the operand as typed (with
// its directory part) in place of the star; that backup name is the keys file.
func TestCCP1GAP0496SedStarTakesTheOperandAsTyped(t *testing.T) {
	home, cwd := ccp1Home(t)
	if err := os.MkdirAll(filepath.Join(cwd, "ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "ssh", "authorized_keys"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, posture := range []string{"default", "strict"} {
		for name, command := range map[string]string{
			"HLR4-SFX-pfx-long":     "sed --in-place=" + home + "/.* s/x/y/ ssh/authorized_keys",
			"HLR4-SFX-pfx-attached": "sed -i" + home + "/.* s/x/y/ ssh/authorized_keys",
			"HLR4-SFX-pfx-cluster":  "sed -ni" + home + "/.* s/x/y/ ssh/authorized_keys",
		} {
			if act, ids := ccp1Bash(t, "claudecode", posture, cwd, command); act != "block" {
				t.Errorf("%s %s: action %q rules %v, want block", posture, name, act, ids)
			}
		}
	}
}

// rel-1-0-10:GAP-0437 (P1 security): a malformed $(( arithmetic never
// panics a gateway route (hook route and the OpenClaw /inspect/tool route).
func TestCCP1GAP0437MalformedArithmeticNeverPanics(t *testing.T) {
	_, cwd := ccp1Home(t)
	for _, command := range []string{"h=$((t d", "h=$((t d))", "echo x >> ~/.ssh/authorized_keys\nh=$((t d"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("hook route %q: panic %v", command, r)
				}
			}()
			act, ids := ccp1Bash(t, "claudecode", "default", cwd, command)
			t.Logf("hook %q: action %q rules %v", command, act, ids)
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("inspect/tool route %q: panic %v", command, r)
				}
			}()
			args, _ := json.Marshal(map[string]string{"command": command})
			api := testAPIServerWithConfig(t, "action")
			_, verdict := postInspect(t, api, `{"tool":"exec","args":`+string(args)+`,"direction":"outbound"}`)
			t.Logf("inspect %q: action %q", command, verdict.Action)
		}()
	}
}

// rel-1-0-10:GAP-0328 (P1 security): an attachment is skipped only when none
// of it is text: text after a base64-looking prefix is read (block).
func TestCCP1GAP0328AttachmentSkipHidesNoText(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	if _, v := postInspect(t, api, `{"tool":"message","args":{"message":"key: `+ccp1Secret+`"},"direction":"outbound"}`); v.Action != "block" {
		t.Skipf("control: the key in a message is %q on this tree, want block", v.Action)
	}
	hidden := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0, 1, 2}, 3000), []byte("key: "+ccp1Secret)...))
	afterPrefix := strings.Repeat("AAEC", 1024) + " key: " + ccp1Secret
	for name, args := range map[string]string{
		"buffer, binary header then text": `{"buffer":"` + hidden + `"}`,
		"buffer, base64 then words":       `{"buffer":"` + afterPrefix + `"}`,
		"caption is always text":          `{"caption":"` + afterPrefix + `"}`,
		"Buffer nested, any case":         `{"attachments":[{"Buffer":"` + hidden + `"}]}`,
		"data URL in message":             `{"message":"data:image/png;base64,` + afterPrefix + `"}`,
	} {
		_, verdict := postInspect(t, testAPIServerWithConfig(t, "action"), `{"tool":"message","args":`+args+`,"direction":"outbound"}`)
		if verdict.Action != "block" {
			t.Errorf("%s: action %q findings %v, want block", name, verdict.Action, verdict.Findings)
		}
	}
}

// rel-1-0-10:GAP-0323 (P2 false alert): a benign 300 KB binary attachment is
// no text and no cap hit: a plain allow.
func TestCCP1GAP0323BenignBinaryAttachmentIsAPlainAllow(t *testing.T) {
	photo := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0, 1, 2, 255, 254}, 60000))
	_, verdict := postInspect(t, testAPIServerWithConfig(t, "action"), `{"tool":"message","args":{"message":"here is the photo","buffer":"`+photo+`","filename":"a.png"},"direction":"outbound"}`)
	if verdict.Action != "allow" || len(verdict.Findings) != 0 {
		t.Errorf("300 KB binary attachment: action %q findings %v, want a plain allow", verdict.Action, verdict.Findings)
	}
}

// rel-1-0-10:GAP-0322 (P2 security, CPU DoS): a message routing array of
// 16000 values (80 KB) is read in well under a second, not O(N^2).
func TestCCP1GAP0322RoutingArrayIsLinear(t *testing.T) {
	to := make([]string, 16000)
	for i := range to {
		to[i] = fmt.Sprintf("u%d", i)
	}
	raw, _ := json.Marshal(map[string]any{"text": "hello", "to": to})
	api := testAPIServerWithConfig(t, "action")
	start := time.Now()
	rec, verdict := postInspect(t, api, `{"tool":"message","args":`+string(raw)+`,"direction":"outbound"}`)
	took := time.Since(start)
	if took > 3*time.Second || rec.Code != http.StatusOK {
		t.Errorf("16000 routing values on /inspect/tool: %v, status %d, action %q; want an answer under 3 s", took, rec.Code, verdict.Action)
	} else {
		t.Logf("16000 routing values took %v (action %q)", took, verdict.Action)
	}
}

// rel-1-0-10:GAP-0476 (P2 security): a quoted dotted password literal is a
// password, not a qualified code name.
func TestCCP1GAP0476QuotedDottedPasswordIsFound(t *testing.T) {
	_, cwd := ccp1Home(t)
	write := func(content string) (string, []string) {
		return ccp1Hook(t, "claudecode", "default", cwd, "Write", map[string]any{"file_path": filepath.Join(cwd, "settings.py"), "content": content})
	}
	if act, ids := write(`password = "` + "Wq7#" + "mz2Lp" + `"`); act == "allow" && len(ids) == 0 {
		t.Skipf("control: a quoted password is a clean allow on this tree")
	}
	for _, content := range []string{
		`password = "admin.` + "Secret" + "2024" + `"`,
		`password: 'corp.` + "Pass" + "2024" + `'`,
		`"password": "svc.` + "Login" + "99" + `"`,
		`PASSWORD="ops.` + "Deploy" + "7" + `"`,
	} {
		if act, ids := write(content); act == "allow" && len(ids) == 0 {
			t.Errorf("%q: clean allow, want a password finding", content)
		}
	}
}

// rel-1-0-10:GAP-0653 (P2 security): an awk program or command word built at
// run time (a variable, a -v value, ENVIRON) is the unknown tier: alert in
// default, block in strict; never a clean allow.
func TestCCP1GAP0653AwkProgramBuiltAtRunTimeIsTheUnknownTier(t *testing.T) {
	_, cwd := ccp1Home(t)
	if err := os.WriteFile(filepath.Join(cwd, "a.txt"), []byte("date\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`P='{system($1)}'; awk "$P" a.txt`,
		`X=date; awk -v c="$X" 'BEGIN{system(c)}'`,
		`X=date; awk -v c="$X" 'BEGIN{c | getline v; print v}'`,
		`C=date awk 'BEGIN{system(ENVIRON["C"])}'`,
	} {
		if act, ids := ccp1Bash(t, "claudecode", "strict", cwd, command); act != "block" {
			t.Errorf("strict %q: action %q rules %v, want block (unknown tier)", command, act, ids)
		}
		if act, ids := ccp1Bash(t, "claudecode", "default", cwd, command); act == "allow" && len(ids) == 0 {
			t.Errorf("default %q: clean allow, want the unknown tier (alert)", command)
		}
	}
}

// rel-1-0-10:GAP-0552 (P2 security): a cmd /c line on the PowerShell tool is
// read as the line cmd.exe runs: a CMD attack fixture the Bash tool's cmd /c
// spelling catches is not a clean allow on the PowerShell tool.
func TestCCP1GAP0552CmdLauncherOnThePowerShellToolIsRead(t *testing.T) {
	_, cwd := ccp1Home(t)
	var fixtures []toolCallCorpusCase
	for _, c := range readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl") {
		if c.IsAttack && string(c.Dialect) == "cmd" && c.Command != "" && len(c.OSOverrides) == 0 &&
			c.ProfilePosture == "" && !strings.ContainsAny(c.Command, "\"\r\n") {
			fixtures = append(fixtures, c)
		}
	}
	clean := func(act string, ids []string) bool { return act == "allow" && len(ids) == 0 }
	read := 0
	for _, posture := range []string{"default", "strict"} {
		for _, c := range fixtures {
			if clean(ccp1Bash(t, "claudecode", posture, cwd, "cmd /c "+c.Command)) {
				continue // the Bash tool's spelling is the reference
			}
			read++
			for _, spelling := range []string{"cmd /c " + c.Command, `C:\Windows\System32\cmd.exe /c ` + c.Command, "cmd /r " + c.Command} {
				if act, ids := ccp1Hook(t, "claudecode", posture, cwd, "PowerShell", map[string]any{"command": spelling}); clean(act, ids) {
					t.Errorf("%s %s: the PowerShell tool's spelling %d is a clean allow", posture, c.ID, len(spelling)-len(c.Command))
				}
			}
		}
	}
	if read == 0 {
		t.Skipf("control: no CMD fixture (%d) is caught in the Bash tool's cmd /c spelling on this tree", len(fixtures))
	}
}

// rel-1-0-10:GAP-0176 (P3 security): an ACP terminal/create frame is judged
// as the shell call it performs (the command rules), not scanned as prose:
// a DefenseClaw state write blocks.
func TestCCP1GAP0176ACPTerminalFrameMeetsTheShellRules(t *testing.T) {
	ccp1Home(t)
	api := testAPIServerWithConfig(t, "action")
	cfg := acpWordingTestConfig()
	cfg.Guardrail = api.scannerCfg.Guardrail
	api.scannerCfg = cfg
	frame, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "terminal/create",
		"params": map[string]any{"sessionId": "s", "command": ccp1StateWrite}})
	body, err := json.Marshal(acp.Evaluation{
		Profile: "default", Mode: acp.ModeAction, AgentID: "kiro", ClientID: "zed",
		Direction: acp.AgentToClient, Surface: acp.SurfaceTerminal, Method: "terminal/create", Payload: json.RawMessage(frame),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	api.handleACPEvaluate(rec, httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Skipf("control: the ACP route answered %d %s on this tree", rec.Code, rec.Body.String())
	}
	var verdict acp.Verdict
	if err := json.Unmarshal(rec.Body.Bytes(), &verdict); err != nil {
		t.Fatal(err)
	}
	if verdict.Action != "block" {
		t.Errorf("terminal/create state write: action %q reason %q, want block", verdict.Action, verdict.Reason)
	}
}

func ccp1Token(seed int64) string {
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 36)
	x := uint64(seed)*6364136223846793005 + 1442695040888963407
	for i := range b {
		x = x*6364136223846793005 + 1442695040888963407
		b[i] = alnum[(x>>33)%uint64(len(alnum))]
	}
	return "gh" + "p_" + string(b)
}

func ccp1JSONText(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func ccp1PassthroughBody(provider string) string {
	if provider == "anthropic" {
		return `{"model":"claude-x","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`
	}
	return `{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}`
}

// ccp1Passthrough sends one call through the host passthrough route to an
// upstream that answers body with contentType (gzip-compressed when gz) and
// returns what the client got, decompressed.
func ccp1Passthrough(t *testing.T, provider, path, contentType, body string, gz bool) string {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		if gz {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(buf.Bytes())
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer upstream.Close()
	registerRawForwardProviderDomain(t, upstream.URL, provider)
	allowRawForwardPrivateTargets(t)
	proxy := newTestProxy(t, &mockProvider{}, NewGuardrailInspector("local", nil, nil), "action")
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(ccp1PassthroughBody(provider)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer test-key")
	if gz {
		req.Header.Set("Accept-Encoding", "gzip")
	}
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, req)
	out := rec.Body.Bytes()
	if strings.Contains(rec.Header().Get("Content-Encoding"), "gzip") || len(out) > 2 && out[0] == 0x1f && out[1] == 0x8b {
		if zr, err := gzip.NewReader(bytes.NewReader(out)); err == nil {
			if plain, err := io.ReadAll(zr); err == nil {
				out = plain
			}
		}
	}
	return string(out)
}

// rel-1-0-10:GAP-0370 (P2 security): streamed thinking text and streamed
// tool input are checked on the passthrough route; a token in them does not
// reach the client.
func TestCCP1GAP0370ThinkingAndToolInputAreChecked(t *testing.T) {
	token := ccp1Token(7)
	sse := func(e string) string { return "data: " + e + "\n\n" }
	control := sse(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":` + ccp1JSONText("the token is "+token) + `}}`)
	if got := ccp1Passthrough(t, "anthropic", "/v1/messages", "text/event-stream", control, false); strings.Contains(got, token) {
		t.Skipf("control: a token in text_delta reaches the client on this tree")
	}
	for name, body := range map[string]string{
		"thinking_delta":   sse(`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":` + ccp1JSONText("the token is "+token) + `}}`),
		"input_json_delta": sse(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":` + ccp1JSONText(`{"token":"`+token+`"}`) + `}}`),
	} {
		if got := ccp1Passthrough(t, "anthropic", "/v1/messages", "text/event-stream", body, false); strings.Contains(got, token) {
			t.Errorf("anthropic %s: the token reached the client", name)
		}
	}
}

// rel-1-0-10:GAP-0087 (P2 security): a compressed provider reply on the
// host passthrough route is decoded and inspected; a token in it does not
// reach the client.
func TestCCP1GAP0087CompressedReplyIsInspected(t *testing.T) {
	token := ccp1Token(11)
	body := `{"choices":[{"index":0,"message":{"role":"assistant","content":` + ccp1JSONText("the token is "+token) + `}}]}`
	if got := ccp1Passthrough(t, "openai", "/v1/chat/completions", "application/json", body, false); strings.Contains(got, token) {
		t.Skipf("control: a token in a plain reply reaches the client on this tree")
	}
	if got := ccp1Passthrough(t, "openai", "/v1/chat/completions", "application/json", body, true); strings.Contains(got, token) {
		t.Errorf("gzip reply: the token reached the client uninspected")
	}
}

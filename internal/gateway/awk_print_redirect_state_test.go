package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-10:GAP-1239: an awk program that redirects print or printf into
// active DefenseClaw state writes the file as the shell redirect does, so on
// the Claude Code hook route it gets the shell redirect's verdict (block,
// tamper.detector_state_write) bare and behind env and sudo, in every pack.
// The redirect fixtures of TestActiveStateMentionAllowedRealWriteBlocked are
// written as the awk program here; a print into a project file, to standard
// error, a comparison and a computed target stay allowed.
func TestGAP1239AwkPrintRedirectIntoStateIsTheShellRedirect(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home, cwd := r104ReviewHome(t)
	state := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(state, "config.yaml"), filepath.Join(state, "device.key"), filepath.Join(cwd, "report.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// awkForm is the awk program that writes target as `printf x OP target`
	// does: awk opens the literal, so the target is absolute.
	awkForm := func(statement, operator, target string) string {
		return fmt.Sprintf(`awk 'BEGIN{%s %s "%s"}'`, statement, operator, target)
	}
	type shape struct {
		shell, awk string
		block      bool
	}
	var shapes []shape
	for _, target := range []string{"config.yaml", "device.key"} {
		for _, operator := range []string{">", ">>"} {
			for _, statement := range []string{`print "x"`, `printf("x")`} {
				shapes = append(shapes, shape{
					shell: "printf x " + operator + " ~/.defenseclaw/" + target,
					awk:   awkForm(statement, operator, filepath.Join(state, target)),
					block: true,
				})
			}
		}
	}
	shapes = append(shapes,
		shape{shell: "printf x > report.txt", awk: awkForm(`print "x"`, ">", "report.txt")},
		shape{shell: "printf x >> " + filepath.Join(cwd, "report.txt"), awk: awkForm(`print "x"`, ">>", filepath.Join(cwd, "report.txt"))},
		shape{shell: "printf x > /dev/stderr", awk: awkForm(`print "x"`, ">", "/dev/stderr")},
		shape{shell: "echo x", awk: fmt.Sprintf(`awk 'BEGIN{print (1 > 2); print "%s"}'`, filepath.Join(state, "config.yaml"))},
		shape{shell: "echo x", awk: `awk '{print > $1}' report.txt`},
	)
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		ask := func(id, command string) agentHookResponse {
			event := claudeToolEvent("PreToolUse", "gap1239-"+pack+"-"+id, id, command)
			event["cwd"] = cwd
			return callAgentHookForTest(t, handler, event)
		}
		for i, s := range shapes {
			shell := ask(fmt.Sprintf("s%d", i), s.shell)
			if got := shell.Action == "block"; got != s.block {
				t.Fatalf("%s %q (shell form): blocked=%v, want %v (%v)", pack, s.shell, got, s.block, shell.RuleIDs)
			}
			for w, wrapper := range []string{"", "env ", "sudo "} {
				awk := ask(fmt.Sprintf("a%d-%d", i, w), wrapper+s.awk)
				if got := awk.Action == "block"; got != s.block {
					t.Errorf("%s %q: blocked=%v, want %v as the shell form %q (%v)", pack, wrapper+s.awk, got, s.block, s.shell, awk.RuleIDs)
				}
				if s.block && !containsString(awk.RuleIDs, stateWriteRuleID) {
					t.Errorf("%s %q: rules %v, want %s", pack, wrapper+s.awk, awk.RuleIDs, stateWriteRuleID)
				}
			}
		}
	}
}

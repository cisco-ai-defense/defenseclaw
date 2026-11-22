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
// the Claude Code hook route it gets the shell redirect's verdict, with
// tamper.detector_state_write, bare and behind env and sudo, in every pack.
// That verdict is the GAP-0747 owner tiering (2026-11-15T15:20Z) of a proven
// state write: a HIGH alert in the default pack, a block in strict (a shell
// form that also names another tamper or persistence rule keeps its block).
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
		writeAction := gap0747WantAction(pack == "strict")
		for i, s := range shapes {
			shell := ask(fmt.Sprintf("s%d", i), s.shell)
			if s.block {
				want := writeAction
				if shell.Action == "block" && gap0747OtherTamperFinding(shell.RuleIDs) {
					want = "block"
				}
				if shell.Action != want || !containsString(shell.RuleIDs, stateWriteRuleID) {
					t.Fatalf("%s %q (shell form): action %q rules %v, want %q with %s", pack, s.shell, shell.Action, shell.RuleIDs, want, stateWriteRuleID)
				}
			} else if shell.Action == "block" {
				t.Fatalf("%s %q (shell form): blocked, want no block (%v)", pack, s.shell, shell.RuleIDs)
			}
			for w, wrapper := range []string{"", "env ", "sudo "} {
				awk := ask(fmt.Sprintf("a%d-%d", i, w), wrapper+s.awk)
				if s.block {
					if awk.Action != shell.Action {
						t.Errorf("%s %q: action %q, want %q as the shell form %q (%v)", pack, wrapper+s.awk, awk.Action, shell.Action, s.shell, awk.RuleIDs)
					}
					if !containsString(awk.RuleIDs, stateWriteRuleID) {
						t.Errorf("%s %q: rules %v, want %s", pack, wrapper+s.awk, awk.RuleIDs, stateWriteRuleID)
					}
				} else if awk.Action == "block" {
					t.Errorf("%s %q: blocked, want no block as the shell form %q (%v)", pack, wrapper+s.awk, s.shell, awk.RuleIDs)
				}
			}
		}
	}
}

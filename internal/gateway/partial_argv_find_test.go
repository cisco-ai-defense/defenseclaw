package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestPartialPowerShellFindArgvDoesNotPanic covers GAP-2410: Codex on
// Windows sends `find ... -exec cmd {} \;` as a Bash command that the
// gateway reads as PowerShell. That parse is partial and keeps the find's
// Program with no Argv, and findHasExecAction walked argv[1:], so the hook
// evaluator panicked and blocked a benign call in every fail mode.
func TestPartialPowerShellFindArgvDoesNotPanic(t *testing.T) {
	commands := []string{
		`find ~/t7d-scratch -name "*.sh" -exec echo {} \;`,
		`find ~/t7d-scratch -name "*.sh" -exec bash -n {} \;`,
		`find ~/t7d-scratch -name "*.sh" -exec timeout 5 bash -n {} \;`,
		`find ~/t7d-scratch -name "*.zip" -exec sh -c 'unzip -d "${1%.zip}" "$1"' _ {} \;`,
	}
	for _, command := range commands {
		facts := actionfacts.Analyze(actionfacts.Input{
			Tool:        "Bash",
			Command:     command,
			CWD:         `C:\Users\dcw2-std1\w`,
			ActiveHome:  `C:\Users\dcw2-std1`,
			DialectHint: actionfacts.DialectPowerShell,
		})
		sawEmptyFind := false
		for _, fact := range facts.Commands {
			if fact.Program == "find" && len(fact.Argv) == 0 {
				sawEmptyFind = true
			}
		}
		if !sawEmptyFind {
			t.Fatalf("%s: the fixture no longer yields a find with no argv; facts=%+v", command, facts.Commands)
		}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("%s: panic %v", command, recovered)
				}
			}()
			if factsHaveFindHandOff(facts) {
				t.Errorf("%s: a find with no argv must not read as a state hand-off", command)
			}
			for _, fact := range facts.Commands {
				for _, path := range facts.Paths {
					_ = provenPartialFindHandOff(facts, fact, path)
				}
				for _, access := range []actionfacts.PathAccess{
					actionfacts.PathAccessWrite, actionfacts.PathAccessRead, actionfacts.PathAccessDelete,
				} {
					_ = provenPartialFindHandOff(facts, fact, actionfacts.PathFact{Access: access})
				}
			}
		}()
	}
}

// TestArgvOperandHelpersTakeAnEmptyArgv keeps every helper that walks the
// words after the program safe for a command whose argv a partial parse
// withheld (GAP-2410 class).
func TestArgvOperandHelpersTakeAnEmptyArgv(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("panic %v", recovered)
		}
	}()
	for _, argv := range [][]string{nil, {}} {
		if len(argvOperands(argv)) != 0 || findHasExecAction(argv) ||
			posixRecursiveForceFlags(argv) || cmdRecursiveQuietFlags(argv) {
			t.Fatalf("argv %q: want no operands and false", argv)
		}
		_, _ = codexCatInputs(argv)
		for _, program := range []string{"find", "kubectl", "curl", "crontab"} {
			command := actionfacts.CommandFact{Program: program, Argv: argv}
			_ = staticKubernetesExecOuter(command)
			_ = toolValueLineageCurlHasUnsupportedMode(command)
			_ = findDeletesBesideItsExec(command)
			_ = factsHaveFindHandOff(actionfacts.Facts{Commands: []actionfacts.CommandFact{command}})
		}
	}
	if !findHasExecAction([]string{"find", ".", "-exec", "echo", "{}", ";"}) {
		t.Fatal("a find with -exec must still read as one")
	}
}

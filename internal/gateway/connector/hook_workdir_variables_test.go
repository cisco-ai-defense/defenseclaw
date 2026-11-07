package connector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// hookLinkDirs makes a managed hook and a link to it named linked-file in a
// directory outside, and an ordinary file linked by the same name in another.
// It returns the managed-link directory and the ordinary-link directory.
func hookLinkDirs(t *testing.T, home, hooks string) (managed, ordinary string) {
	t.Helper()
	owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
	managed = filepath.Dir(gap0625Link(t, owned, filepath.Join(home, "outside", "managed", "linked-file")))
	other := gap0625WriteExecutable(t, filepath.Join(home, "elsewhere", "ordinary-file"))
	ordinary = filepath.Dir(gap0625Link(t, other, filepath.Join(home, "outside", "ordinary", "linked-file")))
	return managed, ordinary
}

// The directory a command goes to may be held in a variable whose value the
// command sets first, in the ways a shell sets one. The managed link stays
// protected; the ordinary link of the same name stays the user's although a
// managed link of that name is in the directory of the scanning process.
func TestHookDirectoryHeldInVariableForms(t *testing.T) {
	forms := map[string]string{
		"plain":            `D=DIR; cd "$D" && bash ./linked-file`,
		"braces":           `D=DIR; cd "${D}"; bash ./linked-file`,
		"unquoted":         `D=DIR; cd $D && bash ./linked-file`,
		"export":           `export D=DIR; cd "$D" && bash ./linked-file`,
		"declare":          `declare D=DIR; cd "$D" && bash ./linked-file`,
		"subshell":         `D=DIR; ( cd "$D" && bash ./linked-file )`,
		"from a variable":  `P=DIR; D="$P"; cd "$D" && bash ./linked-file`,
		"with a suffix":    `P=DIRPARENT; cd "$P"/SUB && bash ./linked-file`,
		"for loop":         `for D in DIR; do cd "$D" && bash ./linked-file; done`,
		"reassigned":       `D=/nonexistent-g625; D=DIR; cd "$D" && bash ./linked-file`,
		"in a shell":       `D=DIR bash -c "cd \"\$D\" && bash ./linked-file"`,
		"exported to bash": `export D=DIR; bash -c "cd \"\$D\" && bash ./linked-file"`,
	}
	fill := func(form, dir string) string {
		out := strings.ReplaceAll(form, "DIRPARENT", shellWord(filepath.Dir(dir)))
		out = strings.ReplaceAll(out, "SUB", filepath.Base(dir))
		return strings.ReplaceAll(out, "DIR", shellWord(dir))
	}
	for name, form := range forms {
		t.Run(name+"/managed", func(t *testing.T) {
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				managed, _ := hookLinkDirs(t, home, hooks)
				command := fill(form, managed)
				gap0625RunsInBash(t, command)
				return command
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
		t.Run(name+"/ordinary", func(t *testing.T) {
			work := t.TempDir()
			t.Chdir(work)
			commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				managed, ordinary := hookLinkDirs(t, home, hooks)
				gap0625Link(t, filepath.Join(managed, "linked-file"), filepath.Join(work, "linked-file"))
				command := fill(form, ordinary)
				gap0625RunsInBash(t, command)
				return command
			})
			gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
		})
	}
	t.Run("last assignment wins", func(t *testing.T) {
		commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
			managed, ordinary := hookLinkDirs(t, home, hooks)
			command := "D=" + shellWord(managed) + "; D=" + shellWord(ordinary) + `; cd "$D" && bash ./linked-file`
			gap0625RunsInBash(t, command)
			return command
		})
		gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
	})
	t.Run("assignment in a subshell is gone", func(t *testing.T) {
		commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
			managed, ordinary := hookLinkDirs(t, home, hooks)
			command := "D=" + shellWord(managed) + "; ( D=" + shellWord(ordinary) + `; true ); cd "$D" && bash ./linked-file`
			gap0625RunsInBash(t, command)
			return command
		})
		gap0625ExpectProtected(t, verifyErr, commands, userHook)
	})
}

// A function body is read from the directory of each call, however the call
// and the change of directory are arranged, and a change of directory made by
// the function stays for the commands after the call.
func TestHookFunctionBodyReadAtEachCall(t *testing.T) {
	forms := map[string]string{
		"cd then call":         `f() { bash ./linked-file; }; cd DIR && f`,
		"keyword":              `function f { bash ./linked-file; }; cd DIR; f`,
		"subshell call":        `f() { bash ./linked-file; }; ( cd DIR; f )`,
		"nested functions":     `g() { bash ./linked-file; }; f() { g; }; cd DIR && f`,
		"function changes":     `f() { cd DIR; }; f; bash ./linked-file`,
		"call in substitution": `f() { bash ./linked-file; }; cd DIR && echo $(f)`,
		"called twice":         `f() { bash ./linked-file; }; f; cd DIR && f`,
	}
	for name, form := range forms {
		t.Run(name+"/managed", func(t *testing.T) {
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				managed, _ := hookLinkDirs(t, home, hooks)
				command := strings.ReplaceAll(form, "DIR", shellWord(managed))
				gap0625RunsInBash(t, command)
				return command
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
		if name == "called twice" {
			continue // the first call reads the scanning directory too
		}
		t.Run(name+"/ordinary", func(t *testing.T) {
			work := t.TempDir()
			t.Chdir(work)
			commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				managed, ordinary := hookLinkDirs(t, home, hooks)
				gap0625Link(t, filepath.Join(managed, "linked-file"), filepath.Join(work, "linked-file"))
				command := strings.ReplaceAll(form, "DIR", shellWord(ordinary))
				gap0625RunsInBash(t, command)
				return command
			})
			gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
		})
	}
}

// Nested shells and unexecuted branches are followed to any depth a command can
// have, not to a fixed small number.
func TestHookNestingAndBranchesBeyondSmallLimits(t *testing.T) {
	t.Run("five nested shells", func(t *testing.T) {
		commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
			managed, _ := hookLinkDirs(t, home, hooks)
			command := "cd " + shellWord(managed) + " && bash ./linked-file"
			for range 5 {
				command = "bash -c " + shellWord(command)
			}
			return command
		})
		gap0625ExpectProtected(t, verifyErr, commands, userHook)
	})
	t.Run("three hundred unexecuted branches", func(t *testing.T) {
		work := t.TempDir()
		t.Chdir(work)
		commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
			managed, _ := hookLinkDirs(t, home, hooks)
			gap0625Link(t, filepath.Join(managed, "linked-file"), filepath.Join(work, "actual", "linked-file"))
			var command strings.Builder
			for i := range 300 {
				dir := filepath.Join(home, "unused", strconv.Itoa(i%26), strconv.Itoa(i/26))
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				command.WriteString("if false; then cd " + shellWord(dir) + "; fi; ")
			}
			command.WriteString("cd actual && bash ./linked-file")
			gap0625RunsInBash(t, command.String())
			return command.String()
		})
		gap0625ExpectProtected(t, verifyErr, commands, userHook)
	})
}

// cd -P and env -C step to the physical parent of a link; plain cd steps to the
// logical one.
func TestHookPhysicalAndLogicalParentSteps(t *testing.T) {
	build := func(t *testing.T, home, hooks string) (alias, logicalFile, physicalFile string) {
		t.Helper()
		owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
		ordinary := gap0625WriteExecutable(t, filepath.Join(home, "elsewhere", "ordinary-file"))
		logical := filepath.Join(home, "outside", "logical")
		physical := filepath.Join(home, "outside", "physical")
		logicalFile = gap0625Link(t, ordinary, filepath.Join(logical, "linked-file"))
		physicalFile = gap0625Link(t, owned, filepath.Join(physical, "linked-file"))
		if err := os.MkdirAll(filepath.Join(physical, "child"), 0o700); err != nil {
			t.Fatal(err)
		}
		alias = gap0625Link(t, filepath.Join(physical, "child"), filepath.Join(logical, "alias"))
		return alias, logicalFile, physicalFile
	}
	for name, command := range map[string]string{
		"cd -P":  "cd -P ALIAS && cd .. && bash ./linked-file",
		"env -C": "env -C ALIAS/.. bash ./linked-file",
	} {
		t.Run(name+"/physical parent is managed", func(t *testing.T) {
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				alias, _, _ := build(t, home, hooks)
				command := strings.ReplaceAll(command, "ALIAS", shellWord(alias))
				gap0625RunsInBash(t, command)
				return command
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
	t.Run("cd -L logical parent is ordinary", func(t *testing.T) {
		commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
			alias, _, _ := build(t, home, hooks)
			command := "cd -L " + shellWord(alias) + " && cd .. && bash ./linked-file"
			gap0625RunsInBash(t, command)
			return command
		})
		gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
	})
}

// Options of an interpreter that take no value and run no code leave the next
// word the script file; an option that may hold code leaves the text to be read.
func TestHookInterpreterFlagsBeforeScript(t *testing.T) {
	for _, runner := range []string{"python3 -B ", "python3 -OO ", "python3 -u -B ", "python3 -- ", "perl -w ", "ruby -w ", "node --no-warnings ", "node -- "} {
		t.Run(strings.TrimSpace(runner)+"/ordinary", func(t *testing.T) {
			commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				script := gap0625WriteExecutable(t, filepath.Join(home, "outside", "ordinary; "+owned))
				return runner + shellWord(script)
			})
			gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
		})
	}
	for _, runner := range []string{"python3 -u -c ", "python3 -W ignore -c ", "node --no-warnings -e ", "perl -w -e "} {
		t.Run(strings.TrimSpace(runner)+"/command text", func(t *testing.T) {
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				return runner + shellWord("true; "+owned)
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
}

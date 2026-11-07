package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The name is explicitly a shell script, even when the file has disappeared.
func TestHookMissingScriptUnderManagedWorkDirectory(t *testing.T) {
	commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
		return "cd " + shellWord(hooks) + " && bash ./hookX"
	})
	gap0625ExpectProtected(t, verifyErr, commands, userHook)
}

// The directory value is known at the time the shell changes into it.
func TestHookDirectoryHeldInKnownVariable(t *testing.T) {
	commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
		owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned"))
		if err := os.WriteFile(owned, []byte("#!/bin/sh\necho managed\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		link := gap0625Link(t, owned, filepath.Join(home, "outside", "linked-file"))
		command := "D=" + shellWord(filepath.Dir(link)) + "; cd \"$D\" && bash ./linked-file"
		hookBashOutput(t, command, "managed")
		return command
	})
	gap0625ExpectProtected(t, verifyErr, commands, userHook)
}

// Default Bash cd uses the logical parent, not both possible parents.
func TestHookCdParentStepIsLogical(t *testing.T) {
	commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
		owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned"))
		logical := filepath.Join(home, "outside", "logical")
		physical := filepath.Join(home, "outside", "physical")
		ordinary := gap0625WriteExecutable(t, filepath.Join(logical, "linked-file"))
		if err := os.WriteFile(ordinary, []byte("#!/bin/sh\necho ordinary\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		gap0625Link(t, owned, filepath.Join(physical, "linked-file"))
		if err := os.MkdirAll(filepath.Join(physical, "child"), 0o700); err != nil {
			t.Fatal(err)
		}
		alias := gap0625Link(t, filepath.Join(physical, "child"), filepath.Join(logical, "alias"))
		command := "cd " + shellWord(alias) + " && cd .. && bash ./linked-file"
		out, err := exec.Command("bash", "-c", command).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "ordinary" {
			t.Fatalf("Bash used other file: out=%q err=%v", out, err)
		}
		return command
	})
	gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
}

// A legitimate Python option still leaves the next word as a script filename.
func TestHookInterpreterFlagLeavesScriptAsOneFile(t *testing.T) {
	for _, option := range []string{"-u", "--"} {
		t.Run(option, func(t *testing.T) {
			commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned"))
				script := gap0625WriteExecutable(t, filepath.Join(home, "outside", "ordinary; "+owned))
				if err := os.WriteFile(script, []byte("print('ordinary')\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				command := "python3 " + option + " " + shellWord(script)
				out, err := exec.Command("bash", "-c", command).CombinedOutput()
				if err != nil || strings.TrimSpace(string(out)) != "ordinary" {
					t.Fatalf("Python used other file: out=%q err=%v", out, err)
				}
				return command
			})
			gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
		})
	}
}

// Nesting four literal shell commands leaves the relative link protected.
func TestHookNestedShellsReadRelativeLink(t *testing.T) {
	commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
		owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned"))
		if err := os.WriteFile(owned, []byte("#!/bin/sh\necho managed\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		link := gap0625Link(t, owned, filepath.Join(home, "outside", "linked-file"))
		command := "cd " + shellWord(filepath.Dir(link)) + " && bash ./linked-file"
		for range 4 {
			command = "bash -c " + shellWord(command)
		}
		hookBashOutput(t, command, "managed")
		return command
	})
	gap0625ExpectProtected(t, verifyErr, commands, userHook)
}

// Function bodies run from the directory at invocation, after cd has executed.
func TestHookFunctionBodyReadFromDirectoryOfCallManaged(t *testing.T) {
	commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
		owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned"))
		if err := os.WriteFile(owned, []byte("#!/bin/sh\necho managed\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		link := gap0625Link(t, owned, filepath.Join(home, "outside", "linked-file"))
		command := "f() { bash ./linked-file; }; cd " + shellWord(filepath.Dir(link)) + " && f"
		hookBashOutput(t, command, "managed")
		return command
	})
	gap0625ExpectProtected(t, verifyErr, commands, userHook)
}

// A function is not read from the directory where it was defined.
func TestHookFunctionBodyReadFromDirectoryOfCallOrdinary(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
		owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned"))
		gap0625Link(t, owned, filepath.Join(work, "linked-file"))
		ordinary := gap0625WriteExecutable(t, filepath.Join(home, "outside", "ordinary"))
		link := gap0625Link(t, ordinary, filepath.Join(home, "outside", "linked-file"))
		command := "f() { bash ./linked-file; }; cd " + shellWord(filepath.Dir(link)) + " && f"
		gap0625RunsInBash(t, command)
		return command
	})
	gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
}

// The -C directory is opened before env changes directory for the program.
func TestHookEnvDirectoryOpenedBeforeItChanges(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
		gap0625Link(t, hooks, filepath.Join(work, "managed-dir"))
		command := "env -C ./managed-dir true"
		gap0625RunsInBash(t, command)
		return command
	})
	gap0625ExpectProtected(t, verifyErr, commands, userHook)
}

// Unexecuted branches must not evict the directory where Bash really stands.
func TestHookUnexecutedBranchesKeepActualDirectory(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
		owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned"))
		if err := os.WriteFile(owned, []byte("#!/bin/sh\necho managed\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		gap0625Link(t, owned, filepath.Join(work, "actual", "linked-file"))
		var command strings.Builder
		for i := range 16 {
			dir := filepath.Join(home, "outside", "unused"+strconv.Itoa(i))
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			command.WriteString("if false; then cd " + shellWord(dir) + "; fi; ")
		}
		command.WriteString("cd actual && bash ./linked-file")
		hookBashOutput(t, command.String(), "managed")
		return command.String()
	})
	gap0625ExpectProtected(t, verifyErr, commands, userHook)
}

func hookBashOutput(t *testing.T, command, want string) {
	t.Helper()
	out, err := exec.Command("bash", "-c", command).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != want {
		t.Fatalf("Bash executed %q: out=%q err=%v, want %q", command, out, err, want)
	}
}

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hookWorkDirForms are commands that open the relative name from the directory
// dir, each by a different way the shell has to get there. Every one is run
// through Bash by the tests, so a form here is a command that really opens it.
func hookWorkDirForms() map[string]func(dir, name string) string {
	w := shellWord
	return map[string]func(dir, name string) string{
		"cd and":         func(dir, name string) string { return "cd " + w(dir) + " && bash " + w(name) },
		"cd semicolon":   func(dir, name string) string { return "cd " + w(dir) + "; bash " + w(name) },
		"cd dashdash":    func(dir, name string) string { return "cd -- " + w(dir) + " && bash " + w(name) },
		"cd physical":    func(dir, name string) string { return "cd -P " + w(dir) + " && bash " + w(name) },
		"pushd":          func(dir, name string) string { return "pushd " + w(dir) + " >/dev/null && bash " + w(name) },
		"command cd":     func(dir, name string) string { return "command cd " + w(dir) + " && bash " + w(name) },
		"subshell":       func(dir, name string) string { return "(cd " + w(dir) + " && bash " + w(name) + ")" },
		"group":          func(dir, name string) string { return "{ cd " + w(dir) + "; bash " + w(name) + "; }" },
		"if":             func(dir, name string) string { return "if cd " + w(dir) + "; then bash " + w(name) + "; fi" },
		"or group":       func(dir, name string) string { return "false || { cd " + w(dir) + " && bash " + w(name) + "; }" },
		"pipeline":       func(dir, name string) string { return "cd " + w(dir) + " && true | bash " + w(name) },
		"substitution":   func(dir, name string) string { return "echo $(cd " + w(dir) + " && bash " + w(name) + ")" },
		"env -C":         func(dir, name string) string { return "env -C " + w(dir) + " bash " + w(name) },
		"env -C attach":  func(dir, name string) string { return "env -C" + w(dir) + " bash " + w(name) },
		"env --chdir=":   func(dir, name string) string { return "env --chdir=" + w(dir) + " bash " + w(name) },
		"env --chdir":    func(dir, name string) string { return "env --chdir " + w(dir) + " bash " + w(name) },
		"env assignment": func(dir, name string) string { return "env -i -C " + w(dir) + " X=1 bash " + w(name) },
		"sh -c":          func(dir, name string) string { return "sh -c " + w("cd "+w(dir)+" && bash "+w(name)) },
		"eval": func(dir, name string) string {
			return "eval " + w("cd "+w(dir)) + " " + w("&&") + " " + w("bash "+w(name))
		},
		"bash -lc twice": func(dir, name string) string {
			return "bash -lc " + w("sh -c "+w("cd "+w(dir)+" && bash "+w(name)))
		},
		"relative steps": func(dir, name string) string {
			return "cd " + w(filepath.Dir(dir)) + " && cd " + w(filepath.Base(dir)) + " && bash " + w(name)
		},
	}
}

// A relative word is the file of that name in the directory the command stands
// in when it reads the word, not in the directory of the process that scans
// it. Each form of changing directory opens a link to a managed hook, which
// stays protected, and an ordinary link of the same name, which stays the
// user's even when a managed link of that name is in the scanning directory.
func TestHookRelativeWordReadFromCommandDirectory(t *testing.T) {
	for name, form := range hookWorkDirForms() {
		t.Run(name+"/managed", func(t *testing.T) {
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				link := gap0625Link(t, owned, filepath.Join(home, "outside", "nested", "linked'file"))
				command := form(filepath.Dir(link), "./"+filepath.Base(link))
				gap0625RunsInBash(t, command)
				return command
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
		t.Run(name+"/ordinary", func(t *testing.T) {
			work := t.TempDir()
			t.Chdir(work)
			commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				gap0625Link(t, owned, filepath.Join(work, "linked'file"))
				other := gap0625WriteExecutable(t, filepath.Join(home, "elsewhere", "ordinary-file"))
				link := gap0625Link(t, other, filepath.Join(home, "outside", "nested", "linked'file"))
				command := form(filepath.Dir(link), "./"+filepath.Base(link))
				gap0625RunsInBash(t, command)
				return command
			})
			gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
		})
	}
}

// The directory word of cd may be written with the home directory.
func TestHookRelativeWordAfterHomeDirectoryChange(t *testing.T) {
	for _, home := range []string{"~", "$HOME", "${HOME}", `"$HOME"`} {
		t.Run(home, func(t *testing.T) {
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(userHome, hooks string) string {
				t.Setenv("HOME", userHome)
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				gap0625Link(t, owned, filepath.Join(userHome, "outside", "linked-file"))
				command := "cd " + home + "/outside && bash ./linked-file"
				gap0625RunsInBash(t, command)
				return command
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
}

// A directory that is not literal or does not exist leaves the shell where it
// was, so the relative word is read from there.
func TestHookRelativeWordAfterDirectoryChangeThatDoesNotHappen(t *testing.T) {
	for name, form := range map[string]string{
		"missing":      "cd %s && bash ./linked-file",
		"variable":     `cd "$UNSET_DIR_G625" && bash ./linked-file`,
		"substitution": `cd "$(echo %s)" && bash ./linked-file`,
	} {
		t.Run(name, func(t *testing.T) {
			work := t.TempDir()
			t.Chdir(work)
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				gap0625Link(t, owned, filepath.Join(work, "linked-file"))
				return strings.Replace(form, "%s", shellWord(filepath.Join(home, "no-such-dir")), 1)
			})
			// Read from where the scan stands, the link is the managed one.
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
}

// The hooks directory stays owned when a named file is gone: a relative spelling
// of it is managed from wherever the command stands, and a relative name of an
// ordinary missing file is not.
func TestHookRelativeMissingManagedHook(t *testing.T) {
	spell := map[string]func(t *testing.T, home, hooks string) string{
		"parent steps": func(t *testing.T, home, hooks string) string {
			cwd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			rel, err := filepath.Rel(cwd, filepath.Join(hooks, "hookX"))
			if err != nil {
				t.Fatal(err)
			}
			return "bash " + shellWord(rel)
		},
		"from root": func(t *testing.T, home, hooks string) string {
			t.Chdir("/")
			return "bash " + shellWord(strings.TrimPrefix(filepath.Join(hooks, "hookX"), "/"))
		},
		"after cd": func(t *testing.T, home, hooks string) string {
			outside := filepath.Join(home, "outside")
			if err := os.MkdirAll(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			rel, err := filepath.Rel(outside, filepath.Join(hooks, "hookX"))
			if err != nil {
				t.Fatal(err)
			}
			return "cd " + shellWord(outside) + " && bash " + shellWord(rel)
		},
		"env -C": func(t *testing.T, home, hooks string) string {
			outside := filepath.Join(home, "outside")
			if err := os.MkdirAll(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			rel, err := filepath.Rel(outside, filepath.Join(hooks, "hookX"))
			if err != nil {
				t.Fatal(err)
			}
			return "env -C " + shellWord(outside) + " bash " + shellWord(rel)
		},
		"through a link": func(t *testing.T, home, hooks string) string {
			link := gap0625Link(t, hooks, filepath.Join(home, "outside", "hooks-link"))
			t.Chdir(filepath.Dir(link))
			return "bash ./hooks-link/hookX"
		},
	}
	for name, build := range spell {
		t.Run(name+"/managed", func(t *testing.T) {
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				return build(t, home, hooks)
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
	t.Run("ordinary missing file", func(t *testing.T) {
		commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
			cwd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			rel, err := filepath.Rel(cwd, filepath.Join(home, "elsewhere", "gone"))
			if err != nil {
				t.Fatal(err)
			}
			return "bash " + shellWord(rel)
		})
		gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
	})
	t.Run("ordinary missing file in the hooks directory as working directory", func(t *testing.T) {
		commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
			t.Chdir(hooks)
			return "bash ./gone-script"
		})
		gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
	})
}

// The script a shell, source, "." or an interpreter opens is one file name,
// whatever characters it holds. A name that holds a separator and a managed
// path as characters is the user's file; the text a shell runs with -c is a
// command and still names what it names.
func TestHookScriptOperandIsOneFile(t *testing.T) {
	runners := []string{"bash ", "sh ", "source ", ". ", "bash -x ", "bash --norc ", "bash -o pipefail ", "bash -e -- ",
		"env bash ", "command sh ", "python3 ", "node ", "perl ", "ruby "}
	for _, runner := range runners {
		t.Run(strings.TrimSpace(runner)+"/ordinary", func(t *testing.T) {
			commands, entry, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				script := gap0625WriteExecutable(t, filepath.Join(home, "outside", "ordinary; "+owned))
				command := runner + shellWord(script)
				if strings.HasPrefix(runner, "bash") || strings.HasPrefix(runner, "sh") || strings.HasPrefix(runner, "source") ||
					strings.HasPrefix(runner, ".") || strings.HasPrefix(runner, "env") || strings.HasPrefix(runner, "command") {
					gap0625RunsInBash(t, command)
				}
				return command
			})
			gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
		})
	}
	for _, runner := range []string{"bash -c ", "sh -c ", "bash -lc ", "bash -o pipefail -c ", "eval ", "python3 -c ", "node -e "} {
		t.Run(strings.TrimSpace(runner)+"/command text", func(t *testing.T) {
			commands, _, userHook, verifyErr := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				// A file with this name exists, and the text is a command too.
				text := "true; " + owned
				gap0625WriteExecutable(t, filepath.Join(home, "outside", text))
				command := runner + shellWord(text)
				if strings.HasPrefix(runner, "bash") || strings.HasPrefix(runner, "sh") || runner == "eval " {
					gap0625RunsInBash(t, command)
				}
				return command
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
}

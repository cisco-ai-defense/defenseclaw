package connector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// gap0625HermesRun puts the command build returns into the Hermes config next
// to the user's own hook, then runs VerifyClean and Teardown. It returns the
// VerifyClean error, the commands left, the entry and the user's hook.
func gap0625HermesRun(t *testing.T, build func(home, hooks string) string) (error, []string, string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs POSIX links and file names")
	}
	conn, opts, configPath, _, userHook := gap0625HermesConfig(t, true)
	hooks := filepath.Join(opts.DataDir, "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := build(filepath.Dir(opts.DataDir), hooks)
	gap0625SetHermesCommand(t, configPath, entry)
	verifyErr := conn.VerifyClean(opts)
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	return verifyErr, gap0625PreToolCommands(t, configPath), entry, userHook
}

func gap0625WriteExecutable(t *testing.T, name string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return name
}

func gap0625Link(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link
}

func gap0625ExpectProtected(t *testing.T, verifyErr error, commands []string, userHook string) {
	t.Helper()
	if verifyErr == nil {
		t.Error("VerifyClean accepted a protected entry")
	}
	if len(commands) != 1 || commands[0] != userHook {
		t.Errorf("protected entry remains: %q", commands)
	}
}

func gap0625ExpectOrdinary(t *testing.T, verifyErr error, commands []string, entry, userHook string) {
	t.Helper()
	if verifyErr != nil {
		t.Errorf("ordinary entry marked managed by VerifyClean: %v", verifyErr)
	}
	if len(commands) != 2 || commands[0] != entry || commands[1] != userHook {
		t.Errorf("ordinary entry removed: %q", commands)
	}
}

// A ".." component steps up from where the link before it points, not from
// the link. The same command shape beside an ordinary directory stays.
func TestGAP0625PathScanParentStepAfterLink(t *testing.T) {
	t.Run("protected through outside link", func(t *testing.T) {
		verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
			if err := os.MkdirAll(filepath.Join(hooks, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			link := gap0625Link(t, filepath.Join(hooks, "sub"), filepath.Join(home, "outside", "link"))
			command := link + "/../owned-file"
			if actual, err := os.Stat(command); err != nil {
				t.Fatalf("command is not an executable path: %v", err)
			} else if expected, err := os.Stat(owned); err != nil || !os.SameFile(actual, expected) {
				t.Fatalf("command does not reach the protected file: %v", err)
			}
			return command
		})
		gap0625ExpectProtected(t, verifyErr, commands, userHook)
	})
	t.Run("protected through two links", func(t *testing.T) {
		verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
			if err := os.MkdirAll(filepath.Join(hooks, "a", "b"), 0o700); err != nil {
				t.Fatal(err)
			}
			first := gap0625Link(t, filepath.Join(hooks, "a", "b"), filepath.Join(home, "outside", "one"))
			second := gap0625Link(t, first, filepath.Join(home, "outside", "two"))
			return second + "/../../owned-file"
		})
		gap0625ExpectProtected(t, verifyErr, commands, userHook)
	})
	t.Run("ordinary beside outside link", func(t *testing.T) {
		verifyErr, commands, entry, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			gap0625WriteExecutable(t, filepath.Join(home, "tools", "owned-file"))
			if err := os.MkdirAll(filepath.Join(home, "tools", "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			link := gap0625Link(t, filepath.Join(home, "tools", "sub"), filepath.Join(home, "outside", "link"))
			return link + "/../owned-file"
		})
		gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
	})
}

// A file name can hold any number of commas, colons or equals signs: a link
// with such a name into the managed directory is protected however long the
// name is, and the same name for an ordinary file stays.
func TestGAP0625PathScanLongPunctuatedLink(t *testing.T) {
	for _, form := range []struct{ name, unit string }{{"comma", "a,"}, {"colon", "a:"}, {"equals", "a="}} {
		for _, count := range []int{31, 33, 100, 120} {
			name := strings.Repeat(form.unit, count) + "owned"
			t.Run(fmt.Sprintf("protected %s %d", form.name, count), func(t *testing.T) {
				verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
					owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
					return gap0625Link(t, owned, filepath.Join(home, name)) + " --event pre_tool_call"
				})
				gap0625ExpectProtected(t, verifyErr, commands, userHook)
			})
			t.Run(fmt.Sprintf("ordinary %s %d", form.name, count), func(t *testing.T) {
				verifyErr, commands, entry, userHook := gap0625HermesRun(t, func(home, hooks string) string {
					tool := gap0625WriteExecutable(t, filepath.Join(home, "tools", "tool"))
					return gap0625Link(t, tool, filepath.Join(home, name)) + " --event pre_tool_call"
				})
				gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
			})
		}
	}
}

// An existing file whose path holds a comma or colon followed by the managed
// directory is one ordinary path. A path word that does not exist, or that
// has a separator a shell would split on, still names the managed directory.
func TestGAP0625PathScanOrdinaryPathWithListPunctuation(t *testing.T) {
	for _, separator := range []string{",", ":", "="} {
		t.Run("existing "+separator, func(t *testing.T) {
			verifyErr, commands, entry, userHook := gap0625HermesRun(t, func(home, hooks string) string {
				return gap0625WriteExecutable(t, filepath.Join(home, "ordinary"+separator+hooks, "user-hook.sh"))
			})
			gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
		})
	}
	for _, separator := range []string{",", ":"} {
		t.Run("missing "+separator, func(t *testing.T) {
			verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
				return filepath.Join(home, "ordinary"+separator+hooks, "user-hook.sh")
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
		t.Run("list "+separator, func(t *testing.T) {
			verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
				tool := gap0625WriteExecutable(t, filepath.Join(home, "tools", "tool"))
				return tool + separator + filepath.Join(hooks, "hookX")
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
	t.Run("quoted existing path with space", func(t *testing.T) {
		verifyErr, commands, entry, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			return shellWord(gap0625WriteExecutable(t, filepath.Join(home, "ordinary ", hooks, "user-hook.sh")))
		})
		gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
	})
	t.Run("quoted command line", func(t *testing.T) {
		verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			return "sh -c " + shellWord("/bin/true "+filepath.Join(hooks, "hookX"))
		})
		gap0625ExpectProtected(t, verifyErr, commands, userHook)
	})
	t.Run("quoted missing path with space", func(t *testing.T) {
		verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			return shellWord(filepath.Join(home, "ordinary ", hooks, "user-hook.sh"))
		})
		gap0625ExpectProtected(t, verifyErr, commands, userHook)
	})
	t.Run("unquoted space", func(t *testing.T) {
		verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			return gap0625WriteExecutable(t, filepath.Join(home, "ordinary ", hooks, "user-hook.sh"))
		})
		gap0625ExpectProtected(t, verifyErr, commands, userHook)
	})
}

// A quoted word after the program is shell text or an argument, whether or not
// the same bytes name a file: "sh -c '<program>'" runs what follows the
// semicolon. Only a quoted program word is one path.
func TestGAP0625PathScanQuotedShellProgram(t *testing.T) {
	t.Run("sh -c program that is also a file name", func(t *testing.T) {
		verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
			program := gap0625WriteExecutable(t, filepath.Join(home, "ordinary; "+owned))
			return "sh -c " + shellWord(program)
		})
		gap0625ExpectProtected(t, verifyErr, commands, userHook)
	})
	t.Run("quoted argument that is also a file name", func(t *testing.T) {
		verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
			argument := gap0625WriteExecutable(t, filepath.Join(home, "ordinary; "+owned))
			tool := gap0625WriteExecutable(t, filepath.Join(home, "tools", "tool"))
			return tool + " " + shellWord(argument)
		})
		gap0625ExpectProtected(t, verifyErr, commands, userHook)
	})
	t.Run("quoted program that is also a file name", func(t *testing.T) {
		verifyErr, commands, entry, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
			return shellWord(gap0625WriteExecutable(t, filepath.Join(home, "ordinary; "+owned))) + " --event pre_tool_call"
		})
		gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
	})
	t.Run("sh -c ordinary program", func(t *testing.T) {
		verifyErr, commands, entry, userHook := gap0625HermesRun(t, func(home, hooks string) string {
			return "sh -c " + shellWord(gap0625WriteExecutable(t, filepath.Join(home, "ordinary ", "tool")))
		})
		gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
	})
}

// A list of ordinary paths is read to its end however long it is: no managed
// directory is named, so the entry stays the user's. The same list with a
// managed path at its end, or a link into the managed directory, is protected.
func TestGAP0625PathScanLongPathList(t *testing.T) {
	for _, count := range []int{220, 1000} {
		list := func(home string) string {
			paths := make([]string, count)
			for i := range paths {
				paths[i] = "/tmp/ordinary-path-" + strconv.Itoa(i)
			}
			return strings.Join(paths, ",")
		}
		t.Run(fmt.Sprintf("ordinary %d", count), func(t *testing.T) {
			verifyErr, commands, entry, userHook := gap0625HermesRun(t, func(home, hooks string) string {
				return gap0625WriteExecutable(t, filepath.Join(home, "tools", "user-tool")) + " --paths=" + list(home)
			})
			gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
		})
		t.Run(fmt.Sprintf("managed at the end %d", count), func(t *testing.T) {
			verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
				return gap0625WriteExecutable(t, filepath.Join(home, "tools", "user-tool")) + " --paths=" + list(home) + "," + filepath.Join(hooks, "hookX")
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
		t.Run(fmt.Sprintf("link at the end %d", count), func(t *testing.T) {
			verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				link := gap0625Link(t, owned, filepath.Join(home, "outside", "link"))
				return gap0625WriteExecutable(t, filepath.Join(home, "tools", "user-tool")) + " --paths=" + list(home) + "," + link
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
		t.Run(fmt.Sprintf("link then missing file %d", count), func(t *testing.T) {
			verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
				gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				link := gap0625Link(t, hooks, filepath.Join(home, "outside", "dirlink"))
				return gap0625WriteExecutable(t, filepath.Join(home, "tools", "user-tool")) + " --paths=" + list(home) + "," + link + "/gone/file"
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
}

// The work for one command is bounded, so a command made of thousands of path
// starts finishes at once and counts as naming the managed directory.
func TestGAP0625PathScanSpanBudget(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, ".defenseclaw", "hooks", "hook.sh")
	begin := time.Now()
	if !hookCommandNamesHookDir(strings.Repeat("/,", 5000), script) {
		t.Error("a command with thousands of path starts was not treated as managed")
	}
	if elapsed := time.Since(begin); elapsed > 5*time.Second {
		t.Errorf("bounded scan took %v", elapsed)
	}
}

// The program of a command is a word of the shell lexer, found by its position
// after the prefixes and not by the first byte of the text. A quoted literal
// that names an existing file is that one file, whatever bytes it holds. A word
// with a command substitution or backticks (in double quotes) is not a literal:
// the shell runs the substitution first, so a managed hook named inside it
// stays protected whatever file the bytes name. Single quotes keep both
// literal, so the same file name there is the user's program.
func TestGAP0625PathScanProgramWordTokens(t *testing.T) {
	prefixes := []string{
		"", "env ", "TOKEN=one ", "command ", "exec ", "nohup ", "nice ", "nice -n 5 ",
		"env -i TOKEN=one ", "env TOKEN=one command exec ", "TOKEN=one env ", "true && ",
	}
	quotings := []struct {
		name string
		word func(string) string
	}{
		{"single", shellWord},
		{"double", func(path string) string { return "\"" + path + "\"" }},
	}
	shapes := []struct {
		name    string
		file    func(home, owned string) string
		managed map[string]bool // quoting name -> a managed hook is run
	}{
		{"managed text in a file name", func(home, owned string) string { return filepath.Join(home, "ordinary; "+owned) }, nil},
		{"command substitution in a file name", func(home, owned string) string { return filepath.Join(home, "ordinary$("+owned+")") }, map[string]bool{"double": true}},
		{"backticks in a file name", func(home, owned string) string { return filepath.Join(home, "ordinary`"+owned+"`") }, map[string]bool{"double": true}},
	}
	for _, prefix := range prefixes {
		for _, quoting := range quotings {
			for _, shape := range shapes {
				name := fmt.Sprintf("%s|%s|%s", strings.TrimSpace(prefix), quoting.name, shape.name)
				t.Run(name, func(t *testing.T) {
					verifyErr, commands, entry, userHook := gap0625HermesRun(t, func(home, hooks string) string {
						owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
						program := gap0625WriteExecutable(t, shape.file(home, owned))
						return prefix + quoting.word(program) + " --event pre_tool_call"
					})
					if shape.managed[quoting.name] {
						gap0625ExpectProtected(t, verifyErr, commands, userHook)
					} else {
						gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
					}
				})
			}
		}
	}
}

// A prefix whose options are not read, and a program that is not a prefix, make
// the quoted word that follows an argument or a shell line: it stays protected
// when it names a managed hook, whatever file the bytes name.
func TestGAP0625PathScanProgramWordUnknownPrefix(t *testing.T) {
	for _, prefix := range []string{"env -S ", "sh -c ", "sudo ", "command -v ", "env -u "} {
		t.Run(strings.TrimSpace(prefix), func(t *testing.T) {
			verifyErr, commands, _, userHook := gap0625HermesRun(t, func(home, hooks string) string {
				owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
				program := gap0625WriteExecutable(t, filepath.Join(home, "ordinary; "+owned))
				return prefix + shellWord(program) + " --event pre_tool_call"
			})
			gap0625ExpectProtected(t, verifyErr, commands, userHook)
		})
	}
}

// The program word is the text the shell makes of all its parts: an escaped
// dollar sign or backtick is a plain character, and adjacent quoted or
// unquoted parts are one word. The existing ordinary file stays the user's
// program, so a managed path in its name is not a hook the entry runs. A part
// that is a real substitution next to literal parts keeps the whole word
// unread, and the managed hook named inside stays protected.
func TestGAP0625PathScanProgramWordEscapesAndAdjacentParts(t *testing.T) {
	prefixes := []string{"", "env ", "command ", "TOKEN=one exec "}
	// escape quotes the file name as one shell word the way the case needs.
	cases := []struct {
		name    string
		file    func(home, owned string) string
		word    func(program string) string
		managed bool
	}{
		{"escaped dollar in double quotes", func(home, owned string) string { return filepath.Join(home, "ordinary$("+owned+")") },
			func(program string) string { return "\"" + strings.ReplaceAll(program, "$", "\\$") + "\"" }, false},
		{"escaped backticks in double quotes", func(home, owned string) string { return filepath.Join(home, "ordinary`"+owned+"`") },
			func(program string) string { return "\"" + strings.ReplaceAll(program, "`", "\\`") + "\"" }, false},
		{"escaped quote and backslash in double quotes", func(home, owned string) string { return filepath.Join(home, "q\"b\\; "+owned) },
			func(program string) string {
				return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(program) + "\""
			}, false},
		{"double then single parts", func(home, owned string) string { return filepath.Join(home, "ordinary; "+owned) },
			func(program string) string {
				cut := strings.Index(program, ";") + 1
				return "\"" + program[:cut] + "\"'" + program[cut:] + "'"
			}, false},
		{"single then double then unquoted parts", func(home, owned string) string { return filepath.Join(home, "ordinary;"+owned) },
			func(program string) string {
				cut := strings.Index(program, ";") + 1
				return "'" + program[:cut] + "'\"" + program[cut:cut+3] + "\"" + program[cut+3:]
			}, false},
		{"escaped spaces unquoted", func(home, owned string) string { return filepath.Join(home, "ordinary; "+owned) },
			func(program string) string { return strings.NewReplacer(" ", "\\ ", ";", "\\;").Replace(program) }, false},
		{"quoted part next to a command substitution", func(home, owned string) string { return filepath.Join(home, "ordinary; "+owned) },
			func(program string) string { return "'" + program + "'\"$(" + program + ")\"" }, true},
		{"unquoted glob after a quoted part", func(home, owned string) string { return filepath.Join(home, "ordinary; "+owned) },
			func(program string) string { return "'" + program + "'*" }, true},
	}
	for _, prefix := range prefixes {
		for _, tc := range cases {
			t.Run(strings.TrimSpace(prefix)+"|"+tc.name, func(t *testing.T) {
				verifyErr, commands, entry, userHook := gap0625HermesRun(t, func(home, hooks string) string {
					owned := gap0625WriteExecutable(t, filepath.Join(hooks, "owned-file"))
					program := gap0625WriteExecutable(t, tc.file(home, owned))
					return prefix + tc.word(program) + " --event pre_tool_call"
				})
				if tc.managed {
					gap0625ExpectProtected(t, verifyErr, commands, userHook)
				} else {
					gap0625ExpectOrdinary(t, verifyErr, commands, entry, userHook)
				}
			})
		}
	}
}

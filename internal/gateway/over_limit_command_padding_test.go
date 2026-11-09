// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func overLimitCommandVerdict(t *testing.T, home, project, command string) string {
	t.Helper()
	call := nativeWriteCall{"codex", "exec_command", func(string) map[string]any {
		return map[string]any{"cmd": command, "workdir": project}
	}}
	return overLimitHostHook(t, "codex", home, call.body(t, project, project))
}

// TestOverLimitCommandPaddingKeepsItsVerdict pins that a shell command
// padded with white space past the 64 KiB command limit keeps the verdict of
// the same command unpadded (GAP-0934): the loader-preload and sudoers
// proofs read the protected redirect at every padding, before it,
// inside it and after it. The same padding on an ordinary command stays
// allowed.
func TestOverLimitCommandPaddingKeepsItsVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	for _, c := range []struct{ name, head, tail, rule string }{
		{"ld.so.preload redirect", "echo /usr/local/lib/libreview.so", " > /etc/ld.so.preload", "persistence.global_ld_preload_install"},
		{"ld.so.preload tee", "echo /usr/local/lib/libreview.so |", " tee -a /etc/ld.so.preload", "persistence.global_ld_preload_install"},
		{"sudoers", "echo 'agent ALL=(ALL) NOPASSWD: ALL'", " > /etc/sudoers.d/agent", "privilege.sudoers_unrestricted_nopasswd"},
	} {
		unpadded := overLimitCommandVerdict(t, home, project, c.head+c.tail)
		if overLimitHookAction(t, unpadded) != "block" || !strings.Contains(unpadded, c.rule) {
			t.Fatalf("%s: the unpadded command is not blocked by %s: %.600s", c.name, c.rule, unpadded)
		}
		for _, pad := range []int{70000, 900000} {
			for position, command := range map[string]string{
				"leading":  strings.Repeat(" ", pad) + c.head + c.tail,
				"inner":    c.head + strings.Repeat(" ", pad) + c.tail,
				"trailing": c.head + c.tail + strings.Repeat(" ", pad),
				"lines":    c.head + c.tail + strings.Repeat("\n  \n", pad/8),
			} {
				t.Run(fmt.Sprintf("%s/pad %d %s", c.name, pad, position), func(t *testing.T) {
					got := overLimitCommandVerdict(t, home, project, command)
					if overLimitHookAction(t, got) != "block" || !strings.Contains(got, c.rule) {
						t.Fatalf("not blocked by %s: %.600s", c.rule, got)
					}
				})
			}
		}
	}
	ordinary := filepath.Join(project, "notes.txt")
	for name, command := range map[string]string{
		"ordinary redirect":  "echo ok > " + ordinary + strings.Repeat(" ", 300000),
		"inner padding":      "echo ok" + strings.Repeat(" ", 300000) + "> " + ordinary,
		"protected read":     "cat /etc/ld.so.preload /etc/passwd" + strings.Repeat(" ", 300000),
		"leading line break": strings.Repeat("\n", 300000) + "echo ok > " + ordinary,
	} {
		t.Run("benign/"+name, func(t *testing.T) {
			got := overLimitCommandVerdict(t, home, project, command)
			if action := overLimitHookAction(t, got); action == "block" {
				t.Fatalf("ordinary padded command blocked: %.600s", got)
			}
		})
	}
}

// TestOverLimitCommandOpaqueTextFailsClosedForItsTargetOnly pins the verdict
// of a command over the 64 KiB limit by text (GAP-0934). Padded with
// comments it is judged as the same command without them, as every rule
// judges the small command: a statement that is blocked small is blocked
// large, one that is allowed small is allowed large, and a protected file
// named in a comment or in data is no write. Padded with text that is data
// (a quoted string, a here-document body), which has no twin, a protected
// file named directly as the target of a write still blocks under every
// spelling, and an ordinary command of the same size stays allowed.
func TestOverLimitCommandOpaqueTextFailsClosedForItsTargetOnly(t *testing.T) {
	home, project := hermesPatchHome(t)
	text := strings.Repeat("x", 70000)
	lib := "/usr/local/lib/libreview.so"
	paddings := map[string]func(statement string) string{
		"comment after":      func(statement string) string { return statement + " # " + text },
		"comment line next":  func(statement string) string { return statement + "\n# " + text },
		"comment line first": func(statement string) string { return "# " + text + "\n" + statement },
		"quoted text after":  func(statement string) string { return statement + "\n: \x27" + text + "\x27" },
		"quoted text first":  func(statement string) string { return ": \x27" + text + "\x27\n" + statement },
		"document after":     func(statement string) string { return statement + "\ncat > /dev/null <<EOF\n" + text + "\nEOF\n" },
		"stray quote before": func(statement string) string {
			return "cat <<EOF\nit\x27s\nEOF\n" + statement + "\n: \x27" + text + "\x27"
		},
	}
	for name, statement := range map[string]string{
		"redirect":         "echo " + lib + " > /etc/ld.so.preload",
		"dot segment":      "echo " + lib + " > /etc/./ld.so.preload",
		"double slash":     "echo " + lib + " >//etc//ld.so.preload",
		"quoted name":      "echo " + lib + " > \"/etc/ld.so.preload\"",
		"variable":         "F=/etc/ld.so.preload; echo " + lib + " > $F",
		"cd then relative": "cd /etc && echo " + lib + " > ld.so.preload",
	} {
		for padName, pad := range paddings {
			t.Run("attack/"+name+"/"+padName, func(t *testing.T) {
				got := overLimitCommandVerdict(t, home, project, pad(statement))
				if overLimitHookAction(t, got) != "block" || !strings.Contains(got, "persistence.global_ld_preload_install") {
					t.Fatalf("not blocked by the preload rule: %.600s", got)
				}
			})
		}
	}
	// Only a fallback reading, which has no twin, reads a write that the
	// small command does not show: the statements below are the same call
	// blocked small and large when they are padded with data.
	for name, statement := range map[string]string{
		"copy":    "cp " + lib + " /etc/ld.so.preload",
		"install": "install -m 644 " + lib + " /etc/ld.so.preload",
		"sudoers": "echo \x27agent ALL=(ALL) NOPASSWD: ALL\x27 > /etc/sudoers.d/agent",
	} {
		for _, padName := range []string{"quoted text after", "quoted text first"} {
			t.Run("fallback attack/"+name+"/"+padName, func(t *testing.T) {
				got := overLimitCommandVerdict(t, home, project, paddings[padName](statement))
				if overLimitHookAction(t, got) != "block" {
					t.Fatalf("not blocked: %.600s", got)
				}
			})
		}
	}
	notes := filepath.Join(project, "notes.txt")
	for name, statement := range map[string]string{
		"heredoc to an ordinary file": "cat > " + filepath.Join(project, "big.txt") + " <<\x27EOF\x27\nnote\nEOF\n",
		"protected read":              "cat /etc/ld.so.preload",
		"ordinary redirect":           "echo ok > " + notes,
		"unknown variable":            "echo ok > $OUT",
		"copy from a protected file":  "cp /etc/ld.so.preload " + filepath.Join(project, "copy.txt"),
		"neighbour name":              "echo ok > /etc/ld.so.preload.bak",
		"relative in the project":     "cd " + project + " && echo ok > ld.so.preload",
		"attack named in a string":    "printf \x27%s\\n\x27 \x27" + lib + " > /etc/ld.so.preload\x27 > " + notes,
		"attack named in a document":  "cat > " + notes + " <<\x27EOF\x27\n" + lib + " > /etc/ld.so.preload\nEOF\n",
	} {
		for _, padName := range []string{"comment after", "comment line next", "comment line first"} {
			t.Run("benign/"+name+"/"+padName, func(t *testing.T) {
				got := overLimitCommandVerdict(t, home, project, paddings[padName](statement))
				if action := overLimitHookAction(t, got); action == "block" {
					t.Fatalf("ordinary oversize command blocked: %.600s", got)
				}
			})
		}
	}
	for name, statement := range map[string]string{
		"protected read":    "cat /etc/ld.so.preload",
		"ordinary redirect": "echo ok > " + notes,
		"unknown variable":  "echo ok > $OUT",
	} {
		for _, padName := range []string{"quoted text after", "document after"} {
			t.Run("benign data padded/"+name+"/"+padName, func(t *testing.T) {
				got := overLimitCommandVerdict(t, home, project, paddings[padName](statement))
				if action := overLimitHookAction(t, got); action == "block" {
					t.Fatalf("ordinary oversize command blocked: %.600s", got)
				}
			})
		}
	}
}

// TestOverLimitCommandPaddingKeepsHeredocMeaning pins that padding a here-
// document line with white space does not change which line ends the
// document, so the statement the shell runs stays the statement judged: the
// padded delimiter line is not a delimiter in the original and not in the
// twin, and the redirect below it is the document text, not a command
// (GAP-0934). A real delimiter followed by the redirect blocks.
func TestOverLimitCommandPaddingKeepsHeredocMeaning(t *testing.T) {
	home, project := hermesPatchHome(t)
	notes := filepath.Join(project, "notes.txt")
	attack := "echo /usr/local/lib/libreview.so > /etc/ld.so.preload"
	for name, command := range map[string]string{
		"trailing padded delimiter": "cat > " + notes + " <<EOF\nnote\nEOF" + strings.Repeat(" ", 70000) + "\n" + attack + "\nEOF\n",
		"leading padded delimiter":  "cat > " + notes + " <<EOF\nnote\n" + strings.Repeat(" ", 70000) + "EOF\n" + attack + "\nEOF\n",
		"tab padded dash delimiter": "cat > " + notes + " <<-EOF\nnote\n" + strings.Repeat("\t", 70000) + "EOF\nEOF\n",
		"padded line in a document": "cat > " + notes + " <<EOF\nnote" + strings.Repeat(" ", 70000) + "\n" + attack + "\nEOF\n",
	} {
		t.Run("benign/"+name, func(t *testing.T) {
			got := overLimitCommandVerdict(t, home, project, command)
			if action := overLimitHookAction(t, got); action == "block" {
				t.Fatalf("ordinary here-document blocked: %.600s", got)
			}
		})
	}
	t.Run("attack/delimiter then redirect", func(t *testing.T) {
		got := overLimitCommandVerdict(t, home, project, "cat > "+notes+" <<EOF\nnote\nEOF\n"+attack+strings.Repeat(" ", 70000))
		if overLimitHookAction(t, got) != "block" || !strings.Contains(got, "persistence.global_ld_preload_install") {
			t.Fatalf("not blocked by the preload rule: %.600s", got)
		}
	})
}

// TestOverLimitCommandDataPaddingFollowsShellOrder pins that a command padded
// with data (a quoted string) is read in the order the shell runs it
// (GAP-0934): a later cd or assignment replaces the earlier one, the body of a
// here-document that only feeds a file is data, and a text a command prints
// is no write. A protected file reached through a known directory or a known
// relative value still blocks, and a here-document or a string run by a shell
// is code.
func TestOverLimitCommandDataPaddingFollowsShellOrder(t *testing.T) {
	home, project := hermesPatchHome(t)
	notes := filepath.Join(project, "notes.txt")
	lib := "/usr/local/lib/libreview.so"
	load := "echo " + lib + " > /etc/ld.so.preload"
	text := strings.Repeat("x", 70000)
	paddings := map[string]func(statement string) string{
		"quoted text after": func(statement string) string { return statement + "\n: \x27" + text + "\x27" },
		"quoted text first": func(statement string) string { return ": \x27" + text + "\x27\n" + statement },
		"document after":    func(statement string) string { return statement + "\ncat > /dev/null <<EOF\n" + text + "\nEOF\n" },
	}
	for name, statement := range map[string]string{
		"here-document to an ordinary file":     "cat > " + notes + " <<\x27EOF\x27\n" + load + "\nEOF\n",
		"here-document with a padded delimiter": "cat > " + notes + " <<EOF\nnote\nEOF \n" + load + "\nEOF\n",
		"cd superseded before a relative write": "cd /etc; cd " + project + "; echo " + lib + " > ld.so.preload",
		"variable reassigned before the write":  "F=/etc/ld.so.preload; F=" + notes + "; echo " + lib + " > \"$F\"",
		"relative value in the project":         "cd " + project + "; F=ld.so.preload; echo " + lib + " > \"$F\"",
		"printed text names a redirect":         "printf \x27%s\\n\x27 \x27" + load + "\x27 > " + notes,
		"redirect in a comment":                 "echo ok > " + notes + " # " + load,
		"printed copy words, unquoted":          "printf \x27%s\\n\x27 cp " + lib + " /etc/ld.so.preload > " + notes,
		"printed copy words, quoted":            "printf \x27%s\\n\x27 \x27cp " + lib + " /etc/ld.so.preload\x27 > " + notes,
		"unquoted document, plain body":         "cat > " + notes + " <<EOF\n" + load + "\nEOF\n",
		"quoted document, literal substitution": "cat > " + notes + " <<\x27EOF\x27\n$(" + load + ")\nEOF\n",
		"escaped delimiter, literal backtick":   "cat > " + notes + " <<\\EOF\n`" + load + "`\nEOF\n",
		"escaped substitution in a body":        "cat > " + notes + " <<EOF\n\\$(" + load + ")\nEOF\n",
		"ordinary substitution in a body":       "cat > " + notes + " <<EOF\n$(date) $(echo note)\nEOF\n",
		"exported variable reassigned":          "export F=/etc/ld.so.preload; export F=" + notes + "; echo ok > \"$F\"",
	} {
		for padName, pad := range paddings {
			t.Run("benign/"+name+"/"+padName, func(t *testing.T) {
				got := overLimitCommandVerdict(t, home, project, pad(statement))
				if action := overLimitHookAction(t, got); action == "block" {
					t.Fatalf("ordinary oversize command blocked: %.600s", got)
				}
			})
		}
	}
	for name, statement := range map[string]string{
		"known relative value":                   "cd /etc; F=ld.so.preload; echo " + lib + " > \"$F\"",
		"relative value before the cd":           "F=ld.so.preload; cd /etc; echo " + lib + " > \"$F\"",
		"cd up from a subdirectory":              "cd /etc/x; cd ..; echo " + lib + " > ld.so.preload",
		"cd back with a dash":                    "cd /etc; cd " + project + "; cd -; echo " + lib + " > ld.so.preload",
		"cd that may fail":                       "cd /etc; cd " + project + " || true; echo " + lib + " > ld.so.preload",
		"exported variable":                      "export F=/etc/ld.so.preload; echo " + lib + " > \"$F\"",
		"here-document run by a shell":           "sh <<EOF\n" + load + "\nEOF\n",
		"here-document piped to a shell":         "cat <<EOF | bash\n" + load + "\nEOF\n",
		"string run by a shell":                  "sh -c \x27" + load + "\x27",
		"string run by a shell with a cd":        "bash -c \x27cd /etc && echo " + lib + " > ld.so.preload\x27",
		"redirect after a data here-document":    "cat > " + notes + " <<EOF\nnote\nEOF\n" + load,
		"function that runs in the directory":    "f() { echo " + lib + " > ld.so.preload; }; cd /etc; f",
		"tee with a quoted operand":              "echo " + lib + " | tee \"/etc/ld.so.preload\"",
		"redirect after a printed text":          "echo \x27tee x\x27; " + load,
		"redirect after unquoted printed words":  "echo cp a b > /etc/ld.so.preload",
		"substitution in an unquoted document":   "cat > " + notes + " <<EOF\n$(" + load + ")\nEOF\n",
		"substitution, normalized target":        "cat > " + notes + " <<EOF\n$(echo " + lib + " > /etc/./ld.so.preload)\nEOF\n",
		"backtick in an unquoted document":       "cat > " + notes + " <<EOF\n`" + load + "`\nEOF\n",
		"substitution after an escaped one":      "cat > " + notes + " <<EOF\n\\$(x) $(" + load + ")\nEOF\n",
		"directory variable and relative target": "cd /etc; D=pam.d; echo \x27auth sufficient pam_permit.so\x27 > $D/sshd",
	} {
		for padName, pad := range paddings {
			t.Run("attack/"+name+"/"+padName, func(t *testing.T) {
				got := overLimitCommandVerdict(t, home, project, pad(statement))
				if overLimitHookAction(t, got) != "block" {
					t.Fatalf("not blocked: %.600s", got)
				}
			})
		}
	}
}

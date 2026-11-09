// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func overLimitCommandInput(t *testing.T, tool, command string) (Input, Facts) {
	t.Helper()
	input := Input{Tool: tool, Args: overLimitArgs(t, map[string]any{"cmd": command, "workdir": "/srv/app"})}
	return input, Analyze(input)
}

// TestOverLimitCommandBoundedTwin pins that a command over the string limit
// by white space padding has a twin that reads as the unpadded command: the
// protected redirect is a path fact of it. Text padding has none, nor does a
// structured write tool or a call within the limits.
func TestOverLimitCommandBoundedTwin(t *testing.T) {
	const attack = "echo /usr/local/lib/libreview.so > /etc/ld.so.preload"
	for _, c := range []struct{ name, command string }{
		{"trailing", attack + strings.Repeat(" ", 300000)},
		{"leading", strings.Repeat("\t", 300000) + attack},
		{"inner", "echo /usr/local/lib/libreview.so" + strings.Repeat(" ", 300000) + "> /etc/ld.so.preload"},
		{"line breaks", attack + strings.Repeat("\n \n", 100000)},
		{"comment after", attack + " # " + strings.Repeat("x", 300000)},
		{"comment line before", "# " + strings.Repeat("x", 300000) + "\n" + attack},
		{"comment lines between", "echo a\n# " + strings.Repeat("x", 300000) + "\n" + attack},
		{"comment beside a here-document", "cat <<\x27EOF\x27 # " + strings.Repeat("x", 300000) + "\nnote\nEOF\n" + attack},
	} {
		t.Run(c.name, func(t *testing.T) {
			input, facts := overLimitCommandInput(t, "exec_command", c.command)
			if facts.Parse.Status != StatusLimitExceeded {
				t.Fatalf("not limit-exceeded: %s", facts.Parse.Status)
			}
			twin, ok := OverLimitCommandBoundedTwin(input, facts)
			if !ok {
				t.Fatal("no twin")
			}
			view := Analyze(twin)
			if view.Parse.Status == StatusLimitExceeded {
				t.Fatalf("twin still exceeds a limit: %s", view.Parse.Status)
			}
			found := false
			for _, path := range view.Paths {
				found = found || path.Normalized == "/etc/ld.so.preload"
			}
			if !found {
				t.Fatalf("the twin has no path fact for the protected redirect: %s", twin.Args)
			}
		})
	}
	for name, opaque := range map[string]string{
		"quoted text":           attack + "\n: \x27" + strings.Repeat("x", 300000) + "\x27",
		"here-document text":    attack + "\ncat <<EOF\n" + strings.Repeat("x", 300000) + "\nEOF\n",
		"hash inside a quote":   attack + "\necho \"# " + strings.Repeat("x", 300000) + "\"",
		"hash inside a word":    attack + "\necho a#" + strings.Repeat("x", 300000),
		"hash in a body":        attack + "\ncat <<EOF\n# " + strings.Repeat("x", 300000) + "\nEOF\n",
		"expansion with a hash": attack + "\necho ${#PATH} # " + strings.Repeat("x", 300000),
	} {
		input, facts := overLimitCommandInput(t, "exec_command", opaque)
		if _, ok := OverLimitCommandBoundedTwin(input, facts); ok {
			t.Fatalf("%s: text that is no padding has a twin", name)
		}
	}
	input, facts := overLimitCommandInput(t, "exec_command", "echo ok")
	if _, ok := OverLimitCommandBoundedTwin(input, facts); ok {
		t.Fatal("a call within the limits has a twin")
	}
	patch := Input{Tool: "apply_patch", Args: overLimitArgs(t, map[string]any{"command": "*** Begin Patch\n*** Add File: /srv/a\n+" + strings.Repeat(" ", 300000) + "\n*** End Patch\n"})}
	if _, ok := OverLimitCommandBoundedTwin(patch, Analyze(patch)); ok {
		t.Fatal("a structured write tool has a command twin")
	}
}

// TestBoundedCommandText pins the bounded form: only a line of white space
// longer than maxKeptWhiteSpaceRun changes, to one byte of its kind, every
// line break stays up to maxKeptWhiteSpaceRun of them, and the meaning of a
// here-document line is the original (GAP-0934).
func TestBoundedCommandText(t *testing.T) {
	short := strings.Repeat(" ", maxKeptWhiteSpaceRun)
	long := strings.Repeat(" ", maxCommandBytes)
	for _, c := range []struct {
		name, text, want string
		ok               bool
	}{
		{"short runs stay", "a" + short + "b" + strings.Repeat("c", maxCommandBytes), "", false},
		{"long run is one space", "a" + long + "b", "a b", true},
		{"long tab run is one tab", "a" + strings.Repeat("\t", maxCommandBytes) + "b", "a\tb", true},
		{"line of blanks keeps its break", "a" + long + "\nb", "a \nb", true},
		{"padding after a here-document word keeps the line not a delimiter", "cat <<EOF\nx\nEOF" + long + "\nEOF\n", "cat <<EOF\nx\nEOF \nEOF\n", true},
		{"padding before a word keeps the line not a delimiter", "cat <<EOF\nx\n" + long + "EOF\nEOF\n", "cat <<EOF\nx\n EOF\nEOF\n", true},
		{"short run kept beside a long one", "a" + short + "b" + long + "c", "a" + short + "b c", true},
		{"empty lines past the bound go, the indent stays", "a" + strings.Repeat("\n", maxCommandBytes) + "  b", "a" + strings.Repeat("\n", maxKeptWhiteSpaceRun) + "  b", true},
		{"no-break space is a word byte", "a" + strings.Repeat("\u00a0", maxCommandBytes) + "b", "", false},
		{"carriage return is a word byte", "a" + strings.Repeat("\r", maxCommandBytes) + "b", "", false},
		{"all white space", long + "  ", "", false},
		{"blank here-document delimiter", "cat <<\x27 \x27\nx\n" + long + "\n \n", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := boundedCommandText(c.text)
			if ok != c.ok || (ok && got != c.want) {
				t.Fatalf("got %q ok=%t, want %q ok=%t", got, ok, c.want, c.ok)
			}
		})
	}
}

// TestOverLimitCommandContentTarget pins the reading of a command that is
// over the limit by text (GAP-0934): a protected file named directly as the
// target of a write is found under every spelling the shell reads as that
// file, wherever the text puts it, and an ordinary file, a read, or a name
// that depends on the environment is not.
func TestOverLimitCommandContentTarget(t *testing.T) {
	opaque := "\n: \x27" + strings.Repeat("x", 70000) + "\x27"
	for _, c := range []struct{ name, command, class string }{
		{"plain redirect", "echo a > /etc/ld.so.preload", "global-preload"},
		{"dot segment", "echo a > /etc/./ld.so.preload", "global-preload"},
		{"parent segment", "echo a > /etc/x/../ld.so.preload", "global-preload"},
		{"double slash", "echo a >//etc//ld.so.preload", "global-preload"},
		{"append", "echo a >> /etc/ld.so.preload", "global-preload"},
		{"clobber", "echo a >| /etc/ld.so.preload", "global-preload"},
		{"both streams", "echo a &> /etc/ld.so.preload", "global-preload"},
		{"double quoted", "echo a > \"/etc/ld.so.preload\"", "global-preload"},
		{"single quoted part", "echo a > /etc/\x27ld.so.preload\x27", "global-preload"},
		{"escaped byte", "echo a > /etc/ld.so.pre\\load", "global-preload"},
		{"tee", "echo a | tee -a /etc/ld.so.preload", "global-preload"},
		{"tee by path", "echo a | /usr/bin/tee /srv/app/out /etc/ld.so.preload", "global-preload"},
		{"cp", "cp lib.so /etc/ld.so.preload", "global-preload"},
		{"mv with options", "mv -f lib.so /etc/ld.so.preload", "global-preload"},
		{"install", "install -m 644 lib.so /etc/ld.so.preload", "global-preload"},
		{"ln", "ln -sf lib.so /etc/ld.so.preload", "global-preload"},
		{"cp then a comment on the line", "cp lib.so /etc/ld.so.preload # keep the copy", "global-preload"},
		{"tee then a comment on the line", "echo a | tee /etc/ld.so.preload # keep the copy", "global-preload"},
		{"cp to an ordinary file, a protected name in the comment", "cp lib.so /srv/app/x # /etc/ld.so.preload", ""},
		{"dd", "dd if=lib.so of=/etc/ld.so.preload", "global-preload"},
		{"variable file", "F=/etc/ld.so.preload; echo a > $F", "global-preload"},
		{"variable directory", "D=/etc\necho a > \"${D}/ld.so.preload\"", "global-preload"},
		{"variable of a variable", "D=/etc; F=$D/ld.so.preload; echo a > $F", "global-preload"},
		{"cd then relative", "cd /etc && echo a > ld.so.preload", "global-preload"},
		{"cd variable then relative", "D=/etc; cd $D; echo a > ld.so.preload", "global-preload"},
		{"cd superseded by another cd", "cd /etc; cd /tmp; echo a > ld.so.preload", ""},
		{"cd superseded by an unknown cd keeps the directory", "cd /etc; cd $WHERE; echo a > ld.so.preload", "global-preload"},
		{"cd back with a dash", "cd /etc; cd /tmp; cd -; echo a > ld.so.preload", "global-preload"},
		{"cd to the home that was set", "export HOME=/etc; cd; echo a > ld.so.preload", "global-preload"},
		{"cd up from a subdirectory", "cd /etc/x; cd ..; echo a > ld.so.preload", "global-preload"},
		{"cd by two steps", "cd /; cd etc; echo a > ld.so.preload", "global-preload"},
		{"cd with a guard", "cd /etc || exit 1; echo a > ld.so.preload", "global-preload"},
		{"cd in a subshell does not supersede", "cd /etc; (cd /tmp); echo a > ld.so.preload", "global-preload"},
		{"cd in a pipeline does not supersede", "cd /etc; cd /tmp | cat; echo a > ld.so.preload", "global-preload"},
		{"cd in a quoted string does not supersede", "cd /etc; echo \x27cd /tmp\x27; echo a > ld.so.preload", "global-preload"},
		{"cd that may fail keeps the directory", "cd /etc; cd /tmp || true; echo a > ld.so.preload", "global-preload"},
		{"pushd", "pushd /etc; echo a > ld.so.preload", "global-preload"},
		{"cd in a function", "f() { echo a > ld.so.preload; }; cd /etc; f", "global-preload"},
		{"cd in a loop", "for d in a; do cd /etc; done; echo a > ld.so.preload", "global-preload"},
		{"cd in a here-document to a shell", "sh <<EOF\ncd /etc\necho a > ld.so.preload\nEOF", "global-preload"},
		{"relative value then cd", "F=ld.so.preload; cd /etc; echo a > \"$F\"", "global-preload"},
		{"cd then relative value", "cd /etc; F=ld.so.preload; echo a > \"$F\"", "global-preload"},
		{"cd then relative value in braces", "cd /etc; F=ld.so.preload; echo a > \"${F}\"", "global-preload"},
		{"relative value of a directory", "cd /etc; D=pam.d; echo a > $D/sshd", "pam"},
		{"relative value in the project", "cd /srv/app; F=ld.so.preload; echo a > \"$F\"", ""},
		{"exported variable", "export F=/etc/ld.so.preload; echo a > $F", "global-preload"},
		{"exported variable reassigned", "export F=/etc/ld.so.preload; export F=/srv/app/n; echo a > $F", ""},
		{"variable reassigned", "F=/etc/ld.so.preload; F=/srv/app/notes.txt; echo a > \"$F\"", ""},
		{"variable reassigned to an unknown value", "F=/etc/ld.so.preload; F=$OUT; echo a > $F", ""},
		{"variable of a prefix assignment keeps the value", "F=/etc/ld.so.preload; F=x true; echo a > $F", "global-preload"},
		{"variable in a quoted string does not replace", "F=/etc/ld.so.preload; echo \x27F=/tmp/x\x27; echo a > $F", "global-preload"},
		{"variable assigned in a group", "{ F=/etc/ld.so.preload; }; F=/srv/app/n; echo a > $F", "global-preload"},
		{"document to a data reader", "cat > /srv/app/f <<\x27EOF\x27\necho a > /etc/ld.so.preload\nEOF\n", ""},
		{"document to tee still writes its operand", "tee /etc/ld.so.preload <<EOF\nlib\nEOF\n", "global-preload"},
		{"document with a padded delimiter line is data", "cat > /srv/app/f <<EOF\nnote\nEOF \necho a > /etc/ld.so.preload\nEOF\n", ""},
		{"document ended, then a redirect", "cat > /srv/app/f <<EOF\nnote\nEOF\necho a > /etc/ld.so.preload\n", "global-preload"},
		{"document with a dash delimiter", "cat > /srv/app/f <<-EOF\n\tnote\n\tEOF\necho a > /etc/ld.so.preload\n", "global-preload"},
		{"document to a shell", "sh <<EOF\necho a > /etc/ld.so.preload\nEOF\n", "global-preload"},
		{"document to a shell through a pipe", "cat <<EOF | sh\necho a > /etc/ld.so.preload\nEOF\n", "global-preload"},
		{"document to a shell by name", "bash -s <<EOF\necho a > /etc/ld.so.preload\nEOF\n", "global-preload"},
		{"document opened in arithmetic", "((i<<EOF))\necho a > /etc/ld.so.preload\nEOF\n", "global-preload"},
		{"document opened in a group", "{ cat; } <<EOF\necho a > /etc/ld.so.preload\nEOF\n", "global-preload"},
		{"document opened in a loop", "while read x; do :; done <<EOF\necho a > /etc/ld.so.preload\nEOF\n", "global-preload"},
		{"document that never ends", "cat > /srv/app/f <<EOF\necho a > /etc/ld.so.preload\n", ""},
		{"redirect in a comment", "echo ok # echo a > /etc/ld.so.preload", ""},
		{"redirect after a comment line", "# note\necho a > /etc/ld.so.preload", "global-preload"},
		{"redirect after a hash in a word", "echo a#b > /etc/ld.so.preload", "global-preload"},
		{"shell command string", "sh -c \x27echo a > /etc/ld.so.preload\x27; echo ok", "global-preload"},
		{"shell command string with cd", "bash -c \x27cd /etc && echo a > ld.so.preload\x27", "global-preload"},
		{"shell command string in double quotes", "sudo sh -c \"echo a > /etc/ld.so.preload\"; echo ok", "global-preload"},
		{"eval string", "eval \x27echo a > /etc/ld.so.preload\x27", "global-preload"},
		{"write after a quoted cd", "sh -c \x27cd /srv\x27; echo a > /etc/ld.so.preload", "global-preload"},
		{"write after a quoted writer", "echo \x27tee x\x27; echo a > /etc/ld.so.preload", "global-preload"},
		{"quoted operand of tee", "echo a | tee \"/etc/ld.so.preload\"", "global-preload"},
		{"quoted operand of cp", "cp lib.so \"/etc/ld.so.preload\"", "global-preload"},
		{"printed text names a redirect", "printf \x27%s\\n\x27 \x27echo a > /etc/ld.so.preload\x27 > /srv/app/n", ""},
		{"echoed text names a copy", "echo \"cp x /etc/ld.so.preload\" > /srv/app/n", ""},
		{"unreadable text keeps every cd", "cd /etc; cd /tmp; cat <(ls) > ld.so.preload", "global-preload"},
		{"substitution keeps the order of cd", "cd /etc; cd /tmp; echo $(date) > ld.so.preload", ""},
		{"cd in a substitution does not move the shell", "x=$(cd /etc; pwd); echo a > /srv/app/ld.so.preload", ""},
		{"cd in a substitution writes there", "x=$(cd /etc && echo a > ld.so.preload)", "global-preload"},
		{"cd in a backtick writes there", "x=`cd /etc && echo a > ld.so.preload`", "global-preload"},
		{"cd in a nested substitution writes there", "echo $(echo $(cd /etc; echo a > ld.so.preload))", "global-preload"},
		{"assignment in a substitution does not move the shell", "x=$(F=/etc/ld.so.preload; echo ok); F=/srv/app/n; echo a > \"$F\"", ""},
		{"assignment in a substitution writes there", "x=$(F=/etc/ld.so.preload; echo a > \"$F\")", "global-preload"},
		{"cd after a substitution", "echo $(date); cd /etc; echo a > ld.so.preload", "global-preload"},
		{"cd before a substitution", "cd /etc; echo $(date); echo a > ld.so.preload", "global-preload"},
		{"cd back before a substitution", "cd /etc; cd /srv/app; echo $(date); echo a > ld.so.preload", ""},
		{"variable reassigned around a substitution", "F=/etc/ld.so.preload; echo $(date); F=/srv/app/n; echo a > \"$F\"", ""},
		{"variable kept around a substitution", "F=/etc/ld.so.preload; echo $(date); echo a > \"$F\"", "global-preload"},
		{"braced default in printed words", "echo ${F:-a > /etc/ld.so.preload } > /srv/app/n", ""},
		{"braced default around a substitution", "echo ${F:-$(echo a > /etc/ld.so.preload)} > /srv/app/n", "global-preload"},
		{"braced default in a here-document", "cat > /srv/app/n <<EOF\n${F:-echo a > /etc/ld.so.preload }\nEOF\n", ""},
		{"substitution in a braced default in a here-document", "cat > /srv/app/n <<EOF\n${F:-$(echo a > /etc/ld.so.preload)}\nEOF\n", "global-preload"},
		{"cd in a substitution in a here-document", "cat > /srv/app/n <<EOF\n$(cd /etc && echo a > ld.so.preload)\nEOF\n", "global-preload"},
		{"cd in a substitution in a here-document, then a relative write", "cat > /srv/app/n <<EOF\n$(cd /etc)\nEOF\necho a > ld.so.preload", ""},
		{"assigning braced expansion in printed words", "echo ${F:=echo a > /etc/ld.so.preload } > /srv/app/n", ""},
		{"assigning braced expansion in a here-document", "cat > /srv/app/n <<EOF\n${F:=echo a > /etc/ld.so.preload }\nEOF\n", ""},
		{"assigning braced expansion after a superseded cd", "cd /etc; cd /srv/app; echo ${F:=ok}; echo a > ld.so.preload", ""},
		{"assigning braced expansion after a superseded value", "F=/etc/ld.so.preload; F=/srv/app/n; echo ${G:=ok}; echo a > \"$F\"", ""},
		{"assigning braced expansion between a superseded value", "F=/etc/ld.so.preload; echo ${G=ok}; F=/srv/app/n; echo a > \"$F\"", ""},
		{"subscripted expansion after a superseded cd", "cd /etc; cd /srv/app; echo ${a[0]}; echo a > ld.so.preload", ""},
		{"assigning braced expansion keeps the cd", "cd /etc; echo ${F:=ok}; echo a > ld.so.preload", "global-preload"},
		{"assigning braced expansion around a substitution", "echo ${F:=$(echo a > /etc/ld.so.preload)} > /srv/app/n", "global-preload"},
		{"assigned protected file", ": ${F:=/etc/ld.so.preload}; echo a > \"$F\"", "global-preload"},
		{"assigned protected file by a plain operator", "echo ${F=/etc/ld.so.preload}; echo a > $F", "global-preload"},
		{"assigned protected file in quotes", "echo \"${F:=/etc/ld.so.preload}\"; echo a > ${F}", "global-preload"},
		{"assigned protected file of an assignment", "x=${F:=/etc/ld.so.preload}; echo a > $F", "global-preload"},
		{"assigned protected file in a here-document", "cat > /srv/app/n <<EOF\n${F:=/etc/ld.so.preload}\nEOF\necho a > $F", "global-preload"},
		{"assigned relative file after cd", "cd /etc; : ${F:=ld.so.preload}; echo a > \"$F\"", "global-preload"},
		{"assigned file replaced by an assignment", ": ${F:=/etc/ld.so.preload}; F=/srv/app/n; echo a > \"$F\"", ""},
		{"assigned ordinary file", ": ${F:=/srv/app/n}; echo a > \"$F\"", ""},
		{"default expansion of a set ordinary file", "F=/srv/app/notes.txt; : ${F:=/etc/ld.so.preload}; echo a > \"$F\"", ""},
		{"default expansion of a set ordinary file in printed words", "F=/srv/app/notes.txt; echo ${F:=/etc/ld.so.preload} > /srv/app/notes.txt; echo a > \"$F\"", ""},
		{"default expansion without a colon of a set ordinary file", "F=/srv/app/notes.txt; : ${F=/etc/ld.so.preload}; echo a > \"$F\"", ""},
		{"default expansion of a set ordinary file in a here-document", "F=/srv/app/notes.txt\ncat > /srv/app/notes.txt <<EOF\n${F:=/etc/ld.so.preload}\nEOF\necho a > \"$F\"", ""},
		{"default expansion of a set ordinary file in a declaration", "export F=/srv/app/notes.txt; : ${F:=/etc/ld.so.preload}; echo a > \"$F\"", ""},
		{"default expansion of a name set by a substitution", "F=$(date); : ${F:=/etc/ld.so.preload}; echo a > \"$F\"", ""},
		{"default expansion of a name set in a condition", "if true; then F=/srv/app/notes.txt; fi; : ${F:=/etc/ld.so.preload}; echo a > \"$F\"", ""},
		{"default expansion after an earlier default", ": ${F:=/srv/app/notes.txt}; : ${F:=/etc/ld.so.preload}; echo a > \"$F\"", ""},
		{"default expansion of a name set in a subshell scope", "echo $(F=/srv/app/notes.txt); : ${F:=/etc/ld.so.preload}; echo a > \"$F\"", "global-preload"},
		{"default expansion of an empty name", "F=; : ${F:=/etc/ld.so.preload}; echo a > \"$F\"", "global-preload"},
		{"default expansion without a colon of an empty name", "F=; : ${F=/etc/ld.so.preload}; echo a > \"$F\"", ""},
		{"default expansion of an unset name", "F=/srv/app/notes.txt; unset F; : ${F:=/etc/ld.so.preload}; echo a > \"$F\"", "global-preload"},
		{"default expansion of a name unset on a condition", "F=/srv/app/notes.txt; false && unset F; : ${F:=/etc/ld.so.preload}; echo a > \"$F\"", ""},
		{"default expansion of another name", "F=/srv/app/notes.txt; : ${G:=/etc/ld.so.preload}; echo a > \"$G\"", "global-preload"},
		{"default expansion in a loop of a set ordinary file", "F=/srv/app/notes.txt; for i in 1; do : ${F:=/etc/ld.so.preload}; done; echo a > \"$F\"", ""},
		{"default expansion in a single quote", "F=/srv/app/notes.txt; echo '${F:=/etc/ld.so.preload}' > /srv/app/notes.txt; echo a > \"$F\"", ""},
		{"default expansion in a single quote with no value set", "echo '${F:=/etc/ld.so.preload}' > /srv/app/notes.txt; echo a > \"$F\"", ""},
		{"default expansion in a single quote of a command", "cp x '${F:=/etc/ld.so.preload}'; echo a > \"$F\"", ""},
		{"default expansion in a quoted here-document", "cat <<'EOF2' > /srv/app/notes.txt\n${F:=/etc/ld.so.preload}\nEOF2\necho a > \"$F\"", ""},
		{"default expansion in a backslash-escaped here-document delimiter", "cat <<\\EOF2 > /srv/app/notes.txt\n${F:=/etc/ld.so.preload}\nEOF2\necho a > \"$F\"", ""},
		{"default expansion after an escaped dollar", "echo \\${F:=/etc/ld.so.preload} > /srv/app/notes.txt; echo a > \"$F\"", ""},
		{"default expansion in a comment", "# ${F:=/etc/ld.so.preload}\necho a > \"$F\"", ""},
		{"default expansion in a comment after a command", "echo ok > /srv/app/notes.txt # ${F:=/etc/ld.so.preload}\necho a > \"$F\"", ""},
		{"default expansion in a comment of a substitution", "echo $(ls # ${F:=/etc/ld.so.preload}\n) > /srv/app/notes.txt; echo a > \"$F\"", ""},
		{"default expansion in a single quote of a substitution", "echo $(echo '${F:=/etc/ld.so.preload}') > /srv/app/notes.txt; echo a > \"$F\"", ""},
		{"default expansion in a single quote inside a double quote", "echo \"'${F:=/etc/ld.so.preload}'\" > /srv/app/notes.txt; echo a > \"$F\"", "global-preload"},
		{"default expansion in a substitution", "echo $(echo ${F:=/etc/ld.so.preload}) > /srv/app/notes.txt; echo a > \"$F\"", ""},
		{"default expansion in a backtick", "echo `echo ${F:=/etc/ld.so.preload}`; echo a > \"$F\"", ""},
		{"default expansion in a shell here-document", "sh <<EOF\n: ${F:=/etc/ld.so.preload}; echo a > \"$F\"\nEOF\n", "global-preload"},
		{"default expansion in an unquoted here-document escaped", "cat <<EOF > /srv/app/notes.txt\n\\${F:=/etc/ld.so.preload}\nEOF\necho a > \"$F\"", ""},
		{"default expansion nested in a default", ": ${A:-${F:=/etc/ld.so.preload}}; echo a > \"$F\"", "global-preload"},
		{"quoted substitution in a set ordinary file text", "F=/srv/app/notes.txt; tee \"$(echo a > /etc/ld.so.preload)\" < /dev/null > \"$F\"", "global-preload"},
		{"quoted tee operand with a protected substitution", "tee \"$(echo a > /etc/ld.so.preload)\" < /dev/null > /srv/app/n", "global-preload"},
		{"quoted tee operand with a protected backtick", "tee \"`echo a > /etc/ld.so.preload`\" < /dev/null > /srv/app/n", "global-preload"},
		{"quoted assignment with a protected substitution", "F=\"$(echo a > /etc/ld.so.preload)\"; echo ok > /srv/app/n", "global-preload"},
		{"quoted cd operand with a protected substitution", "cd \"$(echo a > /etc/ld.so.preload)\"; echo ok > /srv/app/n", "global-preload"},
		{"quoted redirect target with a protected substitution", "echo ok > \"$(echo a > /etc/ld.so.preload)\"", "global-preload"},
		{"quoted copy target with a protected substitution", "cp x \"$(echo a > /etc/ld.so.preload)\"", "global-preload"},
		{"quoted dd target with a protected substitution", "dd of=\"$(echo a > /etc/ld.so.preload)\"", "global-preload"},
		{"quoted operand with quotes inside the substitution", "tee \"$(echo \"x\" > /etc/ld.so.preload)\" > /srv/app/n", "global-preload"},
		{"quoted operand around the substitution", "tee \"a-$(echo a > /etc/ld.so.preload)-b\" > /srv/app/n", "global-preload"},
		{"quoted tee operand with an ordinary substitution", "tee \"$(date)\" > /srv/app/n", ""},
		{"quoted assignment with an ordinary substitution", "F=\"$(date)\"; echo ok > /srv/app/n", ""},
		{"single quoted tee operand names a substitution", "tee '$(echo a > /etc/ld.so.preload)' > /srv/app/n", ""},
		{"after a quoted hash", "echo \"# \"; echo a > /etc/ld.so.preload", "global-preload"},
		{"after a stray quote in a here-document", "cat <<EOF\nit\x27s\nEOF\necho a > /etc/ld.so.preload", "global-preload"},
		{"sudoers", "echo a > /etc/sudoers.d/agent", "sudoers"},
		{"account database", "echo a >> /etc/passwd", "account-database"},
		{"pam", "echo a > /etc/pam.d/sshd", "pam"},
		{"docker daemon", "echo a > /etc/docker/daemon.json", "docker-daemon-config"},
		{"profile fragment", "echo a > /etc/profile.d/x.sh", "global-preload"},
		{"ordinary file", "echo a > /srv/app/notes.txt", ""},
		{"read of a protected file", "cat /etc/ld.so.preload /etc/passwd", ""},
		{"copy from a protected file", "cp /etc/ld.so.preload /srv/app/x", ""},
		{"link to a protected file", "ln -s /etc/ld.so.preload x", ""},
		{"neighbour name", "echo a > /etc/ld.so.preload.bak", ""},
		{"other etc file", "echo a > /etc/hosts", ""},
		{"unknown variable", "echo a > $OUT", ""},
		{"substitution", "echo a > $(mktemp)", ""},
		{"pattern", "echo a > /etc/ld.so.prel*", ""},
		{"relative in the working directory", "cd /tmp && echo a > ld.so.preload", ""},
		{"stream duplicate", "echo a 2>&1", ""},
		{"tee of an ordinary file", "echo a | tee out.txt", ""},
		{"longer name", "echo a > /srv/app/tee-x.txt", ""},
	} {
		for position, command := range map[string]string{"before": c.command + opaque, "after": opaque + "\n" + c.command} {
			t.Run(c.name+"/"+position, func(t *testing.T) {
				input, facts := overLimitCommandInput(t, "exec_command", command)
				if facts.Parse.Status != StatusLimitExceeded {
					t.Fatalf("not limit-exceeded: %s", facts.Parse.Status)
				}
				class, ok := OverLimitCommandContentTarget(input, facts)
				if class != c.class || ok != (c.class != "") {
					t.Fatalf("class=%q ok=%t, want %q", class, ok, c.class)
				}
			})
		}
	}
	t.Run("a command with a twin is judged as its twin", func(t *testing.T) {
		input, facts := overLimitCommandInput(t, "exec_command", "echo a > /etc/ld.so.preload"+strings.Repeat(" ", 300000))
		if class, ok := OverLimitCommandContentTarget(input, facts); ok {
			t.Fatalf("class %q for a command that has a twin", class)
		}
	})
	t.Run("a call within the limits", func(t *testing.T) {
		input, facts := overLimitCommandInput(t, "exec_command", "echo a > /etc/ld.so.preload")
		if class, ok := OverLimitCommandContentTarget(input, facts); ok {
			t.Fatalf("class %q for a call within the limits", class)
		}
	})
}

// TestOverLimitCommandContentTargetAssignments pins which text assigns a
// variable in a padded command (GAP-0934): a word the shell reads as an
// assignment in the main shell, and a braced default only while the name holds
// no value from a run in the order written. A quoted word of a command that
// only receives data, the data of a braced default, a program in another
// language and what a child process assigns assign nothing in the shell
// around them.
func TestOverLimitCommandContentTargetAssignments(t *testing.T) {
	const note, protected, global = "/srv/app/notes.txt", "/etc/ld.so.preload", "global-preload"
	opaque := "\n: \x27" + strings.Repeat("x", 70000) + "\x27"
	write := "; echo lib > \"$F\""
	for _, c := range []struct{ name, command, class string }{
		{"default of an unset name", ": ${F:=" + protected + "}" + write, global},
		{"default of a set ordinary name", "F=" + note + "; : ${F:=" + protected + "}" + write, ""},
		{"default of a name an earlier default set", ": ${F:=" + note + "}; : ${F:=" + protected + "}" + write, ""},
		{"default of a name set to an unreadable value", ": ${F:=$(date)}; : ${F:=" + protected + "}" + write, ""},
		{"default of a name set under a condition", "false && F=" + note + "; : ${F:=" + protected + "}" + write, global},
		{"default of a name set after a test that passes", "true && F=" + note + "; : ${F:=" + protected + "}" + write, ""},
		{"default of a name set after a test that fails", "false || F=" + note + "; : ${F:=" + protected + "}" + write, ""},
		{"default of a name set after an unknown test", "test -f x && F=" + note + "; : ${F:=" + protected + "}" + write, global},
		{"default after a quoted assignment word", "test \x27F=" + note + "\x27; : ${F:=" + protected + "}" + write, global},
		{"quoted assignment word after a set name", "F=" + note + "; test \x27F=" + protected + "\x27" + write, ""},
		{"quoted assignment word of command echo", "F=" + note + "; command echo \x27F=" + protected + "\x27" + write, ""},
		{"quoted assignment word of command with options", "F=" + note + "; command -p -- echo \x27F=" + protected + "\x27" + write, ""},
		{"quoted assignment word of builtin echo", "F=" + note + "; builtin echo \x27F=" + protected + "\x27" + write, ""},
		{"quoted assignment word of command -v", "F=" + note + "; command -v \x27F=" + protected + "\x27" + write, ""},
		{"quoted assignment word of builtin with a double dash", "F=" + note + "; builtin -- echo \x27F=" + protected + "\x27" + write, ""},
		{"quoted assignment word of command with a double dash", "F=" + note + "; command -- echo \x27F=" + protected + "\x27" + write, ""},
		{"quoted assignment word of a quoted echo behind command", "F=" + note + "; command \"echo\" \x27F=" + protected + "\x27" + write, ""},
		{"quoted assignment word of a quoted echo behind builtin", "F=" + note + "; builtin \"echo\" \x27F=" + protected + "\x27" + write, ""},
		{"quoted assignment word of a quoted echo", "F=" + note + "; \"echo\" \x27F=" + protected + "\x27" + write, ""},
		{"eval behind builtin and a double dash", "F=" + note + "; builtin -- eval \x27F=" + protected + "\x27" + write, global},
		{"export behind builtin and a double dash", "F=" + note + "; builtin -- export F=" + protected + write, global},
		{"eval behind command and a double dash", "F=" + note + "; command -p -- eval \x27F=" + protected + "\x27" + write, global},
		{"quoted eval behind command", "F=" + note + "; command \"eval\" \x27F=" + protected + "\x27" + write, global},
		{"quoted eval behind builtin", "F=" + note + "; builtin \"eval\" \x27F=" + protected + "\x27" + write, global},
		{"escaped eval behind command", "F=" + note + "; command \\eval \x27F=" + protected + "\x27" + write, global},
		{"quoted eval", "F=" + note + "; \"eval\" \x27F=" + protected + "\x27" + write, global},
		{"quoted export behind builtin", "F=" + note + "; builtin \x27export\x27 F=" + protected + write, global},
		{"quoted wrapper before eval", "F=" + note + "; \"command\" eval \x27F=" + protected + "\x27" + write, global},
		{"unknown option of builtin before eval", "F=" + note + "; builtin -x eval \x27F=" + protected + "\x27" + write, global},
		{"unknown option of command before eval", "F=" + note + "; command -x eval \x27F=" + protected + "\x27" + write, global},
		{"quoted option of command before eval", "F=" + note + "; command \"-p\" eval \x27F=" + protected + "\x27" + write, global},
		{"command named by an expansion", "F=" + note + "; $RUN \x27F=" + protected + "\x27" + write, global},
		{"command named by an expansion behind command", "F=" + note + "; command \"$RUN\" \x27F=" + protected + "\x27" + write, global},
		{"eval behind command still assigns", "F=" + note + "; command eval \x27F=" + protected + "\x27" + write, global},
		{"export behind command still assigns", "command export F=" + protected + write, global},
		{"default of a name set after a skipped true", "false && true && F=" + note + "; : ${F:=" + protected + "}" + write, global},
		{"default of a name set after a skipped colon", "false && : && F=" + note + "; : ${F:=" + protected + "}" + write, global},
		{"default of a name set after a skipped false", "true || false || F=" + note + "; : ${F:=" + protected + "}" + write, global},
		{"default of a name set after a skipped colon in an or chain", "true || : || F=" + note + "; : ${F:=" + protected + "}" + write, global},
		{"default of a name set after an unknown test and a true", "test -f x && true && F=" + note + "; : ${F:=" + protected + "}" + write, global},
		{"default of a name set after two tests that pass", "true && : && F=" + note + "; : ${F:=" + protected + "}" + write, ""},
		{"default of a name set after two tests that fail", "false || false || F=" + note + "; : ${F:=" + protected + "}" + write, ""},
		{"conditional assignment of a protected file may have run", "F=" + note + "; false && F=" + protected + write, global},
		{"default inside a default is data", ": ${A:-\x27${F:=" + protected + "}\x27}" + write, ""},
		{"default inside an assigning default is data", ": ${A:=\x27${F:=" + protected + "}\x27}" + write, ""},
		{"default inside a double-quoted default runs", ": ${A:-\"${F:=" + protected + "}\"}" + write, global},
		{"default inside a default runs", ": ${A:-${F:=" + protected + "}}" + write, global},
		{"document of another language", "python3 <<\x27EOF2\x27\nprint(\x27${F:=" + protected + "}\x27)\nEOF2\necho lib > \"$F\"", ""},
		{"assignment in a document of a child shell", "sh <<\x27EOF2\x27\n: ${F:=" + protected + "}\nEOF2\necho lib > \"$F\"", ""},
		{"write in a document of a child shell", "sh <<\x27EOF2\x27\n: ${F:=" + protected + "}" + write + "\nEOF2\n", global},
		{"assignment in a string of a child shell", "sh -c \x27F=" + protected + "\x27" + write, ""},
		{"write in a string of a child shell", "sh -c \x27F=" + protected + write + "\x27", global},
		{"assignment by an env prefix", "env F=" + protected + " true" + write, ""},
		{"env prefix and a write by the child", "env F=" + protected + " sh -c \x27echo lib > \"$F\"\x27", global},
		{"assignment by eval", "eval \x27F=" + protected + "\x27" + write, global},
		{"export in the shell", "export F=" + protected + write, global},
	} {
		t.Run(c.name, func(t *testing.T) {
			input, facts := overLimitCommandInput(t, "exec_command", c.command+opaque)
			if class, _ := OverLimitCommandContentTarget(input, facts); class != c.class {
				t.Fatalf("class=%q, want %q", class, c.class)
			}
		})
	}
}

// TestStripShellComments pins that only a comment is left out: an unquoted
// hash that starts a word, to the end of its line. A hash in a quote, in a
// word, after a dollar, in a here-document body or after a backslash is none,
// and a construct the reading does not follow leaves the text unreduced.
func TestStripShellComments(t *testing.T) {
	for _, c := range []struct {
		name, text, want string
		ok               bool
	}{
		{"trailing comment", "echo a # note\necho b", "echo a \necho b", true},
		{"comment line", "# note\necho b", "\necho b", true},
		{"after a separator", "echo a;# note", "echo a;", true},
		{"single quoted hash", "echo \x27# a\x27 # note", "echo \x27# a\x27 ", true},
		{"double quoted hash", "echo \"# a\" # note", "echo \"# a\" ", true},
		{"hash inside a word", "echo a#b", "echo a#b", true},
		{"escaped hash", "echo \\# a", "echo \\# a", true},
		{"dollar hash", "echo $# $?", "echo $# $?", true},
		{"here-document body is data", "cat <<EOF\n# a\nEOF\n# b\n", "cat <<EOF\n# a\nEOF\n\n", true},
		{"dash here-document, tab delimiter", "cat <<-EOF\n# a\n\tEOF\n# b", "cat <<-EOF\n# a\n\tEOF\n", true},
		{"padded delimiter line is data", "cat <<EOF\nEOF \n# a\nEOF\n# b", "cat <<EOF\nEOF \n# a\nEOF\n", true},
		{"quoted delimiter", "cat <<\x27EOF\x27 # c\n# a\nEOF\n", "cat <<\x27EOF\x27 \n# a\nEOF\n", true},
		{"two here-documents", "cat <<A <<B\n# a\nA\n# b\nB\n# c", "cat <<A <<B\n# a\nA\n# b\nB\n", true},
		{"here-string", "cat <<< x # c", "cat <<< x ", true},
		{"command substitution", "echo $(echo a # c\n)", "", false},
		{"parameter expansion", "echo ${#a} # c", "", false},
		{"arithmetic", "echo $((1)) # c", "", false},
		{"arithmetic command", "(( a )) # c", "", false},
		{"backtick", "echo `a` # c", "", false},
		{"ansi-c quote", "echo $\x27a\x27 # c", "", false},
		{"unterminated quote", "echo \x27a # c", "", false},
		{"substitution in a string", "echo \"$(a)\" # c", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := stripShellComments(c.text)
			if ok != c.ok || (ok && got != c.want) {
				t.Fatalf("got %q ok=%t, want %q ok=%t", got, ok, c.want, c.ok)
			}
		})
	}
}

// TestOverLimitWriteElidedContentTargetRelativeLink pins that the client's
// attested target of a relative operand is read under the key the client
// gives it, the operand placed in the working directory.
func TestOverLimitWriteElidedContentTargetRelativeLink(t *testing.T) {
	opaque := "*** Begin Patch\n*** Add File: lnk-preload\n+" + strings.Repeat("x", 300000) + "\n*** End Patch\n"
	raw, err := json.Marshal(map[string]any{"command": opaque, "workdir": "/srv/app"})
	if err != nil {
		t.Fatal(err)
	}
	input := Input{Tool: "apply_patch", Args: raw, CWD: "/srv/app"}
	facts := Analyze(input)
	for _, c := range []struct {
		name     string
		resolved map[string]string
		class    string
	}{
		{"placed key", map[string]string{"/srv/app/lnk-preload": "/etc/ld.so.preload"}, "global-preload"},
		{"ordinary link", map[string]string{"/srv/app/lnk-preload": "/srv/app/notes.txt"}, ""},
		{"no evidence", nil, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			class, ok := OverLimitWriteElidedContentTarget(input, facts, c.resolved)
			if class != c.class || ok != (c.class != "") {
				t.Fatalf("class=%q ok=%t, want %q", class, ok, c.class)
			}
		})
	}
}

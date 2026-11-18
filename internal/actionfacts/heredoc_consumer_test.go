package actionfacts

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// rel-1-0-10:GAP-0889. The command of a quoted here-document is resolved
// with the shared launcher reading: a shell that reads stdin runs the body
// however it is spelled, a command the reading cannot place is the unknown
// tier, and data is only a trusted program of the closed data list
// (hereDocDataPrograms, GAP-0902).
func TestHereDocConsumerResolvesLaunchersAndPaths(t *testing.T) {
	for consumer, want := range map[string]hereDocConsumer{
		// The reviewer's 22 spellings (s7-p3rev).
		"nice bash":              hereDocRunsCode,
		"nice -n 5 bash":         hereDocRunsCode,
		"nohup bash":             hereDocRunsCode,
		"timeout 9 bash":         hereDocRunsCode,
		"exec bash":              hereDocRunsCode,
		"busybox sh":             hereDocRunsCode,
		"stdbuf -o0 bash":        hereDocRunsCode,
		"time bash":              hereDocRunsCode,
		"setsid bash":            hereDocRunsCode,
		"ionice bash":            hereDocRunsCode,
		"chroot / bash":          hereDocUnknown,
		"sudo nice bash":         hereDocRunsCode,
		"nice sudo bash":         hereDocRunsCode,
		"bash -s -- -c":          hereDocRunsCode,
		"source /dev/stdin":      hereDocRunsCode,
		". /dev/stdin":           hereDocRunsCode,
		"./bash":                 hereDocRunsCode,
		"/usr/local/bin/bash":    hereDocRunsCode,
		"/opt/homebrew/bin/bash": hereDocRunsCode,
		"/tmp/x/bash":            hereDocRunsCode,
		"command exec bash":      hereDocRunsCode,
		"env nice bash":          hereDocRunsCode,
		// Path-qualified and nested launchers.
		"/usr/bin/env bash":                 hereDocRunsCode,
		"/usr/bin/nice -n 3 /bin/sh":        hereDocRunsCode,
		"env -i nohup timeout 5 nice sh -s": hereDocRunsCode,
		"sudo -u root env FOO=1 nohup bash": hereDocRunsCode,
		"command -p exec /bin/dash":         hereDocRunsCode,
		"nice --weird-option bash":          hereDocRunsCode,
		"bash -c sh":                        hereDocRunsCode,
		"bash -ec 'nice bash'":              hereDocRunsCode,
		"eval bash":                         hereDocRunsCode,
		"source /proc/self/fd/0":            hereDocRunsCode,
		"bash -x":                           hereDocRunsCode,
		"cat | nice bash":                   hereDocRunsCode,
		// A shell with a script file or a launcher with a run-time option
		// word is read as the shell (posixStdinCodeTarget, launcherInner):
		// the body is read, as the GAP-0526 base did.
		"bash script.sh":  hereDocRunsCode,
		"timeout $T bash": hereDocRunsCode,
		"nohup nohup nohup nohup nohup nohup nohup nohup nohup nohup bash": hereDocRunsCode,
		// Not known: the unknown tier, never data.
		"nice $SHELL":            hereDocUnknown,
		"env PATH=/tmp/x cat":    hereDocUnknown,
		"/usr/local/bin/cat > f": hereDocUnknown,
		"./tool":                 hereDocUnknown,
		"source ./setup.sh":      hereDocUnknown,
		"xargs -I{} sh -c {}":    hereDocUnknown,
		"ssh host":               hereDocUnknown,
		"nsenter -t 1 -m":        hereDocUnknown,
		"bash -c":                hereDocUnknown,
		"bash -c \"$X\"":         hereDocUnknown,
		// Data: a trusted program of the closed data list after the launcher
		// unwrap (the owner case is the cat writer shape).
		"cat > notes.txt":           hereDocData,
		"/bin/cat > notes.txt":      hereDocData,
		"nohup tee -a log":          hereDocData,
		"env LC_ALL=C sort":         hereDocData,
		"env FOO=/opt/x cat":        hereDocData,
		"bash -c 'cat > notes.txt'": hereDocData,
		"cat | wc -l":               hereDocData,
		"sort -u | grep -v x":       hereDocData,
		"/usr/bin/sha256sum":        hereDocData,
		// An interpreter is not on the list (the 1.0.10 lead's ruling
		// replaces the GAP-0876 interpreter reading): the unknown tier.
		"python3 -": hereDocUnknown,
	} {
		if got := syntaxTailHereDocConsumer(consumer); got != want {
			t.Errorf("%q: %d, want %d", consumer, got, want)
		}
	}
}

// A chain of nested readings past maxControlNesting is the unknown tier
// (ONE BOUND rule), never data.
func TestHereDocConsumerPastTheNestingBoundIsUnknown(t *testing.T) {
	consumer := strings.Repeat("eval ", maxControlNesting+2) + "bash"
	if got := syntaxTailHereDocConsumer(consumer); got != hereDocUnknown {
		t.Errorf("%d nested evals: %d, want the unknown tier", maxControlNesting+2, got)
	}
}

// rel-1-0-10:GAP-0902. Data is a closed allowlist (the 1.0.10 lead's ruling):
// every consumer of the reviewer's probe (s7-p3st2rev, 136 spellings: an
// unlisted launcher or shell, a wrapper at an untrusted path, a PATH
// assignment, a redefined or unknown name, a name in another case, and the
// interpreters) is the unknown tier or reads the body, never data. Each shell
// spelling reads the body.
func TestHereDocConsumerDataIsAnAllowlist(t *testing.T) {
	for _, consumer := range []string{
		"xargs sh", "xargs bash -c", "xargs -I CMD sh -c CMD", "xargs -I cat sh -c cat", "xargs -L1 sh -c",
		"parallel", "parallel sh -c", "parallel --pipe sh", "ssh host", "ssh host sh", "ssh -T host",
		"su", "su -", "su root", "su -c sh", "su -s /bin/sh", "su -l", "sudo -s", "sudo -i", "sudo su", "sudo su -",
		"sudo -u root sh", "doas -s", "doas sh", "pkexec bash", "pfexec sh", "sg wheel", "newgrp",
		"script", "script -q", "script -q /dev/null", "expect", "expect -",
		"busybox sh", "busybox ash", "toybox sh", "busybox", "watch", "watch -n 1 sh", "tmux", "tmux send-keys", "screen",
		"at now", "batch", "crontab -", "runuser -u x bash", "systemd-run --pipe bash",
		"unshare bash", "unshare -r bash", "nsenter bash", "strace bash", "strace -f bash", "ltrace bash", "valgrind bash",
		"env -S bash", "rlwrap bash", "fakeroot bash", "firejail bash", "taskset 1 bash", "numactl -C 0 bash",
		"ip netns exec x bash", "torsocks bash", "proxychains bash", "caffeinate bash", "caffeinate -i bash",
		"arch -x86_64 bash", "sandbox-exec -n x bash", "eatmydata bash", "chrt 1 bash", "flock f bash", "unbuffer bash",
		"docker exec -i c sh", "kubectl exec -i p -- sh", "chroot /x sh", "time -p bash", "command -- bash",
		"builtin source /dev/stdin", "exec -a x bash", "exec -l bash", "exec -c bash", "nohup -- bash",
		"dash", "yash", "posh", "rbash", "oksh", "loksh", "elvish", "nu", "xonsh", "rc", "es", "ksh93", "zsh -s",
		"bash -O extglob", "bash -i", "bash -l", "bash --norc", "bash -", "bash --", "bash +x",
		"/tmp/cat", "./cat", "bin/cat", "/tmp/x/nohup cat", "./env cat", "/tmp/x/env FOO=1 cat", "./nice cat",
		"PATH=/tmp/x cat", "PATH=. cat", "PATH=/tmp/x nohup cat", "BASH_ENV=/tmp/x bash -c cat", "ENV=/tmp/x sh -c cat",
		"hash -p /bin/sh cat; cat", "cat(){ sh; }; cat", "alias cat=sh; cat", "f", "mysh", "CAT", "Bash", "SH",
		"python -", "python3", "perl", "ruby", "node", "php", "awk -f -", "sed -f -", "tclsh", "lua", "osascript",
		"pwsh -Command -", "pwsh", "cmd", "powershell",
		// Beyond the probe: other unlisted readers, an untrusted chain word,
		// and sort's compress program.
		"jq .", "psql", "git apply", "kubectl apply -f -", "less", "more", "sed 'e'", "ls",
		"nice /tmp/a=b/nohup cat", "sort --compress-program=sh", "sort --com=sh", "env -C /tmp/x cat",
	} {
		if got := syntaxTailHereDocConsumer(consumer); got == hereDocData {
			t.Errorf("%q: hereDocData, want the unknown tier or the body read", consumer)
		}
	}
	for _, consumer := range []string{
		"rbash", "yash", "posh", "oksh", "loksh", "ksh93", "ash", "mksh", "toybox sh", "busybox ash",
		"Bash", "SH", "dash", "zsh -s", "bash -i", "bash -", "cat(){ sh; }; cat",
	} {
		if got := syntaxTailHereDocConsumer(consumer); got != hereDocRunsCode {
			t.Errorf("%q: %d, want the body read (a shell)", consumer, got)
		}
	}
}

// gap0913Rebinds are the reviewer's rebind prefixes (s7-d4tailrev,
// TestD4trConsumerProbe idx 1-17) and more: each binds PATH (or another
// name that changes what a word runs) or renames cat in a way the parsed
// binding reader follows, or may bind anything (a sourced file, eval of a
// run-time string, enable -f, a run-time command word).
var gap0913Rebinds = []string{
	"export PATH=/tmp/x", "export PA\"\"TH=/tmp/x", "export PA\\TH=/tmp/x", "read PATH < /tmp/p",
	"for PATH in /tmp/x; do :; done", "printf -v PATH /tmp/x", "declare PA''TH=/tmp/x", "mapfile -t PATH < /tmp/p",
	"typeset -x PA\"\"TH=/tmp/x", "eval 'PA''TH=/tmp/x'", "eval \"c\"\"at() { bash; }\"", "eval \"$DEFS\"",
	"source /tmp/defs.sh", ". ./defs.sh", "enable -f /tmp/x.so cat", "cat() { bash; }", "alias cat=bash",
	"function cat { sh; }", "hash -p /bin/sh cat", "PATH+=:/tmp/x", "path=(/tmp/x $path)", "export LD_PRELOAD=/tmp/x.so",
	"builtin alias cat=sh", "command eval 'cat(){ sh; }'", "$CMD cat=sh", "trap 'cat(){ sh; }' DEBUG",
	"declare \"$N=/tmp/x\"", "readarray PATH < /tmp/p", "if true; then PATH=/tmp/x; fi",
}

// gap0913Keeps are statements that bind or define nothing that renames cat:
// the cat writer stays data after them.
var gap0913Keeps = []string{
	"echo concat", "alias ll='ls -l'", "MANPATH=/x", "export FOO=/x", "read -r line < f", "hash cat",
	"eval 'echo hi'", "export PATH", "printf -v x %s y", "for f in a b; do echo $f; done", "cd /tmp && ls",
}

// rel-1-0-10:GAP-0913. A data consumer is the unknown tier when a readable
// statement of the call, or the script before it in its own argument, binds
// PATH or renames the program; the bindings are read with the parser and the
// shared binding reader (callBindsNames), never with a pattern on the text.
// A statement or script that does not parse may bind anything.
func TestHereDocConsumerRenamedByTheCallIsUnknown(t *testing.T) {
	doc := func(script string) shellparse.SyntaxTailHereDoc {
		return shellparse.SyntaxTailHereDoc{Consumer: "cat > notes.txt", Script: script, ScriptKnown: true}
	}
	for _, statement := range gap0913Rebinds {
		if got := syntaxTailHereDocConsumerIn(doc(""), []string{statement}); got == hereDocData {
			t.Errorf("statement %q: hereDocData, want the unknown tier", statement)
		}
		if got := syntaxTailHereDocConsumerIn(doc(statement+"; "), nil); got == hereDocData {
			t.Errorf("script %q: hereDocData, want the unknown tier", statement)
		}
	}
	for _, statement := range gap0913Keeps {
		if got := syntaxTailHereDocConsumerIn(doc(""), []string{statement}); got != hereDocData {
			t.Errorf("statement %q: %d, want hereDocData", statement, got)
		}
		if got := syntaxTailHereDocConsumerIn(doc(statement+" && "), nil); got != hereDocData {
			t.Errorf("script %q: %d, want hereDocData", statement, got)
		}
	}
	for _, row := range []struct {
		name string
		doc  shellparse.SyntaxTailHereDoc
		stmt []string
		want hereDocConsumer
	}{
		{"no bindings", doc(""), nil, hereDocData},
		{"a path is no function", shellparse.SyntaxTailHereDoc{Consumer: "/bin/cat > f", ScriptKnown: true}, []string{"cat() { sh; }"}, hereDocData},
		{"a script that is not known", shellparse.SyntaxTailHereDoc{Consumer: "cat > f"}, nil, hereDocUnknown},
		{"a script that does not parse", doc("if true; then "), nil, hereDocUnknown},
		{"a statement that does not parse", doc(""), []string{"if true"}, hereDocUnknown},
		{"a wrapper renamed", shellparse.SyntaxTailHereDoc{Consumer: "nice cat > f", ScriptKnown: true}, []string{"nice() { sh; }"}, hereDocUnknown},
		{"a shell stays a shell", shellparse.SyntaxTailHereDoc{Consumer: "bash", ScriptKnown: true}, []string{"export PATH=/tmp/x"}, hereDocRunsCode},
	} {
		if got := syntaxTailHereDocConsumerIn(row.doc, row.stmt); got != row.want {
			t.Errorf("%s: %d, want %d", row.name, got, row.want)
		}
	}
}

// The shared binding reader keeps its USER and LOGNAME results: the names
// parameter of callBindsNames does not change CallBindsUserNames.
func TestCallBindsUserNamesKeepsItsNames(t *testing.T) {
	for text, want := range map[string]int{
		"read USER": 1, "printf -v LOGNAME x": 1, "source f": 2, "eval \"$X\"": 2, "eval 'USER=x'": 1,
		"read PATH": 0, "printf -v PATH x": 0, "echo USER": 0,
	} {
		file, ok := shellparse.Parse(text)
		if !ok {
			t.Fatalf("%q: no parse", text)
		}
		call, _ := file.Stmts[0].Cmd.(*syntax.CallExpr)
		if got := len(CallBindsUserNames(call)); got != want {
			t.Errorf("%q: %d names, want %d", text, got, want)
		}
	}
}

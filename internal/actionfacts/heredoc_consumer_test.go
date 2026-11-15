package actionfacts

import (
	"strings"
	"testing"
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

// rel-1-0-10:GAP-0902. The consumer text stops at the list operator before the
// opener, so a function, alias or hash entry of the data name, or a PATH
// assignment, made earlier in the same call is read from the call text: the
// unknown tier. A text that only mentions the name keeps the data reading.
func TestHereDocConsumerRedefinedInTheCallIsUnknown(t *testing.T) {
	for _, row := range []struct {
		command, consumer string
		want              hereDocConsumer
	}{
		{"cat(){ sh; }; cat > f", "cat > f", hereDocUnknown},
		{"cat () { sh; }; cat > f", "cat > f", hereDocUnknown},
		{"function cat { sh; }; cat > f", "cat > f", hereDocUnknown},
		{"alias cat=sh; cat > f", "cat > f", hereDocUnknown},
		{"alias -- 'cat=sh'; cat > f", "cat > f", hereDocUnknown},
		{"hash -p /bin/sh cat; cat > f", "cat > f", hereDocUnknown},
		{"export PATH=/tmp/x:$PATH; cat > f", "cat > f", hereDocUnknown},
		{"PATH=/tmp/x; cat > f", "cat > f", hereDocUnknown},
		{"nice(){ sh; }; nice cat > f", "nice cat > f", hereDocUnknown},
		{"echo concat; cat > f", "cat > f", hereDocData},
		{"alias ll='ls -l'; cat > f", "cat > f", hereDocData},
		{"MANPATH=/x; cat > f", "cat > f", hereDocData},
		// A path is not looked up as a function.
		{"cat(){ sh; }; /bin/cat > f", "/bin/cat > f", hereDocData},
	} {
		if got := syntaxTailHereDocConsumerIn(row.consumer, row.command); got != row.want {
			t.Errorf("%q in %q: %d, want %d", row.consumer, row.command, got, row.want)
		}
	}
}

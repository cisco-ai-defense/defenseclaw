package actionfacts

import (
	"strings"
	"testing"
)

// rel-1-0-10:GAP-0889. The command of a quoted here-document is resolved
// with the shared launcher reading: a shell that reads stdin runs the body
// however it is spelled, a command the reading cannot place is the unknown
// tier, and data is only a known, trusted program that is neither a shell
// nor a launcher.
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
		// Data: a known, trusted program that is no shell and no launcher
		// (the owner case is the cat writer shape).
		"cat > notes.txt":           hereDocData,
		"/bin/cat > notes.txt":      hereDocData,
		"nohup tee -a log":          hereDocData,
		"env LC_ALL=C sort":         hereDocData,
		"python3 -":                 hereDocData,
		"bash -c 'cat > notes.txt'": hereDocData,
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

package actionfacts

import (
	"slices"
	"testing"
)

func TestGAP1182WrapperChildShellBodyReadings(t *testing.T) {
	skipPOSIXPathsOnWindows(t)
	for _, prefix := range []string{
		"chroot / ", "chroot --userspec=1000:1000 / ",
		"nsenter -t 1 ", "nsenter --target=1 ",
		"flock /tmp/l ", "taskset 1 ",
	} {
		command := prefix + "sh -c ': >> ~/.defenseclaw/config.yaml'"
		input := Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/u", DialectHint: DialectPOSIX}
		if got := SimpleCommands(input, Analyze(input)); !slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.Text == ": >> ~/.defenseclaw/config.yaml"
		}) {
			t.Errorf("%q: child body missing: %+v", command, got)
		}
	}
}

func TestGAP1183TopLevelHereDocBodyReadings(t *testing.T) {
	skipPOSIXPathsOnWindows(t)
	for _, row := range []struct {
		prefix string
		code   bool
	}{
		{"sh", true}, {"yash", true}, {"newgrp", false},
		{"/tmp/x/wrap sh", false}, {"PATH=/tmp/x:$PATH cat", false},
		{"cat", false},
	} {
		command := row.prefix + " <<'EOF'\n: >> ~/.defenseclaw/config.yaml\nEOF"
		input := Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/u", DialectHint: DialectPOSIX}
		got := SimpleCommands(input, Analyze(input))
		body := slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.Text == ": >> ~/.defenseclaw/config.yaml\n"
		})
		unknown := slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.EvaluationFailure == EvaluationFailureUnresolvedBody
		})
		if row.code && !body || row.prefix == "cat" && (body || unknown) ||
			!row.code && row.prefix != "cat" && !unknown {
			t.Errorf("%q: body=%t unknown=%t: %+v", command, body, unknown, got)
		}
	}
	command := "unused() { sh <<'EOF'\n: >> ~/.defenseclaw/config.yaml\nEOF\n}\ntrue"
	input := Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/u", DialectHint: DialectPOSIX}
	if got := SimpleCommands(input, Analyze(input)); slices.ContainsFunc(got, func(s SimpleCommand) bool {
		return s.Text == ": >> ~/.defenseclaw/config.yaml\n"
	}) {
		t.Errorf("an uncalled function is not a here-document consumer: %+v", got)
	}
}

func TestGAP1183OrdinaryHereDocDataKeepsReleaseReading(t *testing.T) {
	skipPOSIXPathsOnWindows(t)
	for _, command := range []string{
		"python3 - <<'EOF'\nprint('hello')\nEOF",
		"cat <<'EOF' | python3 -\nprint('hello')\nEOF",
		"env FOO=1 python3 - <<'EOF'\nprint('hello')\nEOF",
		"PATH=/tmp/x:$PATH cat <<'EOF'\nordinary data\nEOF",
		"PATH=/tmp/x:$PATH cat <<'EOF'\necho .defenseclaw/config.yaml\nEOF",
		"PATH=/tmp/x:$PATH cat <<'EOF'\ncat ~/.defenseclaw/config.yaml\nEOF",
		"newgrp <<'EOF'\nordinary data\nEOF",
		"/tmp/x/wrap sh <<'EOF'\nordinary data\nEOF",
	} {
		input := Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/u", DialectHint: DialectPOSIX}
		if got := SimpleCommands(input, Analyze(input)); slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.EvaluationFailure == EvaluationFailureUnresolvedBody || s.Text == "print('hello')\n"
		}) {
			t.Errorf("ordinary data changed reading: %+v", got)
		}
	}
}

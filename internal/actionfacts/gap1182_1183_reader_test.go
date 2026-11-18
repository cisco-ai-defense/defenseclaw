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
	// want: "body", the body is read here as the script of the consumer;
	// "unknown", the unknown tier; "none", this reader adds nothing because
	// the consumer is data, or the ordinary readers already judge its stdin
	// (topLevelHereDocReadElsewhere: the gateway rows of
	// TestGAP1183TopLevelHereDocConsumerOnClaudeHook, TestCapFloorHeredocConsumer
	// and TestStdinCodeWrapperKeepsTheStrictSignal hold their verdicts).
	for _, row := range []struct {
		prefix, delimiter, want string
	}{
		{"sh", "'EOF'", "none"}, {"sh", "EOF", "none"}, {"sudo sh", "EOF", "none"},
		{"bash run.sh", "'EOF'", "none"}, {"crontab -", "'EOF'", "none"},
		{"cat", "'EOF'", "none"},
		{"yash", "'EOF'", "body"}, {"yash", "EOF", "body"}, {"nohup yash", "EOF", "body"},
		{"newgrp", "'EOF'", "unknown"}, {"newgrp", "EOF", "unknown"},
		{"/tmp/x/wrap sh", "'EOF'", "unknown"}, {"PATH=/tmp/x:$PATH cat", "'EOF'", "unknown"},
	} {
		command := row.prefix + " <<" + row.delimiter + "\n: >> ~/.defenseclaw/config.yaml\nEOF"
		input := Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/u", DialectHint: DialectPOSIX}
		got := SimpleCommands(input, Analyze(input))
		body := slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.Text == ": >> ~/.defenseclaw/config.yaml\n"
		})
		unknown := slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.EvaluationFailure == EvaluationFailureUnresolvedBody
		})
		if body != (row.want == "body") || unknown != (row.want == "unknown") {
			t.Errorf("%q: body=%t unknown=%t, want %s: %+v", command, body, unknown, row.want, got)
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

package actionfacts

import (
	"runtime"
	"slices"
	"testing"
)

func TestGAP1182WrapperChildShellBodyReadings(t *testing.T) {
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
	// want: "body", the body is read here as the script of the consumer;
	// "unknown", the unknown tier; "strict", the strict tiers only (a data
	// program after a PATH change, rel-1-0-10:GAP-1481); "none", this reader adds nothing because
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
		{"/tmp/x/wrap sh", "'EOF'", "unknown"}, {"PATH=/tmp/x:$PATH cat", "'EOF'", "strict"},
		{"export PATH=/tmp/x:$PATH; cat > t.sh", "'EOF'", "strict"}, {"env PATH=/tmp/x cat", "'EOF'", "strict"},
		{"export PATH=/tmp/x:$PATH; newgrp", "'EOF'", "unknown"}, {"PATH=/tmp/x:$PATH newgrp", "'EOF'", "unknown"},
		{"export PATH=/tmp/x:$PATH; /tmp/x/wrap sh", "'EOF'", "unknown"},
	} {
		command := row.prefix + " <<" + row.delimiter + "\n: >> ~/.defenseclaw/config.yaml\nEOF"
		input := Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/u", DialectHint: DialectPOSIX}
		got := SimpleCommands(input, Analyze(input))
		body := slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.Text == ": >> ~/.defenseclaw/config.yaml\n"
		})
		unknown := slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.EvaluationFailure == EvaluationFailureUnknownStdinConsumer
		})
		strict := slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.EvaluationFailure == EvaluationFailureUnknownStdinConsumerStrict
		})
		if body != (row.want == "body") || unknown != (row.want == "unknown") || strict != (row.want == "strict") {
			t.Errorf("%q: body=%t unknown=%t strict=%t, want %s: %+v", command, body, unknown, strict, row.want, got)
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

// TestGAP1183EmptyHereDocBodyReadsNothing: an empty here-document (the
// parser gives it no body word) hands its consumer no input, so the
// top-level reader adds nothing and never dereferences the missing body
// (the FU9 owner A/B rows where a recovered panic became a parse-failure
// alert).
func TestGAP1183EmptyHereDocBodyReadsNothing(t *testing.T) {
	for _, command := range []string{
		"python3 - <<EOF\nEOF",
		"cd /work && python3 - <<EOF\nEOF",
		"cd /work && grep -n x <<EOF\nEOF",
		"newgrp <<EOF\nEOF",
		"PATH=/tmp/x:$PATH cat <<'EOF'\nEOF",
		"yash <<EOF\nEOF",
	} {
		input := Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/u", DialectHint: DialectPOSIX}
		if got := simpleTopLevelHereDocBodies(command, input); len(got) != 0 {
			t.Errorf("%q: want no reading, got %+v", command, got)
		}
		if got := SimpleCommands(input, Analyze(input)); slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.EvaluationFailure == EvaluationFailureUnresolvedBody
		}) {
			t.Errorf("%q: an empty document is not an unread body: %+v", command, got)
		}
	}
}

// The chroot root and nsenter --wd folders are POSIX paths, read with the
// rules of the cd walk on every gateway host, Windows included
// (rel-1-0-10:GAP-1881: chroot / joined "/" under the current folder there).
func TestGAP1241NestedWrapperChildFolder(t *testing.T) {
	for _, row := range []struct {
		name, command, cwd string
		unknown            bool
	}{
		{"chroot root", "chroot / sh -c ': >> home/u/.defenseclaw/config.yaml'", "/", false},
		{"chroot named root", "chroot /srv/root sh -c ': >> home/u/.defenseclaw/config.yaml'", "/srv/root", false},
		{"chroot relative root", "chroot srv sh -c ': >> .defenseclaw/config.yaml'", "/home/u/srv", false},
		{"chroot skip chdir", "chroot --skip-chdir / sh -c ': >> .defenseclaw/config.yaml'", "/home/u", false},
		{"nsenter wd", "nsenter --target=1 --wd=/ sh -c ': >> home/u/.defenseclaw/config.yaml'", "/", false},
		{"nsenter relative parent", "nsenter --target=1 --wd=.. sh -c ': >> u/.defenseclaw/config.yaml'", "/home", false},
		{"nsenter target wd", "nsenter --target=1 --wd sh -c ': >> .defenseclaw/config.yaml'", "", true},
		{"nsenter target root", "nsenter --target=1 --root sh -c ': >> .defenseclaw/config.yaml'", "", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if row.name == "nsenter relative parent" && runtime.GOOS == "windows" {
				// A relative --wd keeps its native meaning on a Windows
				// host, where the gateway cannot place it: the child folder
				// is unknown (staticNSEnterWorkDir, rel-1-0-10:GAP-1881).
				row.cwd, row.unknown = "", true
			}
			input := Input{Tool: "Bash", Command: row.command, CWD: "/home/u", ActiveHome: "/home/u", DialectHint: DialectPOSIX}
			got := SimpleCommands(input, Analyze(input))
			if !slices.ContainsFunc(got, func(s SimpleCommand) bool {
				return s.Text == ": >> home/u/.defenseclaw/config.yaml" && s.CWD == row.cwd && s.UnresolvedFolder == row.unknown ||
					s.Text == ": >> .defenseclaw/config.yaml" && s.CWD == row.cwd && s.UnresolvedFolder == row.unknown ||
					s.Text == ": >> u/.defenseclaw/config.yaml" && s.CWD == row.cwd && s.UnresolvedFolder == row.unknown
			}) {
				t.Errorf("child folder want %q unknown=%v: %+v", row.cwd, row.unknown, got)
			}
		})
	}
}

package gateway

import (
	"runtime"
	"strings"
	"testing"
)

// The cert L64 rows use the Claude Code PreToolUse route in all five tiers.
func TestGAP1182WrappedStateWriteOnClaudeHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	forms := []string{
		"chroot / sh -c '%s'", "chroot --userspec=1000:1000 / bash -c '%s'",
		"nsenter -t 1 sh -c '%s'", "nsenter --target=1 bash -c '%s'",
		"flock /tmp/l sh -c '%s'", "taskset 1 sh -c '%s'",
	}
	for _, pack := range gap0437Packs {
		hook := gap0437Server(t, pack, "claudecode", "action")
		cwd := t.TempDir()
		for i, form := range forms {
			command := strings.Replace(form, "%s", ": >> ~/.defenseclaw/config.yaml", 1)
			out := gap0437Hook(t, hook, cwd, pack.name+string(rune('a'+i)), command)
			if out["action"] != "block" || !gap0526Names(out, "tamper.detector_state_write") {
				t.Errorf("%s %q: want state-write block: %v", pack.name, command, out)
			}
		}
	}
}

func TestGAP1183TopLevelHereDocConsumerOnClaudeHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	rows := []struct {
		name, prefix, delimiter string
		code                    bool
		// strict: a data program after a PATH change, allowed outside the
		// strict tiers (rel-1-0-10:GAP-1481).
		strict bool
	}{
		{"shell", "sh", "'EOF'", true, false},
		{"shell unquoted", "sh", "EOF", true, false},
		{"newgrp", "newgrp", "'EOF'", false, false},
		{"newgrp unquoted", "newgrp", "EOF", false, false},
		{"untrusted wrapper", "/tmp/x/wrap sh", "'EOF'", false, false},
		{"assigned PATH", "PATH=/tmp/x:$PATH cat", "'EOF'", false, false},
		{"exported PATH", "export PATH=/tmp/x:$PATH; cat", "'EOF'", false, true},
		{"assigned PATH newgrp", "PATH=/tmp/x:$PATH newgrp", "'EOF'", false, false},
		{"yash", "yash", "'EOF'", true, false},
		// An unquoted body is read as the shell twin reads it
		// (heredocScriptText), not left unread.
		{"yash unquoted", "yash", "EOF", true, false},
		{"yash behind nohup", "nohup yash", "EOF", true, false},
	}
	for _, pack := range gap0437Packs {
		hook := gap0437Server(t, pack, "claudecode", "action")
		cwd := t.TempDir()
		for _, row := range rows {
			command := row.prefix + " <<" + row.delimiter + "\n: >> ~/.defenseclaw/config.yaml\nEOF"
			out := gap0437Hook(t, hook, cwd, pack.name+row.name, command)
			if row.code {
				if out["action"] != "block" || !gap0526Names(out, "tamper.detector_state_write") {
					t.Errorf("%s %s: want state-write block: %v", pack.name, row.name, out)
				}
				continue
			}
			if row.strict && pack.pack != "strict" {
				if out["action"] != "allow" {
					t.Errorf("%s %s: want allow outside strict (GAP-1481): %v", pack.name, row.name, out)
				}
				continue
			}
			if out["action"] == "allow" {
				t.Errorf("%s %s: want at least unknown tier: %v", pack.name, row.name, out)
			}
		}
	}
}

func TestGAP1183OrdinaryHereDocDataOnClaudeHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	commands := []string{
		"python3 - <<'EOF'\nprint('hello')\nEOF",
		"cat <<'EOF' | python3 -\nprint('hello')\nEOF",
		"env FOO=1 python3 - <<'EOF'\nprint('hello')\nEOF",
		"PATH=/tmp/x:$PATH cat <<'EOF'\nordinary data\nEOF",
		"PATH=/tmp/x:$PATH cat <<'EOF'\necho .defenseclaw/config.yaml\nEOF",
		"PATH=/tmp/x:$PATH cat <<'EOF'\ncat ~/.defenseclaw/config.yaml\nEOF",
		"newgrp <<'EOF'\nordinary data\nEOF",
		"/tmp/x/wrap sh <<'EOF'\nordinary data\nEOF",
	}
	for _, pack := range gap0437Packs {
		hook := gap0437Server(t, pack, "claudecode", "action")
		cwd := t.TempDir()
		for i, command := range commands {
			out := gap0437Hook(t, hook, cwd, pack.name+string(rune('a'+i)), command)
			if out["action"] != "allow" || gap0526Names(out, parseFailureRuleID) {
				t.Errorf("%s data shape %d: unexpected verdict: %v", pack.name, i, out)
			}
		}
	}
}

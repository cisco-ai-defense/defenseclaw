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
		name, prefix string
		code         bool
	}{
		{"shell", "sh", true},
		{"newgrp", "newgrp", false},
		{"untrusted wrapper", "/tmp/x/wrap sh", false},
		{"assigned PATH", "PATH=/tmp/x:$PATH cat", false},
		{"yash", "yash", true},
	}
	for _, pack := range gap0437Packs {
		hook := gap0437Server(t, pack, "claudecode", "action")
		cwd := t.TempDir()
		for _, row := range rows {
			command := row.prefix + " <<'EOF'\n: >> ~/.defenseclaw/config.yaml\nEOF"
			out := gap0437Hook(t, hook, cwd, pack.name+row.name, command)
			if row.code {
				if out["action"] != "block" || !gap0526Names(out, "tamper.detector_state_write") {
					t.Errorf("%s %s: want state-write block: %v", pack.name, row.name, out)
				}
				continue
			}
			if out["action"] == "allow" {
				t.Errorf("%s %s: want at least unknown tier: %v", pack.name, row.name, out)
			}
		}
	}
}

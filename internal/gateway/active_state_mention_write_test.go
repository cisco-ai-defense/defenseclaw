package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2312 (LEAD DECISION 2026-10-27 21:35 EDT, BALANCED-DEFAULTS line 118):
// a mention or a read of active DefenseClaw state (echo or printf of its
// path, cp of it to a project file) and a cp whose unknown option names it
// (cp rejects the option and writes nothing) stay allowed in action mode,
// while a real write of config.yaml or device.key in the same shapes is
// blocked.
func TestActiveStateMentionAllowedRealWriteBlocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home, cwd := r104ReviewHome(t)
	state := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		filepath.Join(state, "config.yaml"),
		filepath.Join(state, "device.key"),
		filepath.Join(cwd, "report.txt"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	allowed := []string{
		"echo ~/.defenseclaw/config.yaml",
		`printf '%s\n' ~/.defenseclaw/config.yaml > report.txt`,
		"cp ~/.defenseclaw/config.yaml report.txt",
		"cp report.txt --future-output=~/.defenseclaw/device.key",
	}
	blocked := []string{
		"echo x > ~/.defenseclaw/config.yaml",
		`printf '%s\n' x > ~/.defenseclaw/config.yaml`,
		`printf '%s\n' x >> ~/.defenseclaw/device.key`,
		"cp report.txt ~/.defenseclaw/config.yaml",
		"cp report.txt ~/.defenseclaw/device.key",
		"cp --force report.txt ~/.defenseclaw/device.key",
		"echo x > $HOME/.defenseclaw/device.key",
		"cp report.txt " + filepath.Join(state, "device.key"),
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		judge := func(command string, block bool) {
			t.Helper()
			input := actionfacts.Input{
				Tool: "Bash", Command: command, CWD: cwd,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connectorName, EnforcementCapable: true,
			})
			if got := buildVerdict(findings, "tool_call").Action == "block"; got != block {
				t.Errorf("%s %q: blocked=%v, want %v (%v)",
					connectorName, command, got, block, FindingStrings(findings))
			}
		}
		for _, command := range allowed {
			judge(command, false)
		}
		for _, command := range blocked {
			judge(command, true)
		}
	}
}

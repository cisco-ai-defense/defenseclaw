package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2378: a ~<active user> spelling of active DefenseClaw state or an
// SSH key file is the write its ~/ and absolute spellings are, as a
// redirect target and as a cp/mv/tee/dd/sed -i/rm operand, also after code
// that may change HOME (the prefix is read from the password database).
// Reads, project and other-user targets and quoted or here-document text
// stay allowed.
func TestActiveUserTildeTargetIsTheActiveHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home := filepath.Join(t.TempDir(), "dcku")
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(cwd, "a.txt"),
		filepath.Join(cwd, "env.sh"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	block := []string{
		"echo x > ~dcku/.defenseclaw/hooks/f",
		"echo x >> ~dcku/.defenseclaw/config.yaml",
		"make > ~dcku/.defenseclaw/config.yaml",
		"cp a.txt ~dcku/.defenseclaw/config.yaml",
		"mv a.txt ~dcku/.defenseclaw/config.yaml",
		"tee ~dcku/.defenseclaw/config.yaml < a.txt",
		"dd if=a.txt of=~dcku/.defenseclaw/config.yaml",
		"sed -i s/x/y/ ~dcku/.defenseclaw/config.yaml",
		"rm ~dcku/.defenseclaw/config.yaml",
		"rm -rf ~dcku/.defenseclaw/hooks",
		"source ./env.sh; echo x > ~dcku/.defenseclaw/config.yaml",
		"HOME=/tmp/h; echo x > ~dcku/.defenseclaw/config.yaml",
		"echo k >> ~dcku/.ssh/authorized_keys",
	}
	allow := []string{
		"cat ~dcku/.defenseclaw/config.yaml",
		"ls ~dcku/.defenseclaw",
		"echo x > ~dcku/build.log",
		"cp a.txt ~dcku/notes.txt",
		"cat ~other/.defenseclaw/config.yaml",
		"grep x ~dcku/.defenseclaw/config.yaml > out.txt",
		"echo '~dcku/.defenseclaw/config.yaml' > notes.txt",
		"cat > notes.md <<'EOF'\n~dcku/.defenseclaw/config.yaml\nEOF\n",
		"git status --short",
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		judge := func(command string, want bool) {
			t.Helper()
			input := actionfacts.Input{
				Tool: "Bash", Command: command, CWD: cwd,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connectorName, EnforcementCapable: true,
			})
			if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != want {
				t.Errorf("%s %q: blocked=%v, want %v (%v)", connectorName, command, blocked, want, FindingStrings(findings))
			}
		}
		for _, command := range block {
			judge(command, true)
			// The control spelling blocks as well.
			if !strings.Contains(command, "HOME") {
				judge(strings.ReplaceAll(command, "~dcku/", "~/"), true)
			}
		}
		for _, command := range allow {
			judge(command, false)
		}
	}
}

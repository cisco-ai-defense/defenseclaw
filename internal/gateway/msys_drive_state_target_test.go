package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2375: on a Windows home, Git Bash's MSYS (/c/...) and Cygwin
// (/cygdrive/c/...) spellings of DefenseClaw's own state are the writes
// their C:/ spelling is (rmdir of the hooks folder, rm, cp, mv, touch),
// with and without the POSIX hint, as is Git Bash's ~<me> spelling (GAP-2378); project work under the same spellings
// stays allowed.
func TestMSYSDriveSpellingOfActiveStateIsTheDrivePath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows home")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(cwd, "sub")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(cwd, "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	forward := filepath.ToSlash(home)
	msys := "/" + strings.ToLower(forward[:1]) + forward[2:]
	userTilde := "~" + filepath.Base(home) // GAP-2378 under Git Bash
	block := []string{"rmdir S/.defenseclaw/hooks", "rm -rf S/.defenseclaw/hooks", "rm S/.defenseclaw/config.yaml",
		"cp a.txt S/.defenseclaw/config.yaml", "mv S/.defenseclaw/hooks S/old-hooks", "touch S/.defenseclaw/hooks/x.sh"}
	allow := []string{"rmdir S/project/sub", "cp a.txt S/project/b.txt", "ls S/.defenseclaw", "cat S/.defenseclaw/config.yaml"}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, spelling := range []string{forward, msys, "/cygdrive" + msys, userTilde} {
				for _, rows := range []struct {
					templates []string
					want      bool
				}{{block, true}, {allow, false}} {
					for _, template := range rows.templates {
						command := strings.ReplaceAll(template, "S/", spelling+"/")
						input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home, DialectHint: hint}
						findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
							Input: input, Connector: connectorName, EnforcementCapable: true,
						})
						if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != rows.want {
							t.Errorf("%s hint=%q %q: blocked=%v, want %v (%v)",
								connectorName, hint, command, blocked, rows.want, FindingStrings(findings))
						}
					}
				}
			}
		}
	}
}

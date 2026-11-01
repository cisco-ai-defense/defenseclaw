package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2399: under Git Bash on a Windows home, dd of= naming DefenseClaw's
// own state through $HOME, ${HOME}, "$HOME", ~, the drive and the MSYS
// spelling is a state write and blocks as it does on Linux and macOS;
// dd into the project stays allowed.
func TestWindowsGitBashDDOptionStateTargetBlocks(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows home")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), cwd} {
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
	block := []string{
		"dd if=a.txt of=$HOME/.defenseclaw/config.yaml",
		"dd if=a.txt of=${HOME}/.defenseclaw/hooks/f.sh",
		`dd if=a.txt "of=$HOME/.defenseclaw/config.yaml"`,
		"dd if=a.txt of=~/.defenseclaw/config.yaml",
		"dd if=a.txt of=" + forward + "/.defenseclaw/config.yaml",
		"dd if=a.txt of=" + msys + "/.defenseclaw/config.yaml",
	}
	allow := []string{
		"dd if=a.txt of=$HOME/project/b.img",
		"dd if=a.txt of=b.img",
		"dd if=$HOME/.defenseclaw/config.yaml of=copy.yaml",
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, rows := range []struct {
				commands []string
				want     bool
			}{{block, true}, {allow, false}} {
				for _, command := range rows.commands {
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

// The same dd rows through the Claude Code and Codex hook evaluation on a
// Windows home, in action and observe (state writes block in every mode).
func TestWindowsGitBashDDOptionStateTargetHookBlocks(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows home")
	}
	home, cwd := r105StateFixture(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.WriteFile(filepath.Join(cwd, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	forward := filepath.ToSlash(home)
	msys := "/" + strings.ToLower(forward[:1]) + forward[2:]
	rows := []r105StateRow{
		{name: "home", command: "dd if=a.txt of=$HOME/.defenseclaw/config.yaml", block: true},
		{name: "brace", command: "dd if=a.txt of=${HOME}/.defenseclaw/hooks/f.sh", block: true},
		{name: "quoted", command: `dd if=a.txt "of=$HOME/.defenseclaw/config.yaml"`, block: true},
		{name: "tilde", command: "dd if=a.txt of=~/.defenseclaw/config.yaml", block: true},
		{name: "drive", command: "dd if=a.txt of=" + forward + "/.defenseclaw/config.yaml", block: true},
		{name: "msys", command: "dd if=a.txt of=" + msys + "/.defenseclaw/config.yaml", block: true},
		{name: "profile", command: "dd if=a.txt of=$USERPROFILE/.defenseclaw/config.yaml", block: true},
		{name: "quoted-msys", command: "dd if=a.txt of='" + msys + "/.defenseclaw/config.yaml'", block: true},
		{name: "profile-project", command: "dd if=a.txt of=$USERPROFILE/project-b.img"},
		{name: "project", command: "dd if=a.txt of=$HOME/project-b.img"},
		{name: "plain", command: "dd if=a.txt of=b.img"},
	}
	for _, mode := range []string{"action", "observe"} {
		r105RunStateRows(t, mode, cwd, rows)
	}
}

// GAP-2468: under Git Bash on a Windows home, $USERPROFILE spells the home
// and a quoted MSYS mount (of='/c/...', "of=/c/...", "/c/...") names the
// drive, so state writes through them block as the $HOME and unquoted
// spellings do; the same spellings into the project stay allowed.
func TestWindowsGitBashProfileAndQuotedMountStateWritesBlock(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows home")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), cwd} {
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
	block := []string{
		"dd if=a.txt 'of='" + msys + "/.defenseclaw/config.yaml",
		"dd if=a.txt of='" + msys + "/.defenseclaw/config.yaml'",
		`dd if=a.txt "of=` + msys + `/.defenseclaw/config.yaml"`,
		`dd if=a.txt of="` + msys + `/.defenseclaw/config.yaml"`,
		`cp a.txt "` + msys + `/.defenseclaw/config.yaml"`,
		"dd if=a.txt 'of=" + msys + "/.defenseclaw/config.yaml'",
		"dd if=a.txt of=$USERPROFILE/.defenseclaw/config.yaml",
		"cp a.txt $USERPROFILE/.defenseclaw/config.yaml",
		`echo x > "$USERPROFILE/.defenseclaw/config.yaml"`,
		"rm -rf ${USERPROFILE}/.defenseclaw/hooks",
	}
	allow := []string{
		"make PREFIX=" + msys + "/project/out install",
		"dd if=a.txt of='" + msys + "/project/b.img'",
		`cp a.txt "` + msys + `/project/c.txt"`,
		"grep -r x --exclude=" + msys + "/.defenseclaw/config.yaml .",
		"dd if=$USERPROFILE/.defenseclaw/config.yaml of=copy.yaml",
		"dd if=a.txt of=$USERPROFILE/project/b.img",
		`cp a.txt "$USERPROFILE/project/d.txt"`,
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, rows := range []struct {
				commands []string
				want     bool
			}{{block, true}, {allow, false}} {
				for _, command := range rows.commands {
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

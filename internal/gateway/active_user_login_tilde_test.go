package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-2378 (checker p18 RV18-1): bash reads ~<login> from the password
// database for every login it resolves, also an AD/sssd user@domain login
// and a login that is not the home's base name (/home/%d/%u). Such a
// spelling of the active user's own state or SSH keys is the write its ~/
// and absolute spellings are; other users, quoted text and project paths
// stay allowed.
func TestActiveUserLoginTildeTargetIsTheActiveHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	block := []string{
		"echo x > U/.defenseclaw/hooks/f",
		"cp a.txt U/.defenseclaw/config.yaml",
		"echo k >> U/.ssh/authorized_keys",
		"install -m 600 a.txt U/.defenseclaw/config.yaml",
		"cat a.txt | tee -a U/.defenseclaw/config.yaml",
		`bash -c "echo x > U/.defenseclaw/hooks/f"`,
		`eval "echo x > U/.defenseclaw/hooks/f"`,
		"echo x > U//.defenseclaw/config.yaml",
		"echo x > U/project/../.defenseclaw/config.yaml",
		"cd $HOME/project && dd if=a.txt of=U/.defenseclaw/config.yaml",
		"JAVA_HOME=/opt/j dd if=a.txt of=U/.defenseclaw/config.yaml",
		"dd if=a.txt of=U/.defenseclaw/config.yaml",
		"rm -rf U/.defenseclaw",
		"mv U/.defenseclaw U/old-dc",
		"source ./env.sh; make > U/.defenseclaw/config.yaml",
		"HOME=/tmp/h make > U/.defenseclaw/config.yaml",
	}
	allow := []string{
		"PATH=U/bin:$PATH make test > build.log",
		"cd U/project && make test > build.log",
		"cp a.txt U/project/b.txt",
		"rm -rf U/project/node_modules",
		"dd if=a.txt of=U/backup.img",
		"echo U",
		"ls -la U/.defenseclaw",
		"cat U/.defenseclaw/config.yaml > U/project/cfg-copy.yaml",
		"git -C U/project status",
		"x=U/build.log; make > $x",
		"cp U/.defenseclaw/config.yaml /tmp/cfg.bak",
		"echo x > U/notes.txt",
		"echo 'U/.defenseclaw/config.yaml' > notes.txt",
		"cat ~root/.profile",
	}
	for _, tc := range []struct {
		name, base, login string
		spellings         []string
	}{
		// The AD home's base name is the fully qualified login.
		{"user@domain home", "dcad-r103-eng1@dclab.test", "", []string{"~dcad-r103-eng1@dclab.test", "~DCAD-R103-ENG1@DCLAB.TEST"}},
		// sssd fallback_homedir /home/%d/%u: the login is not the base name.
		{"login is not the base name", "eng1", "eng1@dclab.test", []string{"~eng1@dclab.test", "~eng1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "dclab.test", tc.base)
			cwd := filepath.Join(home, "project")
			for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"), filepath.Join(cwd, "node_modules")} {
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
			restore := trustedSameHostLogin
			t.Cleanup(func() { trustedSameHostLogin = restore })
			login := tc.login
			trustedSameHostLogin = func() string { return login }
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
				for _, spelling := range tc.spellings {
					for _, command := range block {
						judge(strings.ReplaceAll(command, "U", spelling), true)
					}
					for _, command := range allow {
						judge(strings.ReplaceAll(command, "U", spelling), false)
					}
				}
				// Another directory user's home is not the active one.
				judge("echo x > ~bob@dclab.test/.defenseclaw/hooks/f", false)
				// dd of=~/ is read as the home whatever the base name is.
				judge("dd if=a.txt of=~/.defenseclaw/config.yaml", true)
			}
		})
	}
}

// trustedActiveLogins reads the login from the identity whose home the
// request carries: a managed hook peer's account name, a Windows
// DOMAIN\user as user, and nothing for a home that is not that account's.
func TestTrustedActiveLoginsFollowTheTrustedIdentity(t *testing.T) {
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "eng1@dclab.test", Home: "/home/dclab.test/eng1"})
	if got := trustedActiveLogins(ctx, "/home/dclab.test/eng1"); len(got) != 1 || got[0] != "eng1@dclab.test" {
		t.Errorf("managed peer logins = %q", got)
	}
	if got := trustedActiveLogins(ctx, "/home/other"); got != nil {
		t.Errorf("another home's logins = %q", got)
	}
	restore := trustedSameHostLogin
	t.Cleanup(func() { trustedSameHostLogin = restore })
	trustedSameHostLogin = func() string { return `DCLAB\dcw-std1` }
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	if got := trustedActiveLogins(context.Background(), home); len(got) != 1 || got[0] != "dcw-std1" {
		t.Errorf("same-host logins = %q", got)
	}
}

// GAP-2378 managed ProtectHome leg: the gateway cannot open the home, so
// the ~<login> twin's targets come from the hook client's map. A state
// write in that spelling blocks and a project copy stays allowed (the twin
// had no client target and read as persistence.ssh_authorized_keys_command
// for Codex on managed RHEL).
func TestActiveUserLoginTildeBehindProtectHomeUsesClientTargets(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("unprivileged POSIX gateway walk")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "eng1@dclab.test")
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
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for command, want := range map[string]bool{
			"echo x > ~eng1@dclab.test/.defenseclaw/hooks/f":           true,
			"dd if=a.txt of=~ENG1@DCLAB.TEST/.defenseclaw/config.yaml": true,
			"cp a.txt ~eng1@dclab.test/project/b.txt":                  false,
			"echo notes > ~eng1@dclab.test/project/notes.txt":          false,
		} {
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok {
				t.Fatal("client proof did not decode")
			}
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
					DialectHint: actionfacts.DialectPOSIX},
				Connector: connectorName, EnforcementCapable: true,
				ProtectedHomeHook: true, ResolvedWriteTargets: targets,
			})
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != want {
				t.Errorf("%s %q: blocked=%v, want %v (%v)", connectorName, command, blocked, want, FindingStrings(findings))
			}
		}
	}
}

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestR105LinkRenameAndNestedCd: a static mv next to an ordinary project
// link is ordinary work (GAP-2532); a link to SSH or DefenseClaw state
// stays opaque when a nested shell changes directory or find -exec renames
// it (GAP-2533).
func TestR105LinkRenameAndNestedCd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix shell rows")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"), filepath.Join(cwd, "src"), filepath.Join(cwd, "build")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "a.txt"), filepath.Join(cwd, "src", "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rows := []struct {
		command string
		block   bool
	}{
		// GAP-2532: a rename next to a benign project link.
		{`ln -s build/out bin; sh -c "mv a.txt b.txt"; ls`, false},
		{`ln -s build/out bin; mv a.txt b.txt; ls`, false},
		{`sh -c "ln -s build/out bin; mv a.txt b.txt"`, false},
		{`bash -c "ln -s build/out bin && mv bin bin2"`, false},
		{`ln -s build/out bin; sh -c "mv bin bin2"; echo x > notes.txt`, false},
		{`ln -s build/out bin; mv -f a.txt b.txt; echo x > notes.txt`, false},
		{`ln -s build/out bin && mv bin bin2 && echo ok > bin2/log.txt`, false},
		{`ln -s build/out bin; sh -c "cd src && ls"`, false},
		// Protected twins: renames of state and SSH links stay opaque.
		{`ln -s ~/.defenseclaw/config.yaml c; mv c d; echo x > d`, true},
		{`ln -s ~/.defenseclaw/config.yaml c; sh -c "mv c d"; echo x > d`, true},
		{`ln -s ~/.defenseclaw c; sh -c "mv c d"; echo x > d/config.yaml`, true},
		{`ln -s ~/.ssh/authorized_keys k; mv k j; echo key >> j`, true},
		{`ln -s ~/.defenseclaw c; mv a.txt b.txt; echo x > c/config.yaml`, true},
		{`ln -s .ssh s; mv s ../s; echo key >> ../s/authorized_keys`, true},
		{`ln -s build/out bin; mv ../.ssh build/out; echo key >> bin/authorized_keys`, true},
		// GAP-2533: a directory change in a nested shell, a find -exec rename.
		{`ln -s ~/.defenseclaw c; sh -c "cd c && echo x > config.yaml"`, true},
		{`ln -s ~/.defenseclaw c; sh -c "cd c; echo x > config.yaml"`, true},
		{`ln -s ~/.defenseclaw c; bash -c "pushd c; echo x > config.yaml"`, true},
		{`ln -s ~/.ssh s; sh -c "cd s && echo key >> authorized_keys"`, true},
		{`ln -s ~/.defenseclaw/config.yaml c; find . -name c -exec mv {} d \;; echo x > d`, true},
		{`ln -s ~/.defenseclaw/config.yaml c; sh -c "find . -name c -exec mv {} d \;"; echo x > d`, true},
		{`ln -s ~/.defenseclaw/config.yaml c; find . -name c -execdir mv {} d +; echo x > d`, true},
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, row := range rows {
			var findings []RuleFinding
			panicked := ""
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						panicked = fmt.Sprint(rec)
					}
				}()
				findings = dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input:              actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home},
					Connector:          connectorName,
					EnforcementCapable: true,
				})
			}()
			if panicked != "" {
				t.Errorf("%s %q: evaluator panic %s", connectorName, row.command, panicked)
				continue
			}
			if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
				t.Errorf("%s %q: block=%v want %v (%v)", connectorName, row.command, blocked, row.block, findings)
			}
		}
	}
}

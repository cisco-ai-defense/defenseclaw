package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestR105LinkRenameAndNestedCd: a static mv next to an ordinary project
// link is ordinary work (GAP-2532); a link to SSH or DefenseClaw state
// stays opaque when a nested shell changes directory or find -exec renames
// it (GAP-2533), also through a disk link below a linked outside directory
// (RV-c4-1).
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
	for _, name := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "a.txt"), filepath.Join(cwd, "src", "a.txt"), filepath.Join(cwd, "README.md")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A link on disk to SSH state that a find -exec mv can move onto the
	// target of a new link.
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "keys.orig")); err != nil {
		t.Fatal(err)
	}
	// RV-c4-1: a directory outside the project with disk links to SSH and
	// DefenseClaw state, and a clean one.
	ext, clean := t.TempDir(), t.TempDir()
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(ext, "x")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".defenseclaw"), filepath.Join(ext, "y")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(clean, "lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(clean, "lib"), filepath.Join(clean, "current")); err != nil {
		t.Fatal(err)
	}
	// RV-c5-1: project disk links that reach a name the command links
	// (d2/r -> ../e, dangling until ln makes e) or re-targets (p2 -> e2).
	if err := os.MkdirAll(filepath.Join(cwd, "d2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "benign", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, link := range [][2]string{{"../e", filepath.Join(cwd, "d2", "r")}, {"benign", filepath.Join(cwd, "e2")}, {"e2", filepath.Join(cwd, "p2")}} {
		if err := os.Symlink(link[0], link[1]); err != nil {
			t.Fatal(err)
		}
	}
	// RV-c5-2: an outside directory larger than the linked-tree walk bound.
	big := t.TempDir()
	for i := range 20005 {
		if err := os.WriteFile(filepath.Join(big, fmt.Sprintf("f%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	place := strings.NewReplacer("{E}", ext, "{C}", clean, "{BIG}", big)
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
		// GAP-2532 (RV-c2-2): a link to an existing project file, or to a
		// path outside the project, next to an unrelated mv.
		{`ln -s src/a.txt alias.txt; mv c.txt d.txt`, false},
		{`ln -s src/a.txt alias.txt; mv a.txt b.txt; cat alias.txt`, false},
		{`ln -s README.md docs.md; mv a.txt e.txt; ls`, false},
		{`ln -sf /usr/bin/python3 py; mv a.txt b.txt`, false},
		{`ln -sf ../src/main.go link.go; mv a.txt b.txt`, false},
		{`ln -sr build/out bin; mv bin bin2; ls`, false},
		// A moved relative link whose target reaches state from its new
		// directory, a moved directory holding one, a link to the home.
		{`ln -s ../../.defenseclaw c; mkdir sub; mv c sub/; echo x > sub/c/config.yaml`, true},
		{`mkdir -p a sub; ln -s ../../../.defenseclaw a/c; mv a sub/; echo x > sub/a/c/config.yaml`, true},
		{`ln -s .. up; mv a.txt b.txt; echo key >> up/.ssh/authorized_keys`, true},
		// GAP-2533 (RV-c2-1): a nested cd next to a link outside the
		// project, a find -exec mv into a project directory.
		{`ln -sf /usr/bin/python3 py; bash -c "cd src && ls"`, false},
		{`ln -s ../shared lib; sh -c "cd src && make"`, false},
		{`ln -sf /usr/bin/python3 .venv/bin/python; bash -c "cd src && python3 -m pytest" > test.log`, false},
		{`ln -sf /usr/bin/node node; nohup sh -c "cd build && npm run dev" > dev.log 2>&1 &`, false},
		{`ln -s /etc/hosts hosts.txt; sh -c "cd src && git status"`, false},
		{`ln -s build/out bin; find . -name "*.orig" -exec mv {} build/ \;`, false},
		{`ln -sf /usr/lib/libfoo.so libfoo.so; find . -name Makefile -execdir make \;`, false},
		// Twins: env -C and find -execdir change directory; a link to the
		// home or above it; a find -exec mv onto a link target or of the
		// link itself.
		{`ln -s ~/.defenseclaw c; env -C c sh -c "echo x > config.yaml"`, true},
		{`ln -s ~/.defenseclaw c; find c -maxdepth 0 -execdir sh -c "echo x > c/config.yaml" \;`, true},
		{`ln -s .. up; sh -c "cd up && echo key >> .ssh/authorized_keys"`, true},
		{`ln -s ~ h; sh -c "cd h && echo x > .defenseclaw/config.yaml"`, true},
		{`ln -s build/keys.orig k; find . -name "*.orig" -exec mv {} build/ \;; echo key >> k`, true},
		{`ln -s ~/.ssh s; find . -name "s" -exec mv {} build/ \;; echo key >> build/s/authorized_keys`, true},
		// RV-c4-1: a nested cd, env -C, find -execdir or find -exec mv below a
		// linked outside directory, through its disk link to state.
		{`ln -s {E} e; bash -c "cd e/x && echo k >> authorized_keys"`, true},
		{`ln -s {E} e; bash -c "cd e && cd x && echo k >> authorized_keys"`, true},
		{`ln -s {E} e; sh -c "cd e/x; echo k >> authorized_keys"`, true},
		{`ln -s {E} e; bash -c "cd e/y && echo z > config.yaml"`, true},
		{`ln -s {E} e; find . -name authorized_keys -exec mv {} e/x/ \;`, true},
		{`ln -s {E} e; find . -name "*.txt" -exec mv {} e/x/ \;`, true},
		{`ln -s {E} e; find e/x -maxdepth 0 -execdir sh -c "echo k >> x/authorized_keys" \;`, true},
		{`ln -s {E} e; find e/ -name x -exec mv {} build/ \;; echo k >> build/x/authorized_keys`, true},
		// RV-c5-1: the nested cd reaches the link through a project disk link.
		{`ln -s {E} e; bash -c "cd d2/r/x && echo k >> authorized_keys"`, true},
		{`ln -s {E} e; bash -c "cd d2/r/y && echo z > config.yaml"`, true},
		{`ln -sfn {E} e2; bash -c "cd p2/x && echo k >> authorized_keys"`, true},
		{`ln -s {E} e; sh -c "cd d2/r && cd x && echo k >> authorized_keys"`, true},
		{`ln -s {E} e; sh -c "cd d2 && cd r/x && echo k >> authorized_keys"`, true},
		{`ln -s {E} e; find d2/r/x -maxdepth 0 -execdir sh -c "echo k >> x/authorized_keys" ';'`, true},
		{`ln -s {E} e; find . -maxdepth 1 -name a.txt -exec mv {} d2/r/x/ \;`, true},
		// Benign: the nested cd does not go through the link, or the linked
		// directory holds no disk link to state.
		{`ln -s {E} ext; bash -c "cd src && ls"`, false},
		{`ln -s {C} sdk; sh -c "cd sdk/current && ls"`, false},
		{`ln -s {C} sdk; bash -c "cd sdk && ls lib"`, false},
		{`ln -s {C} sdk; find . -name "*.orig" -exec mv {} sdk/lib/ \;`, false},
		{`ln -s {C} sdk; bash -c "cd p2/x && ls"`, false},
		// RV-c5-2: a find that names no link does not read a large linked
		// tree beside it.
		{`ln -s {BIG} big; find . -name "*.tmp" -exec mv {} build/ \;`, false},
		{`ln -s {BIG} big; bash -c "cd src && ls"`, false},
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
					Input:              actionfacts.Input{Tool: "Bash", Command: place.Replace(row.command), CWD: cwd, ActiveHome: home},
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

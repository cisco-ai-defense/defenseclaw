//go:build !windows

package workspace

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// RV5 fixes (GAP-0752..0756): the reviewer's failing probes, kept.

func rv5Remote(fs *fakeSandbox) string {
	return filepath.Join(fs.root, strings.TrimPrefix(remoteRepo, "/"))
}

// rv5Launch commits files (and attrs as .gitattributes) and launches a
// copy with credentials replaced (form; "" holds them back).
func rv5Launch(t *testing.T, name string, files map[string]string, attrs string, form string) (*env, *fakeSandbox) {
	t.Helper()
	e := newEnv(t)
	e.initRepo()
	if attrs != "" {
		writeFile(t, e.project, ".gitattributes", attrs)
	}
	for p, c := range files {
		writeFile(t, e.project, p, c)
	}
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "files")
	_, fs := launchCopy(t, e, name, func(o *StageOptions) { o.RewriteSecrets = form })
	return e, fs
}

// rv5Pull pulls, applies with a 3-way merge and checks the folder.
func rv5Pull(t *testing.T, e *env, fs *fakeSandbox, name string, want map[string]string) *PullResult {
	t.Helper()
	pr := pull(t, e, fs, name)
	if _, err := apply(e, name, ApplyMerge, func(o *ApplyOptions) { o.AcceptSensitive = true }); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for p, w := range want {
		if got := s9aLocal(t, e, p); got != w {
			t.Errorf("%s = %q, want %q", p, got, w)
		}
	}
	noPlaceholderIn(t, e)
	return pr
}

// sandboxGit runs the agent's git in the sandbox copy.
func sandboxGit(fs *fakeSandbox, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", rv5Remote(fs), "-c", "user.name=agent", "-c", "user.email=agent@example.invalid"}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// GAP-0752: a tracked file uploaded with its credentials replaced. The
// sandbox's HEAD and index hold the uploaded version, so the agent's git
// status, diff and stash work, and the pull works with text=auto.
func TestB1RV5SandboxGitOnReplacedTrackedFile(t *testing.T) {
	k := b1Key(0)
	for _, attrs := range []string{"", "* text=auto\n"} {
		t.Run("attrs="+strings.TrimSpace(attrs), func(t *testing.T) {
			e, fs := rv5Launch(t, "rv51", map[string]string{"config.py": "import os\nTOKEN = \"" + k + "\"\nprint(TOKEN)\n"}, attrs, PlaceholderToken)
			for _, args := range [][]string{{"status", "--porcelain"}, {"diff", "--stat"}} {
				out, err := sandboxGit(fs, args...)
				if err != nil || strings.TrimSpace(out) != "" {
					t.Fatalf("sandbox git %v on the fresh copy: err=%v out=%q (want clean)", args, err, out)
				}
			}
			up := s9aRemote(t, fs, "config.py")
			fs.write(remoteRepo+"/config.py", strings.Replace(up, "import os", "import os, sys", 1))
			if out, err := sandboxGit(fs, "diff"); err != nil || !strings.Contains(out, "+import os, sys") {
				t.Fatalf("sandbox git diff: err=%v out=%q", err, out)
			}
			for _, args := range [][]string{{"stash"}, {"stash", "pop"}} {
				if out, err := sandboxGit(fs, args...); err != nil {
					t.Fatalf("sandbox git %v: err=%v out=%q", args, err, out)
				}
			}
			if strings.Contains(s9aRemote(t, fs, "config.py"), k) {
				t.Fatal("the sandbox copy holds the value")
			}
			rv5Pull(t, e, fs, "rv51", map[string]string{"config.py": "import os, sys\nTOKEN = \"" + k + "\"\nprint(TOKEN)\n"})
		})
	}
}

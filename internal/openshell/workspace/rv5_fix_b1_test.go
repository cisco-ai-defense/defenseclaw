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

// branchLeaks fails when anything reachable from branch holds key or a
// placeholder.
func branchLeaks(t *testing.T, e *env, branch, key string, absent ...string) {
	t.Helper()
	all := e.git(e.project, "log", "-p", "--format=%H %s", branch)
	if strings.Contains(all, key) && !strings.Contains(e.git(e.project, "log", "-p", "--format=%H %s", "HEAD"), key) {
		t.Errorf("the value is reachable from branch %s", branch)
	}
	if strings.Contains(all, "DC_SECRET_") {
		t.Errorf("a placeholder is reachable from branch %s", branch)
	}
	for _, a := range absent {
		if strings.Contains(all, a) {
			t.Errorf("branch %s ancestry holds %q", branch, a)
		}
	}
	if n := strings.TrimSpace(e.git(e.project, "rev-list", "--count", "HEAD.."+branch)); n != "1" {
		t.Errorf("branch %s is %s commits on HEAD, want 1", branch, n)
	}
}

// GAP-0753: the sandbox changed a file the folder had uncommitted edits
// to, so the branch keeps the whole result: an untracked file uploaded
// with replaced credentials must not land on it with its value.
func TestB1RV5BranchKeptEditsLeavesReplacedFileOut(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "app.py", "a = 1\n")
	e.git(e.project, "add", "app.py")
	e.git(e.project, "commit", "-q", "-m", "app")
	key := b1Key(0)
	writeFile(t, e.project, "creds.py", "TOKEN = \""+key+"\"\n")
	writeFile(t, e.project, "app.py", "a = 2\n")
	_, fs := launchCopy(t, e, "rv52a", func(o *StageOptions) { o.RewriteSecrets = PlaceholderToken })
	if got := s9aRemote(t, fs, "creds.py"); strings.Contains(got, key) {
		t.Fatalf("upload holds the key: %q", got)
	}
	fs.write(remoteRepo+"/app.py", "a = 3\n")
	pull(t, e, fs, "rv52a")
	res, err := apply(e, "rv52a", ApplyBranch, func(o *ApplyOptions) { o.AcceptSensitive, o.Force = true, true })
	if err != nil {
		t.Fatalf("branch: %v", err)
	}
	if tip := e.git(e.project, "ls-tree", "-r", "--name-only", res.Branch); strings.Contains(tip, "creds.py") || !strings.Contains(tip, "app.py") {
		t.Errorf("branch tree = %q, want app.py without creds.py", tip)
	}
	if got := e.git(e.project, "show", res.Branch+":app.py"); got != "a = 3" {
		t.Errorf("branch app.py = %q, want the sandbox's", got)
	}
	branchLeaks(t, e, res.Branch, key)
}

// GAP-0753: a clean folder; the agent changed the replaced file and a
// plain one. The branch is one commit on HEAD with the plain change only:
// neither the agent's change to the replaced file nor a placeholder is in
// its ancestry.
func TestB1RV5BranchOneCommitOnHead(t *testing.T) {
	e, fs, key := s9aCopy(t, "rv52b")
	fs.write(remoteRepo+"/config.py", strings.Replace(s9aRemote(t, fs, "config.py"), "import os\n", "import os, AGENTEDIT\n", 1))
	fs.write(remoteRepo+"/notes.md", "agent notes\n")
	if out, err := sandboxGit(fs, "commit", "-qam", "agent commit"); err != nil {
		t.Fatalf("sandbox commit: %v %s", err, out)
	}
	pull(t, e, fs, "rv52b")
	res, err := apply(e, "rv52b", ApplyBranch, func(o *ApplyOptions) { o.AcceptSensitive, o.Force = true, true })
	if err != nil {
		t.Fatalf("branch: %v", err)
	}
	if got := e.git(e.project, "show", res.Branch+":notes.md"); got != "agent notes" {
		t.Errorf("branch notes.md = %q", got)
	}
	if got := e.git(e.project, "show", res.Branch+":config.py"); got != strings.TrimSpace(e.git(e.project, "show", "HEAD:config.py")) {
		t.Errorf("branch config.py = %q, want HEAD's", got)
	}
	branchLeaks(t, e, res.Branch, key, "AGENTEDIT")
	// Made again, the branch is recognized as holding the same work.
	pull(t, e, fs, "rv52b")
	if _, err := apply(e, "rv52b", ApplyBranch, func(o *ApplyOptions) { o.AcceptSensitive = true }); err != nil {
		t.Errorf("second branch apply: %v", err)
	}
}

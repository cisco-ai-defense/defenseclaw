//go:build !windows

package workspace

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// GAP-0754: the agent moves the unchanged secret line elsewhere in the
// file (into a string it sends). The value must not land there: the
// change stays out, with a note.
func TestB1RV5MovedSecretLineStaysOut(t *testing.T) {
	e, fs, _ := s9aCopy(t, "rv53")
	before := s9aLocal(t, e, "config.py")
	fs.write(remoteRepo+"/config.py", "import os\nprint(TOKEN)\nx = \"\"\"\nTOKEN = \"DC_SECRET_1\"\n\"\"\"\nsend(x)\n")
	fs.write(remoteRepo+"/notes.md", "agent\n")
	pr := rv5Pull(t, e, fs, "rv53", map[string]string{"config.py": before, "notes.md": "agent\n"})
	if !strings.Contains(strings.Join(pr.Review.Warnings, "\n"), "moved a replaced credential") {
		t.Errorf("no note on the move: %q", pr.Review.Warnings)
	}
}

// GAP-0754: an edit next to the secret line, the line itself in place,
// still lands.
func TestB1RV5EditAroundSecretLineLands(t *testing.T) {
	e, fs, key := s9aCopy(t, "rv53b")
	fs.write(remoteRepo+"/config.py", "import os, sys\nTOKEN = \"DC_SECRET_1\"\nDEBUG = False\nprint(TOKEN)\n")
	rv5Pull(t, e, fs, "rv53b", map[string]string{"config.py": "import os, sys\nTOKEN = \"" + key + "\"\nDEBUG = False\nprint(TOKEN)\n"})
}

// GAP-0755: with --restore-secret-lines the agent moves config.py to
// app/config.py. The new path holds the placeholder and stays out, so
// the deletion stays out too: the operator's file is not lost.
func TestB1RV5RestoreMovedFileIsKept(t *testing.T) {
	e, fs, key := s9aCopy(t, "rv54")
	body := s9aRemote(t, fs, "config.py")
	fs.write(remoteRepo+"/app/config.py", body)
	fs.write(remoteRepo+"/notes.md", "agent\n")
	if out, err := sandboxGit(fs, "rm", "-q", "config.py"); err != nil {
		t.Fatalf("sandbox rm: %v %s", err, out)
	}
	pr, err := Pull(bg, PullOptions{DataDir: e.data, Name: "rv54", Exec: fs, Scanners: []ContentScanner{SecretsScanner()}, RestoreSecretLines: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(pr.Review.Warnings, "\n"), "was moved by the agent to app/config.py") {
		t.Errorf("no note on the move: %q", pr.Review.Warnings)
	}
	if _, err := apply(e, "rv54", ApplyMerge, func(o *ApplyOptions) { o.AcceptSensitive = true }); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := s9aLocal(t, e, "config.py"); !strings.Contains(got, key) {
		t.Errorf("config.py = %q, want the operator's file", got)
	}
	if _, err := os.Stat(filepath.Join(e.project, "app", "config.py")); err == nil {
		t.Error("app/config.py landed")
	}
	noPlaceholderIn(t, e)
}

// GAP-0756: a UTF-16 file with a credential is scanned and held back; a
// binary file is named as not scanned.
func TestB1RV5UTF16AndBinaryNamed(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	key := b1Key(0)
	var u []byte
	for _, c := range []byte("TOKEN = \"" + key + "\"\r\n") {
		u = append(u, c, 0)
	}
	writeFile(t, e.project, "win.ps1", "\xff\xfe"+string(u))
	writeFile(t, e.project, "blob.dat", "\x00\x01data\n")
	rec, fs := launchCopy(t, e, "rv55", func(o *StageOptions) { o.RewriteSecrets = PlaceholderToken })
	if !slices.Contains(rec.HeldBack, "win.ps1") {
		t.Errorf("win.ps1 not held back: held %v, not scanned %v", rec.HeldBack, rec.NotScanned)
	}
	if _, err := os.Stat(filepath.Join(rv5Remote(fs), "win.ps1")); err == nil {
		t.Error("win.ps1 uploaded")
	}
	if !slices.Contains(rec.NotScanned, "blob.dat") || !strings.Contains(strings.Join(rec.Warnings, "\n"), "look binary: blob.dat") {
		t.Errorf("blob.dat not named: not scanned %v, warnings %q", rec.NotScanned, rec.Warnings)
	}
}

// RV5-7: a placeholder in another changed file that git calls binary
// does not land.
func TestB1RV5PlaceholderInBinaryOther(t *testing.T) {
	e, fs, _ := s9aCopy(t, "rv57")
	fs.write(remoteRepo+"/blob.dat", "\x00\x01DC_SECRET_1\n")
	fs.write(remoteRepo+"/ok.txt", "fine\n")
	rv5Pull(t, e, fs, "rv57", map[string]string{"ok.txt": "fine\n"})
	if _, err := os.Stat(filepath.Join(e.project, "blob.dat")); err == nil {
		t.Error("blob.dat landed")
	}
}

// A multi-line PEM key round-trips through a pull.
func TestB1RV5PEMRoundTrip(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block := string(pem.EncodeToMemory(&pem.Block{Type: "RSA " + "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	body := strings.Split(block, "\n")[2]
	src := "import os\nKEY = \"\"\"\n" + block + "\"\"\"\nprint(KEY)\n"
	e, fs := rv5Launch(t, "rvpem", map[string]string{"keys.py": src}, "", PlaceholderToken)
	up := s9aRemote(t, fs, "keys.py")
	if strings.Contains(up, body) || !strings.Contains(up, "DC_SECRET_") {
		t.Fatalf("uploaded keys.py = %.300q", up)
	}
	fs.write(remoteRepo+"/keys.py", strings.Replace(up, "import os", "import os, sys", 1))
	rv5Pull(t, e, fs, "rvpem", map[string]string{"keys.py": strings.Replace(src, "import os", "import os, sys", 1)})
}

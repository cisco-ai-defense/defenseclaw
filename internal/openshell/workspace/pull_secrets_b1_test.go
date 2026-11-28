//go:build !windows

package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B1 S9a step 5: pull translates placeholders back. These tests use only
// API older than the step, so they run (red) against the interim guard.

// s9aCopy launches a git project whose config.py holds a key, uploaded
// with the key replaced by DC_SECRET_1.
func s9aCopy(t *testing.T, name string) (*env, *fakeSandbox, string) {
	t.Helper()
	e := newEnv(t)
	e.initRepo()
	key := b1Key(0)
	writeFile(t, e.project, "config.py", "import os\nTOKEN = \""+key+"\"\nprint(TOKEN)\n")
	e.git(e.project, "add", "config.py")
	e.commit("config")
	_, fs := launchCopy(t, e, name, func(o *StageOptions) { o.RewriteSecrets = PlaceholderToken })
	if got := s9aRemote(t, fs, "config.py"); !strings.Contains(got, "DC_SECRET_1") || strings.Contains(got, key) {
		t.Fatalf("uploaded config.py = %q", got)
	}
	return e, fs, key
}

func s9aRemote(t *testing.T, fs *fakeSandbox, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fs.root, strings.TrimPrefix(remoteRepo, "/"), rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func s9aLocal(t *testing.T, e *env, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.project, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// noPlaceholderIn fails when any project file holds a placeholder.
func noPlaceholderIn(t *testing.T, e *env) {
	t.Helper()
	_ = filepath.WalkDir(e.project, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if b, _ := os.ReadFile(p); !d.IsDir() && strings.Contains(string(b), "DC_SECRET_") {
			t.Errorf("%s holds a placeholder: %q", p, b)
		}
		return nil
	})
}

func hasNote(pr *PullResult, sub string) bool {
	for _, w := range pr.Review.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// The agent's edit to a replaced file lands with the local value; a
// placeholder the agent copied into another file does not land.
func TestB1PullNeverWritesValueOrPlaceholder(t *testing.T) {
	e, fs, key := s9aCopy(t, "s9a1")
	fs.write(remoteRepo+"/config.py", strings.Replace(s9aRemote(t, fs, "config.py"), "import os\n", "import os, sys\n", 1))
	fs.write(remoteRepo+"/notes.md", "the token is DC_SECRET_1\n")
	fs.write(remoteRepo+"/README.md", "agent readme\n")
	pr := pull(t, e, fs, "s9a1")
	if pr.Review.Sensitive() {
		t.Fatalf("review is sensitive: %+v", pr.Review.Findings)
	}
	for _, c := range pr.Changes {
		if c.Path == "notes.md" {
			t.Fatalf("notes.md (a placeholder) is among the changes: %+v", pr.Changes)
		}
	}
	if !hasNote(pr, "notes.md") {
		t.Fatalf("no note for notes.md: %q", pr.Review.Warnings)
	}
	mustApply(t, e, "s9a1")
	if got, want := s9aLocal(t, e, "config.py"), "import os, sys\nTOKEN = \""+key+"\"\nprint(TOKEN)\n"; got != want {
		t.Fatalf("config.py = %q, want %q", got, want)
	}
	if got := s9aLocal(t, e, "README.md"); got != "agent readme\n" {
		t.Fatalf("README.md = %q", got)
	}
	if _, err := os.Stat(filepath.Join(e.project, "notes.md")); err == nil {
		t.Fatal("notes.md landed")
	}
	noPlaceholderIn(t, e)
}

// A changed line that holds a placeholder keeps the local line, with a
// note; the agent's other edits to the file land.
func TestB1PullKeepsLocalLineAgentChanged(t *testing.T) {
	e, fs, key := s9aCopy(t, "s9a2")
	fs.write(remoteRepo+"/config.py", "import os\nTOKEN = \"DC_SECRET_1\"  # deploy\nprint(TOKEN, 1)\n")
	pr := pull(t, e, fs, "s9a2")
	if !hasNote(pr, "kept your line 2") {
		t.Fatalf("no kept-line note: %q", pr.Review.Warnings)
	}
	mustApply(t, e, "s9a2")
	if got, want := s9aLocal(t, e, "config.py"), "import os\nTOKEN = \""+key+"\"\nprint(TOKEN, 1)\n"; got != want {
		t.Fatalf("config.py = %q, want %q", got, want)
	}
	noPlaceholderIn(t, e)
}

// A local edit to the secret line since the upload: the agent's change to
// the file is not brought back.
func TestB1PullDropsWhenLocalChanged(t *testing.T) {
	e, fs, _ := s9aCopy(t, "s9a3")
	writeFile(t, e.project, "config.py", "import os\nTOKEN = \"rotated\"\nprint(TOKEN)\n")
	fs.write(remoteRepo+"/config.py", strings.Replace(s9aRemote(t, fs, "config.py"), "print(TOKEN)", "print(TOKEN, 2)", 1))
	fs.write(remoteRepo+"/README.md", "agent readme\n")
	pr := pull(t, e, fs, "s9a3")
	if !hasNote(pr, "changed in your folder since the upload") {
		t.Fatalf("no note: %q", pr.Review.Warnings)
	}
	mustApply(t, e, "s9a3")
	if got := s9aLocal(t, e, "config.py"); got != "import os\nTOKEN = \"rotated\"\nprint(TOKEN)\n" {
		t.Fatalf("config.py = %q", got)
	}
	noPlaceholderIn(t, e)
}

// A patch leaves the agent's change to a replaced file out and says so;
// the patch never holds the value or a placeholder.
func TestB1PatchLeavesReplacedFileOut(t *testing.T) {
	e, fs, key := s9aCopy(t, "s9a4")
	fs.write(remoteRepo+"/config.py", strings.Replace(s9aRemote(t, fs, "config.py"), "import os\n", "import os, sys\n", 1))
	fs.write(remoteRepo+"/README.md", "agent readme\n")
	pull(t, e, fs, "s9a4")
	out := filepath.Join(e.home, "s9a4.patch")
	res, err := apply(e, "s9a4", ApplyPatch, func(o *ApplyOptions) { o.PatchPath = out })
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if p := string(b); strings.Contains(p, key) || strings.Contains(p, "DC_SECRET_") || strings.Contains(p, "config.py") || !strings.Contains(p, "README.md") {
		t.Fatalf("patch = %q", p)
	}
	if len(res.Warnings) == 0 || !strings.Contains(strings.Join(res.Warnings, "\n"), "config.py") {
		t.Fatalf("warnings = %q", res.Warnings)
	}
}

// After an apply moved the secret line, the next pull still finds the
// value; a change that stays out never undoes what an apply brought, and
// never lands a placeholder.
func TestB1PullAfterApplyKeepsAppliedChange(t *testing.T) {
	e, fs, key := s9aCopy(t, "s9a5")
	fs.write(remoteRepo+"/config.py", "# header\n"+s9aRemote(t, fs, "config.py"))
	pull(t, e, fs, "s9a5")
	mustApply(t, e, "s9a5")
	fs.write(remoteRepo+"/config.py", strings.Replace(s9aRemote(t, fs, "config.py"), "print(TOKEN)", "print(TOKEN, 3)", 1))
	pull(t, e, fs, "s9a5")
	mustApply(t, e, "s9a5")
	want := "# header\nimport os\nTOKEN = \"" + key + "\"\nprint(TOKEN, 3)\n"
	if got := s9aLocal(t, e, "config.py"); got != want {
		t.Fatalf("after 2 applies config.py = %q, want %q", got, want)
	}
	fs.write(remoteRepo+"/config.py", "# header\nimport os\nTOKEN = os.environ[\"TOKEN\"]\nprint(TOKEN, 3)\n")
	fs.write(remoteRepo+"/README.md", "agent readme\n")
	pull(t, e, fs, "s9a5")
	mustApply(t, e, "s9a5")
	if got := s9aLocal(t, e, "config.py"); got != want {
		t.Fatalf("after a dropped change config.py = %q, want %q", got, want)
	}
	noPlaceholderIn(t, e)
}

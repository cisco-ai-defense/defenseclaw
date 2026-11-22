//go:build !windows

package workspace

import (
	"strings"
	"testing"
)

func pullRestore(t *testing.T, e *env, fs *fakeSandbox, name string) *PullResult {
	t.Helper()
	pr, err := Pull(bg, PullOptions{DataDir: e.data, Name: name, Exec: fs, Scanners: []ContentScanner{SecretsScanner()}, RestoreSecretLines: true})
	if err != nil {
		t.Fatal(err)
	}
	return pr
}

// --restore-secret-lines puts the value back on the agent's changed line,
// and the review does not flag the value it put back.
func TestB1PullRestoreSecretLinesPutsValueBack(t *testing.T) {
	e, fs, key := s9aCopy(t, "s9r1")
	fs.write(remoteRepo+"/config.py", "import os\nTOKEN = \"DC_SECRET_1\"  # deploy\nprint(TOKEN, 1)\n")
	pr := pullRestore(t, e, fs, "s9r1")
	if pr.Review.Sensitive() {
		t.Fatalf("review is sensitive: %+v", pr.Review.Findings)
	}
	mustApply(t, e, "s9r1")
	if got, want := s9aLocal(t, e, "config.py"), "import os\nTOKEN = \""+key+"\"  # deploy\nprint(TOKEN, 1)\n"; got != want {
		t.Fatalf("config.py = %q, want %q", got, want)
	}
	noPlaceholderIn(t, e)
}

// The agent removed the line: by default the change is not brought back;
// --restore-secret-lines takes the agent's lines as they are.
func TestB1PullRemovedSecretLine(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "restore"}[restore], func(t *testing.T) { s9aRemoved(t, restore) })
	}
}

func s9aRemoved(t *testing.T, restore bool) {
	{
		e, fs, key := s9aCopy(t, "s9r2")
		fs.write(remoteRepo+"/config.py", "import os\nTOKEN = os.environ[\"TOKEN\"]\nprint(TOKEN)\n")
		if restore {
			pullRestore(t, e, fs, "s9r2")
		} else {
			pr := pull(t, e, fs, "s9r2")
			if !hasNote(pr, "removed or rewrote line 2") {
				t.Fatalf("no note: %q", pr.Review.Warnings)
			}
			fs.write(remoteRepo+"/README.md", "agent readme\n")
			pull(t, e, fs, "s9r2")
		}
		mustApply(t, e, "s9r2")
		want := "import os\nTOKEN = \"" + key + "\"\nprint(TOKEN)\n"
		if restore {
			want = "import os\nTOKEN = os.environ[\"TOKEN\"]\nprint(TOKEN)\n"
		}
		if got := s9aLocal(t, e, "config.py"); got != want {
			t.Fatalf("restore=%v: config.py = %q, want %q", restore, got, want)
		}
		noPlaceholderIn(t, e)
	}
}

// DC_SECRET_1 is not DC_SECRET_12; the env form wraps the token.
func TestB1PlaceholderTokens(t *testing.T) {
	b := []byte("a DC_SECRET_12 b DC_SECRET_1 c ${DC_SECRET_1}")
	if got := tokenAt(b, "DC_SECRET_1"); len(got) != 2 {
		t.Fatalf("DC_SECRET_1 at %v", got)
	}
	out, ok := withValues(b, nil, map[string][]byte{"DC_SECRET_1": []byte("v1"), "${DC_SECRET_1}": []byte("e1")})
	if !ok || string(out) != "a DC_SECRET_12 b v1 c e1" {
		t.Fatalf("withValues = %q, %v", out, ok)
	}
	if _, ok := withValues([]byte("x DC_SECRET_1 DC_SECRET_1"), []SecretLine{{Placeholder: "DC_SECRET_1"}}, nil); ok {
		t.Fatal("a repeated placeholder passed")
	}
	if _, _, _, _, why := translateReplaced([]byte("k = DC_SECRET_1\n"), []byte("k = DC_SECRET_1\nj = DC_SECRET_1\n"), []SecretLine{{Placeholder: "DC_SECRET_1", Line: 1}}, true); !strings.Contains(why, "more than once") {
		t.Fatalf("why = %q", why)
	}
}

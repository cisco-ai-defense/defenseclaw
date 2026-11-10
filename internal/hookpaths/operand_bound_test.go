// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestPlainOperandNamesAreOnlyNamesNoProtectedFileIsCalled(t *testing.T) {
	plain := []string{
		"a.txt", "f123", "src/main.go", "dir/sub/file-1.tar.gz", "report_2026.md", "UPPER", "./f1", "\x27a\x27", "\"dir/a\"",
		"/tmp/work/out1.txt", "/home/user/project/src/a.go", "C:\\Users\\user\\work\\a.txt", "c:/work/b.txt", "dir\\a.txt",
	}
	named := []string{
		"authorized_keys", "src/authorized_keys2", "id_rsa.pub", "keys.txt", "ssh_config", ".ssh/x", ".hidden", "../x",
		"~/x", "$HOME", "${x}", "*.txt", "a?b", "a[1]", "a b", "\x27a b\x27", "\x27a\"", "a\\ b", "C:x", "\\\\host\\s", "//host/s",
		"/etc/passwd", "/etc/profile", "/usr/lib/x", "/var/spool/cron/u", "/root/x", "C:\\Windows\\System32\\x", "C:\\ProgramData\\x",
		"name.", "a/../b", "PROGRA~1", "AGENTS.md", "dir/claude.md", "Soul.MD", "defenseclaw.yaml", "openclaw.json", "memory.md",
		"x=y", "-f", "", `\.\./.\s\s\h/\a\u\t\h\o\r\i\z\e\d_\k\e\y\s`, `\.\./f`, `a\$b`, `"a\b"`, `\'a\'`, `"unclosed`, "file.txt:stream", "a{1,2}", "%TEMP%", "config", "dir/Config", "environment", "rc", "bashrc", "profile",
		"Library/LaunchAgents/x.plist", "systemd/x.service", "crontab", "startup/x", "x\u00e9", "dir/.git/config", "a/.b",
	}
	for _, word := range plain {
		if _, plain := plainOperandName(word); !plain {
			t.Errorf("%q is not plain", word)
		}
	}
	for _, word := range named {
		if name, plain := plainOperandName(word); plain {
			t.Errorf("%q is plain: %q", word, name)
		}
	}
}

// The hook client describes a call over the operand bound by its first
// operands and the later ones that are not plain names, and says so in the
// map; a command within the bound is described as before (GAP-0943).
func TestClientDescribesACallOverTheOperandBoundOnce(t *testing.T) {
	bound := actionfacts.MaxOperandsPerCall
	words := func(n int) string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("f%d", i)
		}
		return strings.Join(out, " ")
	}
	if _, over := BoundCommandOperands("touch "+words(bound), "", ""); over {
		t.Error("a call at the bound is over it")
	}
	reduced, over := BoundCommandOperands("touch "+words(5000)+" ../.ssh/authorized_keys", "", "")
	if !over {
		t.Fatal("a call of 5001 operands is not over the bound")
	}
	if !strings.HasSuffix(reduced, " ../.ssh/authorized_keys") || strings.Contains(reduced, "f4999") {
		t.Errorf("reduced command keeps the wrong operands: %.80s...%.40s", reduced, reduced[max(0, len(reduced)-40):])
	}
	// Quoted names and path forms are plain names too: they are no cover for
	// a protected file named after them.
	padding := strings.Repeat("\"f1\" ./f2 /tmp/f3 ", 2000)
	reduced, over = BoundCommandOperands("touch "+padding+"../.ssh/authorized_keys", "", "")
	if !over || !strings.HasSuffix(reduced, " ../.ssh/authorized_keys") || len(reduced) > bound*20 {
		t.Errorf("padding kept: over %v, %d bytes of %d", over, len(reduced), len(padding))
	}
}

// Past the bound a plain name stays in the reduced command when one read of
// the file system finds a link in it, in the name or in a folder below the
// cwd, and when it is a second name of a protected key file; a plain name of
// an ordinary folder, or of none, is left out (GAP-0943).
func TestBoundCommandOperandsKeepsAPlainNameThatIsALink(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"real", "sub"} {
		if err := os.Mkdir(filepath.Join(cwd, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"alias": keys, "fl": filepath.Join(cwd, "real")} {
		if err := os.Symlink(target, filepath.Join(cwd, link)); err != nil {
			t.Skipf("no links here: %v", err)
		}
	}
	if err := os.Link(keys, filepath.Join(cwd, "hl")); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	padding := strings.Repeat("f1 ", 2000)
	for _, tc := range []struct {
		word string
		kept bool
	}{
		{"alias", true}, {"\"alias\"", true}, {"./alias", true}, {"hl", true}, {"fl/x", true}, {"fl/x/y", true},
		{"sub/x", false}, {"none/x", false}, {"real", false}, {"sub", false},
		{filepath.Join(cwd, "alias"), true}, {filepath.Join(cwd, "fl", "x"), true},
	} {
		if _, plain := plainOperandName(tc.word); !plain {
			// A temporary folder under a system folder (macOS) is no plain name.
			continue
		}
		reduced, over := BoundCommandOperands("touch "+padding+tc.word, cwd, home)
		if !over {
			t.Fatalf("%q: not over the bound", tc.word)
		}
		if got := strings.HasSuffix(reduced, " "+tc.word); got != tc.kept {
			t.Errorf("%q: kept %v, want %v", tc.word, got, tc.kept)
		}
	}
	// A cwd that is a link keeps every relative name.
	linkCwd := filepath.Join(t.TempDir(), "cwdlink")
	if err := os.Symlink(cwd, linkCwd); err != nil {
		t.Skipf("no links here: %v", err)
	}
	if reduced, _ := BoundCommandOperands("touch "+padding+"sub/x", linkCwd, home); !strings.HasSuffix(reduced, " sub/x") {
		t.Error("a relative name of a cwd that is a link was left out")
	}
}

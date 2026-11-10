// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
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
		"x=y", "-f", "", "file.txt:stream", "a{1,2}", "%TEMP%", "config", "dir/Config", "environment", "rc", "bashrc", "profile",
		"Library/LaunchAgents/x.plist", "systemd/x.service", "crontab", "startup/x", "x\u00e9", "dir/.git/config", "a/.b",
	}
	for _, word := range plain {
		if !plainOperandName(word) {
			t.Errorf("%q is not plain", word)
		}
	}
	for _, word := range named {
		if plainOperandName(word) {
			t.Errorf("%q is plain", word)
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
	if _, over := BoundCommandOperands("touch " + words(bound)); over {
		t.Error("a call at the bound is over it")
	}
	reduced, over := BoundCommandOperands("touch " + words(5000) + " ../.ssh/authorized_keys")
	if !over {
		t.Fatal("a call of 5001 operands is not over the bound")
	}
	if !strings.HasSuffix(reduced, " ../.ssh/authorized_keys") || strings.Contains(reduced, "f4999") {
		t.Errorf("reduced command keeps the wrong operands: %.80s...%.40s", reduced, reduced[max(0, len(reduced)-40):])
	}
	// Quoted names and path forms are plain names too: they are no cover for
	// a protected file named after them.
	padding := strings.Repeat("\"f1\" ./f2 /tmp/f3 ", 2000)
	reduced, over = BoundCommandOperands("touch " + padding + "../.ssh/authorized_keys")
	if !over || !strings.HasSuffix(reduced, " ../.ssh/authorized_keys") || len(reduced) > bound*20 {
		t.Errorf("padding kept: over %v, %d bytes of %d", over, len(reduced), len(padding))
	}
}

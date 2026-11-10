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
	plain := []string{"a.txt", "f123", "src/main.go", "dir/sub/file-1.tar.gz", "report_2026.md", "UPPER"}
	named := []string{
		"authorized_keys", "src/authorized_keys2", "id_rsa.pub", "keys.txt", "ssh_config", ".ssh/x", ".hidden", "../x",
		"~/x", "$HOME", "${x}", "*.txt", "a?b", "a[1]", "a b", "\x27a\x27", "\"a\"", "C:x", "C:\\x", "\\\\host\\s", "//host/s",
		"/etc/passwd", "name.", "a/../b", "PROGRA~1", "AGENTS.md", "dir/claude.md", "Soul.MD", "defenseclaw.yaml",
		"openclaw.json", "memory.md", "x=y", "-f", "",
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

// The hook client describes a statement over the operand bound by its first
// operands and the later ones that are not plain names, and says so in the
// map; a command within the bound is described as before (GAP-0943).
func TestClientDescribesAStatementOverTheOperandBoundOnce(t *testing.T) {
	bound := actionfacts.MaxOperandsPerStatement
	words := func(n int) string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("f%d", i)
		}
		return strings.Join(out, " ")
	}
	if _, over := BoundCommandOperands("touch " + words(bound)); over {
		t.Error("a statement at the bound is over it")
	}
	reduced, over := BoundCommandOperands("touch " + words(5000) + " ../.ssh/authorized_keys")
	if !over {
		t.Fatal("a statement of 5001 operands is not over the bound")
	}
	if !strings.HasSuffix(reduced, " ../.ssh/authorized_keys") || strings.Contains(reduced, "f4999") {
		t.Errorf("reduced command keeps the wrong operands: %.80s...%.40s", reduced, reduced[max(0, len(reduced)-40):])
	}
}

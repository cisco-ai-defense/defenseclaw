// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
)

// GAP-0795: a relay of the agent's own user answers a git operation with
// ExitGitUnseparated (the launcher then runs the in-actor review with a
// warning); it never runs GitCommand as a program.
func TestGAP0795UnseparatedRelayAnswersGitOp(t *testing.T) {
	var w bytes.Buffer
	runExec(context.Background(), ExecRequest{Argv: []string{GitCommand, "review", "/x", "https://h/r.git", strings.Repeat("a", 40), "p", "r"}}, t.TempDir(), &w, func() {}, nil)
	b, code := w.Bytes(), ""
	for len(b) >= 5 {
		n := int(binary.BigEndian.Uint32(b[1:5]))
		if b[0] == ExecExit {
			code = string(b[5 : 5+n])
		}
		b = b[5+n:]
	}
	if code != "96" {
		t.Fatalf("exit %q, want 96 (ExitGitUnseparated)", code)
	}
}

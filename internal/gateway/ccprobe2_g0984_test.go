// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0984: one statement of joined
// quoted words (the GAP-0984 drain shape, built as gap0984JoinedQuotes builds
// it) sent through the real Claude Code hook route (gap0437Server/gap0437Hook)
// in the default pack. The cap floor re-read the statement for every joined
// quote (13.9 s per call at 36 KiB on d4), past the hook answer deadline
// (per-user 3.5 s), so the agent got the no-answer fail mode. On rel the call
// answers well inside the deadline. Scratch, test-only branch.

package gateway

import (
	"strings"
	"testing"
	"time"
)

func ccp2g0984JoinedQuotes(n int) string {
	return "tool '" + strings.Repeat("cat <<'\"'\"'E'\"'\"'\n", n) + "E\nit's (x)\necho after"
}

func TestCCP2G0984_JoinedQuotesAnswerInsideTheHookDeadline(t *testing.T) {
	p := gap0437Pack{name: "default", pack: "default"}
	a := gap0437Server(t, p, "claudecode", "action")
	cwd := t.TempDir()
	// warm the server once with a short call so the timing is the call's own
	gap0437Hook(t, a, cwd, "g0984-warm", "echo ok")
	for _, n := range []int{2000} {
		command := ccp2g0984JoinedQuotes(n)
		start := time.Now()
		out := gap0437Hook(t, a, cwd, "g0984", command)
		elapsed := time.Since(start)
		t.Logf("n=%d bytes=%d elapsed=%s action=%v", n, len(command), elapsed, out["action"])
		if elapsed > 3500*time.Millisecond {
			t.Errorf("n=%d (%d bytes): hook answer took %s, past the 3.5 s per-user hook answer deadline", n, len(command), elapsed)
		}
	}
}

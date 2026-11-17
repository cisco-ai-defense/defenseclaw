// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe3 old-API probe for rel-1-0-10:GAP-0984 (P1): the drain shape of the
// gap's own timing harness (evidence/rel-1-0-10/s7/g0984/zz_g0984_time_test.go:
// a statement of joined quoted words, then a here-document consumer) sent
// through the real Claude Code hook route (gap0437Server/gap0437Hook, old API
// at the pre-fix sha adce183510) in the default pack. Pre-fix the cap floor
// re-read the statement for every joined quote (13.6-13.9 s per call at
// 36 KiB on d4), past the 3.5 s per-user hook answer deadline. On rel the call
// answers inside it. The s7-probe2 copy left out the consumer script, so the
// cap floor never ran and it was green on both sides. Scratch, test-only.

package gateway

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func ccp3g0984Shape(n int) string {
	return "tool '" + strings.Repeat("cat <<'\"'\"'E'\"'\"'\n", n) + "E\nit's (x)\necho after"
}

func TestCCP3G0984_DrainShapeAnswersInsideTheHookDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shape")
	}
	p := gap0437Pack{name: "default", pack: "default"}
	hook := gap0437Server(t, p, "claudecode", "action")
	cwd := t.TempDir()
	gap0437Hook(t, hook, cwd, "g0984-warm", "echo ok")
	for _, consumer := range []string{"bash", "cat > notes.txt"} {
		const n = 2000
		command := ccp3g0984Shape(n) + "\n" + gap0876Script(consumer, gap0486Blocked["B1"])
		start := time.Now()
		out := gap0437Hook(t, hook, cwd, "g0984p3", command)
		elapsed := time.Since(start)
		t.Logf("ROW consumer=%d n=%d bytes=%d action=%v severity=%v elapsed_ms=%d", len(consumer), n, len(command), out["action"], out["severity"], elapsed.Milliseconds())
		if elapsed > 3500*time.Millisecond {
			t.Errorf("consumer %d bytes, n=%d (%d bytes): the hook answer took %s, past the 3.5 s per-user hook answer deadline", len(consumer), n, len(command), elapsed)
		}
	}
}

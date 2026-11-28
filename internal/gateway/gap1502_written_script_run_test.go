// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// TestGAP1502WrittenScriptRunLaterIsJudgedByItsBody: a script a statement of
// the call writes from text the reading knows (a here-document, a here-string,
// an echo or printf) and a later statement runs (sh F, bash F, . F, source F,
// ./F, sudo bash F) is the script the call runs, so the hook answers it as
// the direct form of the same script, the oracle (rel-1-0-10:GAP-1502; the
// file forms were allowed in every tier at rel and head). A harmless script,
// a file another interpreter runs and a written note stay allowed.
func TestGAP1502WrittenScriptRunLaterIsJudgedByItsBody(t *testing.T) {
	bodies := []string{
		": >> ~/.defenseclaw/config.yaml",
		"printf changed >> $HOME/.defenseclaw/config.yaml",
		"rm -rf ~/*",
	}
	forms := []string{
		"cat > x <<'EOF'\nBODY\nEOF\nsh x",
		"cat > run.sh <<EOF\nBODY\nEOF\nbash run.sh",
		"cat <<'EOF' > run.sh\nBODY\nEOF\n. ./run.sh",
		"cat > run.sh <<'EOF'\nBODY\nEOF\nsource run.sh",
		"cat > run.sh <<'EOF'\nBODY\nEOF\nchmod +x run.sh && ./run.sh",
		"cat > run.sh <<'EOF'\n#!/bin/sh\nBODY\nEOF\nchmod +x run.sh; ./run.sh",
		"cat > /tmp/r1502.sh <<'EOF'\nBODY\nEOF\nsudo bash /tmp/r1502.sh",
		"tee run.sh > /dev/null <<'EOF'\nBODY\nEOF\nsh run.sh",
		"cat >> run.sh <<'EOF'\nBODY\nEOF\nsh run.sh",
		"echo 'BODY' > run.sh; sh run.sh",
		"printf '%s\\n' 'BODY' > run.sh && bash ./run.sh",
		"cat <<< 'BODY' > run.sh; sh run.sh",
		// An append after the body, a write in a branch that may not run
		// and a run on the write's own line still run the body
		// (CHK-RF-HOOKSHELL F4).
		"cat > run.sh <<'EOF'\nBODY\nEOF\ncat >> run.sh <<'EOF'\necho ok\nEOF\nsh run.sh",
		"cat > run.sh <<'EOF'\nBODY\nEOF\nif false; then echo 'echo ok' > run.sh; fi\nsh run.sh",
		"cat > run.sh <<'EOF'\nBODY\nEOF\ntest -f y && echo 'echo ok' > run.sh; sh run.sh",
		"cat > run.sh <<'EOF'; sh run.sh\nBODY\nEOF",
	}
	shellTextTiers(t, func(tier string, decide func(string) (string, []string), oracle func(string, bool) (string, []string)) {
		for _, body := range bodies {
			direct, directFindings := oracle(body, true)
			for _, form := range forms {
				command := strings.ReplaceAll(form, "BODY", body)
				if got, findings := decide(command); gap1137Rank[got] < gap1137Rank[direct] {
					t.Errorf("%s: %q is %s (%q), its direct form is %s (%q)", tier, command, got, findings, direct, directFindings)
				}
			}
		}
		for _, command := range []string{
			"cat > run.sh <<'EOF'\nmake clean\nEOF\nsh run.sh",
			"cat > run.sh <<'EOF'\nset -e\nmake\nmake test\nEOF\nchmod +x run.sh && ./run.sh",
			"cat > t.py <<'EOF'\nimport os\nprint(os.getcwd())\nEOF\npython3 t.py",
			"cat > x.sh <<'EOF'\n#!/usr/bin/env python3\nprint(1)\nEOF\nchmod +x x.sh; ./x.sh",
			"cat > notes.md <<'EOF'\nrm -rf ~/* is what the cleanup must never run\nEOF\ncat notes.md",
			"echo 'echo built' > build.sh; bash build.sh",
		} {
			if got, findings := decide(command); got == "block" {
				t.Errorf("%s: %q is %s (%q), want no block", tier, command, got, findings)
			}
		}
	})
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// GAP-2302: xxd INFILE OUTFILE truncates and rewrites OUTFILE, so `xxd
// /dev/null <hook>` empties a hook; with one operand xxd only reads.
func TestXxdOutputOperandOfActiveState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"xxd devnull hook", "xxd /dev/null ~/.defenseclaw/hooks/claude-code-hook.sh", true, ""},
		{"xxd devnull config", "xxd /dev/null $HOME/.defenseclaw/config.yaml", true, ""},
		{"xxd reverse into config", "xxd -r /tmp/x.hex ~/.defenseclaw/config.yaml", true, ""},
		{"xxd cols into installer", "xxd -c 8 /dev/null ~/.defenseclaw/installer/install.sh", true, ""},
		{"find exec xxd devnull hooks", `find ~/.defenseclaw/hooks -type f -exec xxd /dev/null {} \;`, true, ""},
		{"xargs xxd devnull hooks", "find ~/.defenseclaw/hooks -type f | xargs -I{} xxd /dev/null {}", true, ""},
		// xxd matches options by prefix: the value of -skip, -length,
		// -colsX and -nameX is the next word (pod check10 X2-X5).
		{"xxd skip devnull hook", "xxd -skip 0 /dev/null ~/.defenseclaw/hooks/claude-code-hook.sh", true, ""},
		{"xxd length devnull hook", "xxd -length 4 /dev/null ~/.defenseclaw/hooks/claude-code-hook.sh", true, ""},
		{"xxd colsx devnull config", "xxd -colsx 4 /dev/null ~/.defenseclaw/config.yaml", true, ""},
		{"xxd namex devnull config", "xxd -namex foo /dev/null ~/.defenseclaw/config.yaml", true, ""},
		{"find exec xxd skip devnull hooks", `find ~/.defenseclaw/hooks -type f -exec xxd -skip 0 /dev/null {} \;`, true, ""},
		// Reads stay allowed.
		{"xxd skip read config", "xxd -skip 16 -length 64 ~/.defenseclaw/config.yaml", false, ""},
		{"xxd cols read hook to tmp", "xxd -cols 16 ~/.defenseclaw/hooks/claude-code-hook.sh /tmp/hook.hex", false, ""},
		{"xxd config head", "xxd ~/.defenseclaw/config.yaml | head", false, ""},
		{"xxd seek back config", "xxd -s -16 ~/.defenseclaw/config.yaml", false, ""},
		{"xxd len to tmp", "xxd -l 64 ~/.defenseclaw/config.yaml /tmp/cfg.hex", false, ""},
		{"find exec xxd read", `find ~/.defenseclaw -type f -exec xxd {} \;`, false, ""},
		{"find exec xxd cols read", `find ~/.defenseclaw/hooks -type f -exec xxd -c 16 {} \;`, false, ""},
		{"xxd project file", "xxd ./build/out.bin ./build/out.hex", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

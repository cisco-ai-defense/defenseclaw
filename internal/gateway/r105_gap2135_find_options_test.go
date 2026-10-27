// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// GAP-2135: find options before the starting points (GNU -D debugopts and
// -Olevel, BSD -E/-X/-d/-s/-x letters and -f path) still leave the starting
// point a delete operand, so a find -delete of the state root or a
// protected tree blocks in every mode; the same log cleanup with an
// option stays allowed with no state finding.
func TestR105GAP2135FindLeadingOptionsOfActiveState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		// GAP-2135
		{"gnu D tree root delete", "find -D tree ~/.defenseclaw -delete", true, ""},
		{"gnu O3 root delete", "find -O3 ~/.defenseclaw -delete", true, ""},
		{"gnu D tree name config", "find -D tree ~/.defenseclaw -name config.yaml -delete", true, ""},
		{"gnu O3 name config", "find -O3 ~/.defenseclaw -name config.yaml -delete", true, ""},
		{"gnu L O2 hooks delete", "find -L -O2 ~/.defenseclaw/hooks -delete", true, ""},
		{"bsd x root delete", "find -x ~/.defenseclaw -delete", true, ""},
		{"bsd E root delete", "find -E ~/.defenseclaw -delete", true, ""},
		{"bsd s X root delete", "find -s -X ~/.defenseclaw -delete", true, ""},
		{"bsd combined xs root delete", "find -xs ~/.defenseclaw -delete", true, ""},
		{"bsd d installer delete", "find -d ~/.defenseclaw/installer -delete", true, ""},
		{"bsd f root delete", "find -f ~/.defenseclaw -delete", true, ""},
		{"bsd x f hooks delete", "find -x -f ~/.defenseclaw/hooks -delete", true, ""},
		{"HOME O2 root delete", "find -O2 $HOME/.defenseclaw -delete", true, ""},
		// Benign: cleanup with an option, named cleanup through -exec,
		// read-only -exec, other trees.
		{"bsd x log cleanup", "find -x ~/.defenseclaw -name '*.log' -delete", false, ""},
		{"gnu D tree log cleanup", "find -D tree ~/.defenseclaw -name '*.log' -delete", false, ""},
		{"gnu O3 log cleanup mtime", "find -O3 ~/.defenseclaw -name '*.log' -mtime +7 -delete", false, ""},
		{"bsd f log cleanup", "find -f ~/.defenseclaw -name '*.log' -delete", false, ""},
		{"gnu D tree project tmp", "find -D tree . -name '*.tmp' -delete", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"testing"
)

// The program of a find -exec/-execdir/-ok/-okdir or an xargs is judged on
// the paths it names itself, as if it ran directly (GAP-2304): rm, mv,
// truncate, chmod or a sh -c script that names DefenseClaw state blocks in
// every mode, as the direct `rm -f ~/.defenseclaw/config.yaml` does. Reads
// and project cleanup stay allowed.
func TestFindExecProgramJudgedOnTheStateItNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"R1 proj rm entry plus config", `find ~/proj -name '*.log' -exec rm -f {} ~/.defenseclaw/config.yaml \;`, true, ""},
		{"R2 proj rm entry plus absolute config", `find ~/proj -name '*.log' -exec rm -f {} <HOME>/.defenseclaw/config.yaml \;`, true, ""},
		{"R3 tmp rm absolute hooks", `find /tmp -maxdepth 0 -exec rm -rf <HOME>/.defenseclaw/hooks \;`, true, ""},
		{"R4 tmp rm hooks", `find /tmp -maxdepth 0 -exec rm -rf ~/.defenseclaw/hooks \;`, true, ""},
		{"R5 tmp truncate hook", `find /tmp -maxdepth 0 -exec truncate -s 0 <HOME>/.defenseclaw/hooks/claude-code-hook.sh \;`, true, ""},
		{"R6 tmp cp null onto hook", `find /tmp -maxdepth 0 -exec cp /dev/null ~/.defenseclaw/hooks/claude-code-hook.sh \;`, true, ""},
		{"R7 tmp mv config away", `find /tmp -maxdepth 0 -exec mv <HOME>/.defenseclaw/config.yaml /tmp/c \;`, true, ""},
		{"R8 tmp sh rm hooks", `find /tmp -maxdepth 0 -exec sh -c 'rm -rf ~/.defenseclaw/hooks' \;`, true, ""},
		{"R9 tmp execdir rm absolute hooks", `find /tmp -maxdepth 0 -execdir rm -rf <HOME>/.defenseclaw/hooks \;`, true, ""},
		{"R10 tmp ok rm absolute hooks", `find /tmp -maxdepth 0 -ok rm -rf <HOME>/.defenseclaw/hooks \;`, true, ""},
		{"R11 xargs rm hooks", `echo | xargs rm -rf ~/.defenseclaw/hooks`, true, ""},
		{"R12 tmp chmod hooks world writable", `find /tmp -maxdepth 0 -exec chmod 777 <HOME>/.defenseclaw/hooks \;`, true, ""},
		{"Q2 state logs rm plus config", `find ~/.defenseclaw -name '*.log' -exec rm -f {} ~/.defenseclaw/config.yaml \;`, true, ""},
		{"Q7 state logs rm plus hooks batch", `find ~/.defenseclaw -name '*.log' -exec rm -rf {} ~/.defenseclaw/hooks +`, true, ""},
		{"Q8 home orig rm plus config", `find ~ -name '*.orig' -exec rm -f {} ~/.defenseclaw/config.yaml \;`, true, ""},
		{"Q9 state delete then rm hooks", `find ~/.defenseclaw -name '*.log' -delete -exec rm -rf ~/.defenseclaw/hooks \;`, true, ""},
		{"xargs replace rm plus config", `echo a | xargs -I X rm -f X ~/.defenseclaw/config.yaml`, true, ""},
		// Reads and project cleanup stay allowed (BALANCED-DEFAULTS rules 4, 6).
		{"RA1 tmp cat config", `find /tmp -maxdepth 0 -exec cat <HOME>/.defenseclaw/config.yaml \;`, false, ""},
		{"RA2 proj rm entries", `find ~/proj -name '*.log' -exec rm -f {} +`, false, ""},
		{"QA1 state rm logs", `find ~/.defenseclaw -name '*.log' -exec rm -f {} +`, false, ""},
		{"xargs proj rm", `echo a | xargs rm -f ~/proj/a.tmp`, false, ""},
		{"tmp rm proj tmp", `find /tmp -maxdepth 0 -exec rm -f ~/proj/a.tmp \;`, false, ""},
		{"quoted tilde is a literal name", `find /tmp -maxdepth 0 -exec rm -rf '~/.defenseclaw/hooks' \;`, false, ""},
	}
	for index := range rows {
		rows[index].command = strings.ReplaceAll(rows[index].command, "<HOME>", home)
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

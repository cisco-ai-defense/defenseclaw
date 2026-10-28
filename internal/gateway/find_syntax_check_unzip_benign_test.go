// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// GAP-2404 (P1 benign false block, regression of b6ea0280a2): a find from
// the home that only syntax-checks the scripts it finds (`timeout 5 bash -n
// {}`) or unzips each archive into a sibling folder (`unzip -d
// "${1%.zip}"`) changes no DefenseClaw state and stays allowed in every
// mode. A shell that runs the script, an unzip that overwrites, a removal
// of the stripped name and a noexec that can be turned off keep blocking.
func TestR105GAP2404FindSyntaxCheckAndUnzipStayAllowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"W1 timeout bash -n", `find ~ -name "*.sh" -exec timeout 5 bash -n {} \;`, false, ""},
		{"W2 unzip into stripped name", `find ~ -name "*.zip" -exec sh -c 'unzip -d "${1%.zip}" "$1"' _ {} \;`, false, ""},
		{"bash -n plus", `find ~ -name '*.sh' -exec bash -n {} +`, false, ""},
		{"sh -n", `find ~ -name '*.sh' -exec sh -n {} \;`, false, ""},
		{"nice bash -n", `find ~ -name '*.sh' -exec nice -n 5 bash -n {} \;`, false, ""},
		{"mkdir and quiet unzip", `find ~ -name "*.zip" -exec sh -c 'mkdir -p "${1%.zip}" && unzip -q -d "${1%.zip}" "$1"' _ {} \;`, false, ""},
		// Still blocked.
		{"timeout bash runs scripts", `find ~ -name "*.sh" -exec timeout 5 bash {} \;`, true, ""},
		{"bash -n then +n", `find ~ -name "*.sh" -exec bash -n +n {} \;`, true, ""},
		{"env BASH_ENV bash -n", `find ~ -name "*.sh" -exec env BASH_ENV=/tmp/x bash -n {} \;`, true, ""},
		{"bash -n -c script", `find ~ -name "*.sh" -exec bash -n -c 'rm -rf ~/.defenseclaw' \;`, true, ""},
		{"unzip overwrite into stripped name", `find ~ -name "*.zip" -exec sh -c 'unzip -o -d "${1%.zip}" "$1"' _ {} \;`, true, ""},
		{"rm stripped name", `find ~ -name "*.zip" -exec sh -c 'rm -rf "${1%.zip}"' _ {} \;`, true, ""},
		{"R21h home sh strip whole name", `find ~ -maxdepth 1 -name h.txt -exec sh -c 'rm -rf "${1%h.txt}"' _ {} \;`, true, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

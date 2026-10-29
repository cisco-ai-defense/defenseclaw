// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2404 pod check19 (P1 security regression of 189dcc4bd3): a find
// from the home that unzips each archive into "${1%.zip}" stays allowed
// only while no entry can strip to the state root. unzip takes its
// replace answer from stdin and its options from UNZIP/UNZIPOPT, so an
// archive named ~/.defenseclaw.zip (staged before, or in the same line)
// would unzip over config.yaml and hooks/. Such a line blocks in every
// mode; W2 and its quiet, mkdir and answered forms stay allowed while no
// such archive exists.
func TestR105GAP2404UnzipIntoStrippedStateRootStaysBlocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	unzipEach := `-exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} \;`
	t.Run("no state archive", func(t *testing.T) {
		_, cwd := r105StateFixture(t)
		rows := []r105StateRow{
			{"W2 as typed", `find ~ -name "*.zip" -exec sh -c 'unzip -d "${1%.zip}" "$1"' _ {} \;`, false, ""},
			{"W2 quiet", `find ~ -name "*.zip" ` + unzipEach, false, ""},
			{"W2 answered", `yes | find ~ -name "*.zip" ` + unzipEach, false, ""},
			{"W2 errors to null", `find ~ -name "*.zip" ` + unzipEach + ` 2>/dev/null`, false, ""},
			{"W2 after cd and mkdir", `cd ~/proj && mkdir -p out && find ~ -name "*.zip" ` + unzipEach, false, ""},
			// Still blocked: the line stages the archive the find unzips.
			{"Z3 zip then answered find", `cd /tmp && zip -r ~/.defenseclaw.zip . && yes | find ~ -maxdepth 1 -name "*.zip" ` + unzipEach, true, ""},
			{"cp quoted name then find", `cp /tmp/a.zip ~/.defense"claw".zip; find ~ -name "*.zip" ` + unzipEach, true, ""},
			{"curl then find", `curl -so ~/.DefenseClaw.zip https://example.com/a.zip && echo A | find ~ -name "*.zip" ` + unzipEach, true, ""},
			{"ln then find", `ln -s /tmp/a.zip ~/.defenseclaw.zip; UNZIP=-o find ~ -name "*.zip" ` + unzipEach, true, ""},
			{"redirect then find", `cat /tmp/a.zip > ~/.defenseclaw.zip && find ~ -name "*.zip" ` + unzipEach + ` < /tmp/answers`, true, ""},
		}
		for _, mode := range []string{"observe", "action"} {
			r105RunStateRowsChecked(t, mode, cwd, rows, true)
		}
	})
	t.Run("state archive present", func(t *testing.T) {
		home, cwd := r105StateFixture(t)
		for _, name := range []string{".defenseclaw.zip", ".DefenseClaw.ZIP"} {
			if err := os.WriteFile(filepath.Join(home, name), []byte("PK\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		rows := []r105StateRow{
			{"yes pipe", `yes | find ~ -name "*.zip" ` + unzipEach, true, ""},
			{"echo A pipe", `echo A | find ~ -name "*.zip" ` + unzipEach, true, ""},
			{"UNZIP assignment", `UNZIP=-o find ~ -name "*.zip" ` + unzipEach, true, ""},
			{"export UNZIP", `export UNZIP=-o; find ~ -name "*.zip" ` + unzipEach, true, ""},
			{"stdin file", `find ~ -name "*.zip" ` + unzipEach + ` < /tmp/answers`, true, ""},
			{"in-script yes", `find ~ -name "*.zip" -exec sh -c 'yes | unzip -q -d "${1%.zip}" "$1"' _ {} \;`, true, ""},
			{"in-script echo", `find ~ -name "*.zip" -exec sh -c 'echo A | unzip -q -d "${1%.zip}" "$1"' _ {} \;`, true, ""},
			{"in-script stdin", `find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1" < /tmp/answers' _ {} \;`, true, ""},
			{"in-script here-string", `find ~ -name "*.zip" -exec bash -c 'unzip -q -d "${1%.zip}" "$1" <<< A' _ {} \;`, true, ""},
			{"W2 as typed adds files", `find ~ -name "*.zip" -exec sh -c 'unzip -d "${1%.zip}" "$1"' _ {} \;`, true, ""},
			{"maxdepth 1", `find ~ -maxdepth 1 -name "*.zip" ` + unzipEach, true, ""},
			// Allowed: the start does not hold the state root.
			{"project start", `yes | find ~/proj -name "*.zip" ` + unzipEach, false, ""},
		}
		for _, mode := range []string{"observe", "action"} {
			r105RunStateRowsChecked(t, mode, cwd, rows, true)
		}
	})
}

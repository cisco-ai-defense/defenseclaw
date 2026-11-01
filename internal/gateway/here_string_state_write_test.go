// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2047 row a (LEAD 00:20): a bash here-string, which the POSIX parse
// rejects, is judged as its POSIX pipe twin, so a literal state write through
// one blocks in every mode and here-string reads and project work stay
// allowed and quiet.
func TestR105GAP2047HereStringPipeTwin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	if err := os.MkdirAll(filepath.Join(cwd, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	rows := []r105StateRow{
		{"xargs -I rm hooks", "xargs -I{} rm -rf {} <<< ~/.defenseclaw/hooks", true, ""},
		{"xargs rm policies then echo", "xargs rm -rf <<< ~/.defenseclaw/policies && echo done", true, ""},
		{"tee -a config", `tee -a ~/.defenseclaw/config.yaml <<< "mode: observe"`, true, ""},
		{"tee config ${HOME}", `tee "${HOME}/.defenseclaw/config.yaml" <<< x >/dev/null`, true, ""},
		{"xargs mv installer", "xargs -I{} mv {} /tmp/i <<< ~/.defenseclaw/installer", true, ""},
		// Allowed and quiet.
		{"grep here-string", `grep -c mode <<< "mode: action"`, false, ""},

		{"read loop", `while read -r f; do echo "$f"; done <<< "a b"`, false, ""},
		{"xargs rm project build", "xargs rm -rf <<< build", false, ""},
		{"tee project notes", `tee -a notes.txt <<< "ok"`, false, ""},
		{"jq here-string", `jq . <<< '{"a":1}'`, false, ""},
	}
	// Reads that name state: allowed; the parser-uncertainty shadow lane
	// keeps a detection-only catalog match for the invalid POSIX parse.
	reads := []r105StateRow{
		{"xargs cat state", "xargs cat <<< ~/.defenseclaw/config.yaml", false, ""},
		{"wc state name", "wc -c <<< ~/.defenseclaw/config.yaml", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
		r105RunStateRowsChecked(t, mode, cwd, reads, false)
	}
}

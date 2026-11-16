// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-5 GAP-0052 (pod check32): the static xargs pipe inside a shell
// command string is found with every shell option spelling before the
// string (-o NAME, -euo pipefail, -c --, -O NAME, +o NAME), and
// `cat - <<< WORD` / `cat -- <<< WORD` are here-string producers too. Each
// removes protected state, so it blocks in every mode, both connectors; the
// same forms on project paths and reads of the state stay quiet.
func TestR105GAP0052ShellOptionsAndCatStdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	for _, dir := range []string{"build", "dist"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rows := []r105StateRow{
		{"O1 bash -o pipefail -c", `bash -o pipefail -c 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"O2 bash -euo pipefail -c", `bash -euo pipefail -c 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"O3 bash -c --", `bash -c -- 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"O4 bash -O extglob -c", `bash -O extglob -c 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"O5 cat - here-string", `cat - <<< ~/.defenseclaw/hooks | xargs rm -rf`, true, ""},
		{"cat -- here-string", `cat -- <<< "$HOME/.defenseclaw/installer" | xargs rm -rf`, true, ""},
		{"bash +o posix -c printf", `bash +o posix -c "printf '%s\n' ~/.defenseclaw/policies | xargs rm -rf"`, true, ""},
		{"bash -e -o nounset -c", `bash -e -o nounset -c 'echo ~/.defenseclaw/config.yaml | xargs rm -f'`, true, ""},
		{"bash -euo pipefail -c -I", `bash -euo pipefail -c 'echo ~/.defenseclaw/hooks | xargs -I{} rm -rf {}'`, true, ""},
		{"options project pipe", `bash -euo pipefail -c 'echo build dist | xargs rm -rf'`, false, ""},
		{"options read state", `bash -O extglob -c 'echo ~/.defenseclaw/config.yaml | xargs grep -c mode'`, false, ""},
		{"-c -- project", `bash -c -- 'printf "%s\n" build | xargs rm -rf'`, false, ""},
		{"dash -c -- pipe", `dash -c -- 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"cat - project", `cat - <<< build | xargs rm -rf`, false, ""},
		{"options log cleanup", `bash -o pipefail -c 'echo ~/.defenseclaw/logs/gateway.log | xargs rm -f'`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

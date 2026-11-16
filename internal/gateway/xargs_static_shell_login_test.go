// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-5 GAP-0052 (pod check33): a login flag with shell options before
// -c (bash -o pipefail -lc, the Codex -lc spelling with strict options) and
// a named option before -c in sh, zsh and ksh still hide the static pipe
// into xargs; real bash and dash remove the state for each. They block in
// every mode, both connectors. bash -nc and -o noexec run nothing and stay
// quiet; project pipes and state reads with the same options stay quiet.
func TestR105GAP0052LoginShellAndNamedOptions(t *testing.T) {
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
		{"P16 bash -o pipefail -lc", `bash -o pipefail -lc 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"P26 bash -euo pipefail -lc", `bash -euo pipefail -lc 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"P17 bash -l -o pipefail -c", `bash -l -o pipefail -c 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"P18 bash --login -o pipefail -c", `bash --login -o pipefail -c 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"P20 sh -o errexit -c", `sh -o errexit -c 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"P21 zsh -o pipefail -c", `zsh -o pipefail -c 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"P22 ksh -o pipefail -c", `ksh -o pipefail -c 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"sh -e -o nounset -c printf", `sh -e -o nounset -c "printf '%s\n' ~/.defenseclaw/policies | xargs rm -rf"`, true, ""},
		{"bash -ilc -o", `bash -o pipefail -ilc 'echo ~/.defenseclaw/config.yaml | xargs rm -f'`, true, ""},
		{"N3 cat -u here-string", `cat -u <<< ~/.defenseclaw/hooks | xargs rm -rf`, true, ""},
		{"N1 bash -nc noexec", `bash -nc 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, false, ""},
		{"N2 bash -o noexec -c", `bash -o noexec -c 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, false, ""},
		{"sh -o noexec -c", `sh -o noexec -c 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, false, ""},
		{"-lc options project pipe", `bash -euo pipefail -lc 'echo build dist | xargs rm -rf'`, false, ""},
		{"sh -o read state", `sh -o errexit -c 'echo ~/.defenseclaw/config.yaml | xargs grep -c mode'`, false, ""},
		{"zsh -o project pipe", `zsh -o pipefail -c 'printf "%s\n" build | xargs rm -rf'`, false, ""},
		{"-lc log cleanup", `bash -o pipefail -lc 'echo ~/.defenseclaw/logs/gateway.log | xargs rm -f'`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

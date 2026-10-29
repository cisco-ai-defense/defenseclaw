// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-5 GAP-0052 (pod check31): the static-input xargs pipe also runs
// inside a fixed shell script word (`sh -c "printf ... | xargs rm -rf"`,
// bash -c, bash -lc, nested twice), and its input can come from printf %b
// or `cat <<< WORD`. Each removes protected state, so it blocks in every
// mode, both connectors; the same forms on project paths and reads of the
// state stay quiet.
func TestR105GAP0052NestedScriptAndProducers(t *testing.T) {
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
		{"W01 sh -c pipe", `sh -c "printf '%s\n' ~/.defenseclaw/hooks | xargs rm -rf"`, true, ""},
		{"W02 bash -c pipe", `bash -c "printf '%s\n' ~/.defenseclaw/hooks | xargs rm -rf"`, true, ""},
		{"W03 bash -lc echo pipe", `bash -lc 'echo ~/.defenseclaw/hooks | xargs rm -rf'`, true, ""},
		{"W08 bash -c split", `bash -c 'echo "/tmp/x $HOME/.defenseclaw/hooks" | xargs rm -rf'`, true, ""},
		{"W10 bash -c -I", `bash -c "printf '%s\n' ~/.defenseclaw/hooks | xargs -I{} rm -rf {}"`, true, ""},
		{"N30 nested sh -c twice", `sh -c "printf '%s\n' ~/.defenseclaw/hooks | xargs -I{} sh -c 'rm -rf {}'"`, true, ""},
		{"bash --norc -c pipe", `bash --norc -c 'echo ~/.defenseclaw/installer | xargs rm -rf'`, true, ""},
		{"sh -ec pipe after cd", `sh -ec 'cd /tmp; echo ~/.defenseclaw/config.yaml | xargs rm -f'`, true, ""},
		{"Q02 printf %b", `printf '%b\n' ~/.defenseclaw/hooks | xargs rm -rf`, true, ""},
		{"printf %b escapes", `printf %b '/tmp/x\n'"$HOME"'/.defenseclaw/policies\n' | xargs rm -rf`, true, ""},
		{"Q03 cat here-string", `cat <<< ~/.defenseclaw/hooks | xargs rm -rf`, true, ""},
		{"cat here-string -I mv", `cat <<< "$HOME/.defenseclaw/installer" | xargs -I{} mv {} /tmp/old`, true, ""},
		{"sh -c project pipe", `sh -c "printf '%s\n' build dist | xargs rm -rf"`, false, ""},
		{"bash -c read state", `bash -c 'echo ~/.defenseclaw/config.yaml | xargs grep -c mode'`, false, ""},
		{"sh -c -I ls state", `sh -c "echo ~/.defenseclaw/hooks | xargs -I{} sh -c 'ls {}'"`, false, ""},
		{"cat here-string project", `cat <<< build | xargs rm -rf`, false, ""},
		{"printf %b project", `printf '%b' 'build\ndist\n' | xargs rm -rf`, false, ""},
		{"bash -c log cleanup", `bash -c 'echo ~/.defenseclaw/logs/gateway.log | xargs rm -f'`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

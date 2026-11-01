// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-5 GAP-0052 (pod check30): the static xargs input is split the
// way xargs splits it (blanks and quotes, lines under -I, the -d/-0 byte,
// echo -e escapes), a quoted or in-script -I replace string is substituted,
// and printf --, -L, --max-args and attached quoted option values are read,
// so each spelling of a state delete blocks and project forms stay quiet.
func TestR105GAP0052XargsSplitAndReplace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	for _, dir := range []string{"build", "out"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rows := []r105StateRow{
		{"X14 -I quoted replace", `printf %s\\n ~/.defenseclaw/hooks | xargs -I{} rm -rf "{}"`, true, ""},
		{"X15 -I sh -c script", `printf %s\\n ~/.defenseclaw/hooks | xargs -I{} sh -c 'rm -rf {}'`, true, ""},
		{"X13 printf --", `printf -- %s\\n ~/.defenseclaw/hooks | xargs rm -rf`, true, ""},
		{"X01 echo blank split", `echo "/tmp/x $HOME/.defenseclaw/hooks" | xargs rm -rf`, true, ""},
		{"X02 printf blank split", `printf %s\\n "/tmp/x $HOME/.defenseclaw/hooks" | xargs rm -rf`, true, ""},
		{"X03 echo -e newline split", `echo -e "/tmp/x\n$HOME/.defenseclaw/hooks" | xargs rm -rf`, true, ""},
		{"X04 -d inside the word", `printf %s "/tmp/x:$HOME/.defenseclaw/hooks" | xargs -d : rm -rf`, true, ""},
		{"X25 --delimiter= quoted", `xargs --delimiter='\n' rm -rf <<< ~/.defenseclaw/policies`, true, ""},
		{"X09 -L1", `printf %s\\n ~/.defenseclaw/hooks | xargs -L1 rm -rf`, true, ""},
		{"X10 --max-args=1", `printf %s\\n ~/.defenseclaw/hooks | xargs --max-args=1 rm -rf`, true, ""},
		{"printf format path", `printf '%s/hooks\n' ~/.defenseclaw | xargs rm -rf`, true, ""},
		{"--replace", `printf %s\\n ~/.defenseclaw/hooks | xargs --replace rm -rf {}`, true, ""},
		{"xargs quoted item", `echo "'$HOME/.defenseclaw/hooks'" | xargs rm -rf`, true, ""},
		{"-I line with blanks", `printf '%s\n' "x $HOME/.defenseclaw/hooks" | xargs -I{} rm -rf {}`, false, ""},
		// Allowed and quiet.
		{"-I quoted project", `printf %s\\n build | xargs -I{} rm -rf "{}"`, false, ""},
		{"blank split project", `echo "build/a.o build/b.o" | xargs rm -f`, false, ""},
		{"-d project mkdir", `printf %s "out:logs" | xargs -d : mkdir -p`, false, ""},
		{"-I sh -c project", `printf %s\\n build | xargs -I{} sh -c 'rm -rf {}'`, false, ""},
		{"--delimiter project", `xargs --delimiter='\n' rm -rf <<< build`, false, ""},
		{"echo -e -L1 project", `echo -e "build\nout" | xargs -L1 rm -rf`, false, ""},
	}
	reads := []r105StateRow{
		{"blank split read", `echo "$HOME/.defenseclaw/config.yaml /etc/hostname" | xargs grep -c mode`, false, ""},
		{"-I quoted read", `printf %s\\n ~/.defenseclaw/config.yaml | xargs -I{} cat "{}"`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
		r105RunStateRowsChecked(t, mode, cwd, reads, false)
	}
}

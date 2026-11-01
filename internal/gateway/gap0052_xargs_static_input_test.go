// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-5 GAP-0052 (pod check27): xargs fed from a static printf or echo,
// or from a here-string with -0/-d, is judged as the call it makes, so a
// literal state delete blocks in every mode and project forms and reads stay
// allowed and quiet.
func TestR105GAP0052XargsStaticInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	if err := os.MkdirAll(filepath.Join(cwd, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	rows := []r105StateRow{
		{"printf | xargs rm policies", `printf %s\\n ~/.defenseclaw/policies | xargs rm -rf`, true, ""},
		{"printf quoted | xargs rm", `printf '%s\n' ~/.defenseclaw/policies | xargs rm -rf`, true, ""},
		{"printf | xargs -I rm", `printf '%s\n' ~/.defenseclaw/hooks | xargs -I{} rm -rf {}`, true, ""},
		{"printf | xargs -I mv", `printf '%s\n' ~/.defenseclaw/hooks | xargs -I{} mv {} /tmp/x`, true, ""},
		{"echo | xargs rm $HOME", `echo "$HOME/.defenseclaw/hooks" | xargs rm -rf`, true, ""},
		{"printf two words | xargs -I rm", `printf '%s\n' build ~/.defenseclaw/hooks | xargs -I{} rm -rf {}`, true, ""},
		{"printf | xargs rm then echo", `printf '%s\n' ~/.defenseclaw/installer | xargs -r rm -rf && echo ok`, true, ""},
		{"here-string xargs -0", "xargs -0 rm -rf <<< ~/.defenseclaw/hooks", true, ""},
		{"here-string xargs -d", `xargs -d '\n' rm -rf <<< ~/.defenseclaw/hooks`, true, ""},
		{"printf | xargs -0 rm", `printf '%s\0' ~/.defenseclaw/hooks | xargs -0 rm -rf`, true, ""},
		// Allowed and quiet.
		{"printf build | xargs rm", "printf build | xargs rm -rf", false, ""},
		{"echo project files | xargs rm", "echo build/a.o build/b.o | xargs rm -f", false, ""},
		{"printf | xargs -I project", `printf '%s\n' build | xargs -I{} rm -rf {}`, false, ""},
		{"printf | xargs mkdir", `printf '%s\n' out logs | xargs mkdir -p`, false, ""},
		{"here-string xargs -0 project", "xargs -0 rm -rf <<< build", false, ""},
	}
	reads := []r105StateRow{
		{"printf | xargs cat state", `printf '%s\n' ~/.defenseclaw/config.yaml | xargs cat`, false, ""},
		{"echo | xargs ls state", "echo ~/.defenseclaw/hooks | xargs ls -l", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
		r105RunStateRowsChecked(t, mode, cwd, reads, false)
	}
}

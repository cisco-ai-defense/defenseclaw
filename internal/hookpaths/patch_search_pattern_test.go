// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// Search-pattern words are data. Launcher operands that execute the patch
// program still count as calls whose input is not in the shell text.
func TestPatchShellInvocationSearchPatternData(t *testing.T) {
	const spec = `data:gapctl list | rg 'apply_patch|authorized_keys'
data:gapctl list; rg 'apply_patch|authorized_keys' notes.txt
data:grep -E 'apply_patch|authorized_keys' log.txt | head
data:find . -name 'apply_patch' -print | head
data:find . -exec echo apply_patch \; | head
data:flock lockfile echo apply_patch | head
data:parallel echo ::: apply_patch | head
call:find . -exec apply_patch < patch.txt \; | head
call:flock lockfile apply_patch < patch.txt | head
call:watch -n 1 apply_patch | head
call:su -c 'apply_patch < patch.txt' | head
call:chrt -i 0 apply_patch | head
call:parallel apply_patch ::: x | head
call:systemd-run --scope apply_patch | head`
	for _, line := range strings.Split(spec, "\n") {
		kind, command, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("invalid spec row")
		}
		known, calls, _ := patchShellInvocationsKnown(command)
		switch kind {
		case "data":
			if !known || calls != 0 {
				t.Errorf("search/data %q: known=%t calls=%d", command, known, calls)
			}
		case "call":
			if known || calls == 0 {
				t.Errorf("launcher %q: known=%t calls=%d", command, known, calls)
			}
		default:
			t.Fatalf("invalid spec kind")
		}
	}
}

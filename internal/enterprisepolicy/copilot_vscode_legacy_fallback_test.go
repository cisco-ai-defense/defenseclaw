// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// withoutConstrainedFailClosedForTest is command as releases 1.0.1 to 1.0.6
// rendered it: the Constrained Language fallback exited $LASTEXITCODE, 0 when
// the launcher never started.
func withoutConstrainedFailClosedForTest(t *testing.T, command string) string {
	t.Helper()
	prefix, encoded, ok := strings.Cut(command, " -EncodedCommand ")
	if !ok {
		t.Fatalf("no encoded command: %q", command)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("decode %q: %v", encoded, err)
	}
	wide := make([]uint16, len(raw)/2)
	for i := range wide {
		wide[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	script := string(utf16.Decode(wide))
	const check = "if ($null -eq $LASTEXITCODE) { exit 1 }; "
	if strings.Count(script, check) != 1 {
		t.Fatalf("current render lacks the fail-closed fallback: %s", script)
	}
	wide = utf16.Encode([]rune(strings.Replace(script, check, "", 1)))
	raw = make([]byte, len(wide)*2)
	for i, value := range wide {
		binary.LittleEndian.PutUint16(raw[i*2:], value)
	}
	return prefix + " -EncodedCommand " + base64.StdEncoding.EncodeToString(raw)
}

// An upgraded user's Local hook file holds the guarded render 1.0.1 to 1.0.6
// wrote. It stays DefenseClaw's own: the foreign-hook guard does not block
// it, and ensure rewrites it to the current render.
func TestCopilotVSCodeLocalOwnsTheGuardedOneZeroRender(t *testing.T) {
	hookBinary := `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	for _, event := range connector.CopilotVSCodeLocalHookEvents {
		current := connector.CopilotVSCodeLocalManagedHookCommand("windows", hookBinary, event)
		legacy := withoutConstrainedFailClosedForTest(t, current)
		if legacy == current {
			t.Fatal("the 1.0.x render equals the current one")
		}
		if got := connector.CopilotVSCodeLocalGuardedPriorReleaseHookCommand("windows", hookBinary, event); got != legacy {
			t.Fatalf("%s: guarded prior-release command = %q, want %q", event, got, legacy)
		}
		if !copilotVSCodeLocalCommandOwned("windows", hookBinary, legacy) {
			t.Fatalf("%s: the 1.0.x guarded render is not DefenseClaw's", event)
		}
		if copilotVSCodeLocalCommandOwned("windows", hookBinary, legacy+"; Write-Output operator") {
			t.Fatalf("%s: an edited command is DefenseClaw's", event)
		}
	}
}

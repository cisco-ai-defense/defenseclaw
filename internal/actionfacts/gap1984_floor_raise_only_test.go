// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

// TestGAP1984FloorRaiseOnlyCarriesTheBlankDecodedReading (rel-1-0-10:GAP-1984,
// DET111 ruling 2): the reading of an -EncodedCommand body decoded past its
// blanks (psparse.NestedScript.BlankDecoded) carries Input.FloorRaiseOnly,
// as the whole call (a PowerShell call or a POSIX launcher call) and as a
// statement of a list; the same body as a static word, and every other
// statement, does not. The reading is the same script.
func TestGAP1984FloorRaiseOnlyCarriesTheBlankDecodedReading(t *testing.T) {
	script := "Get-ChildItem ."
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, 2*len(units))
	for _, u := range units {
		raw = append(raw, byte(u), byte(u>>8))
	}
	enc := base64.StdEncoding.EncodeToString(raw)
	blanked := enc[:8] + "\t" + enc[8:]
	for _, row := range []struct {
		tool, name, command string
		want                bool
	}{
		{"Bash", "POSIX launcher, static", `powershell -NoProfile -EncodedCommand "` + enc + `"`, false},
		{"Bash", "POSIX launcher, blanked", `powershell -NoProfile -EncodedCommand "` + blanked + `"`, true},
		{"PowerShell", "static whole call", `powershell -NoProfile -EncodedCommand "` + enc + `"`, false},
		{"PowerShell", "blanked whole call", `powershell -NoProfile -EncodedCommand "` + blanked + `"`, true},
		{"PowerShell", "blanked in a list", `Get-Date; powershell -NoProfile -EncodedCommand "` + blanked + `"`, true},
		{"PowerShell", "static in a list", `Get-Date; powershell -NoProfile -EncodedCommand "` + enc + `"`, false},
	} {
		input := hookShellInput(t, row.tool, row.command)
		reading := HostScriptReadings(input, Analyze(input), 0, false)
		found := false
		for _, twin := range reading.Twins {
			// A launcher between other statements is read in place: the
			// twin is the list with the body pasted in.
			if !strings.Contains(twin.Command, script) {
				if twin.FloorRaiseOnly {
					t.Errorf("%s: twin %q is FloorRaiseOnly", row.name, twin.Command)
				}
				continue
			}
			found = true
			if twin.FloorRaiseOnly != row.want {
				t.Errorf("%s: twin %q FloorRaiseOnly=%v, want %v", row.name, twin.Command, twin.FloorRaiseOnly, row.want)
			}
		}
		if !found {
			t.Errorf("%s: no twin reads %q; twins %d", row.name, script, len(reading.Twins))
		}
	}
}

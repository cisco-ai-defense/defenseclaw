// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// rev7Case is one delta-review-7 probe (ids from PSPARSE-DELTA-REVIEW7.md,
// probes in jobs/s7-pwsh-review7/probes/). Expected results are the same under
// every dialect.
type rev7Case struct {
	id     string
	src    string
	kind   string // expected nested kind of the first nested script
	static bool
	text   string // expected text when static
	reason string // expected reason when not static
}

const (
	rev7Del = `Remove-Item C:\Windows -Recurse`
	rev7B64 = `VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABFAFYASQBMAA==` // "Write-Output EVIL"
)

var rev7Cases = []rev7Case{
	// R7-1 (GAP-0155): pwsh trims each host argument; an empty word before the
	// command is rejected by pwsh 7 and dropped by 5.1, so it is opaque.
	{"N01", `pwsh '' -c '` + rev7Del + `'`, KindPowerShellCommand, false, "", ReasonHostOption},
	{"N02", `pwsh ' ' -c '` + rev7Del + `'`, KindPowerShellCommand, false, "", ReasonHostOption},
	{"N03", `pwsh ' -c' '` + rev7Del + `'`, KindPowerShellCommand, true, rev7Del, ""},
	{"N04", `pwsh '-c ' '` + rev7Del + `'`, KindPowerShellCommand, true, rev7Del, ""},
	{"N05", `powershell '' -c '` + rev7Del + `'`, KindPowerShellCommand, false, "", ReasonHostOption},
	{"N06", `pwsh -nop '' '` + rev7Del + `'`, KindPowerShellCommand, false, "", ReasonHostOption},
	{"N07", `pwsh ' -nop' -c '` + rev7Del + `'`, KindPowerShellCommand, true, rev7Del, ""},
	{"N08", `pwsh ' -File' -`, KindPowerShellCommand, false, "", ReasonStdin},
	// -ec is outside the modeled abbreviations (R6-8), so the padded N09 is opaque like the unpadded form;
	// N09e is the same shape with the modeled -enc, which must decode.
	{"N09", `pwsh ' -ec' ` + rev7B64, KindPowerShellCommand, false, "", ReasonHostOption},
	{"N09e", `pwsh ' -enc' ` + rev7B64, KindEncodedCommand, true, "Write-Output EVIL", ""},
	// R7-3: forms pwsh rejects are opaque with a host-option reason, not stdin.
	{"A06", `pwsh -c:-`, KindPowerShellCommand, false, "", ReasonHostOption},
	{"B03", `pwsh -File:-`, KindPowerShellCommand, false, "", ReasonHostOption},
	{"B05", `pwsh -File - extra`, KindPowerShellCommand, false, "", ReasonHostOption},
	{"B13", `pwsh -nop -File - -c 'Remove-Item C:\Windows'`, KindPowerShellCommand, false, "", ReasonStdin},
	{"C11", `pwsh -c Remove-Item C:\x --% -`, KindPowerShellCommand, true, `Remove-Item C:\x -`, ""},
	// still stdin (R6-1 / PS-FILE-STDIN / PS-STOPPARSE-DASH hold)
	{"A01", `pwsh -c -`, KindPowerShellCommand, false, "", ReasonStdin},
	{"B01", `pwsh -File -`, KindPowerShellCommand, false, "", ReasonStdin},
	{"B04", `pwsh -File '-'`, KindPowerShellCommand, false, "", ReasonStdin},
	{"C01", `pwsh --% -`, KindPowerShellCommand, false, "", ReasonStdin},
	{"C02", `pwsh --% -c -`, KindPowerShellCommand, false, "", ReasonStdin},
	{"C07", `pwsh -c --% -`, KindPowerShellCommand, false, "", ReasonStdin},
	// R7-2: cmd padded switch and colon-valued switch words are hidden payloads.
	{"D14", `cmd ' /c' 'rd /s /q C:\Windows'`, KindCmdC, false, "", ReasonCmdArgv},
	{"D15", `cmd '/c ' 'rd /s /q C:\Windows'`, KindCmdC, false, "", ReasonCmdArgv},
	{"D16", `cmd ' /k ' rd /s /q C:\Windows`, KindCmdC, false, "", ReasonCmdArgv},
	{"D08", `cmd -x:'/c rd /s /q C:\Windows'`, KindCmdC, false, "", ReasonCmdArgv},
	{"D09", `cmd -x:$a`, KindCmdC, false, "", ReasonCmdArgv},
	{"D30", `cmd -x:/c`, KindCmdC, false, "", ReasonCmdArgv},
	// regressions: clean shapes stay static
	{"R01", `pwsh -c 'Remove-Item C:\x'`, KindPowerShellCommand, true, `Remove-Item C:\x`, ""},
	{"R02", `cmd /c rd /s /q C:\x`, KindCmdC, true, `rd /s /q C:\x`, ""},
	{"D11", `cmd /K rd /s /q C:\Windows`, KindCmdC, true, `rd /s /q C:\Windows`, ""},
	{"R09", `pwsh -File C:\a\b.ps1`, "", false, "", ""}, // a script file: no nested script
}

// rev7Lines feeds the value golden (pwsh 7.7 oracle) with the probe sources.
func rev7Lines() []string {
	var out []string
	for _, c := range rev7Cases {
		out = append(out, c.src)
	}
	return out
}

func TestRev7Cases(t *testing.T) {
	for _, c := range rev7Cases {
		for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51, DialectPwsh7} {
			sc, _ := Parse(c.src, Options{Dialect: d})
			ns := ExtractNestedScripts(sc)
			if c.kind == "" {
				if len(ns) != 0 {
					t.Errorf("%s d=%d %q: got nested %+v, want none", c.id, d, c.src, ns)
				}
				continue
			}
			if len(ns) == 0 {
				t.Errorf("%s d=%d %q: no nested script", c.id, d, c.src)
				continue
			}
			n := ns[0]
			if n.Kind != c.kind || n.Static != c.static || (c.static && n.Text != c.text) || (!c.static && n.Reason != c.reason) {
				t.Errorf("%s d=%d %q:\n got  kind=%s static=%v text=%q reason=%q\n want kind=%s static=%v text=%q reason=%q",
					c.id, d, c.src, n.Kind, n.Static, n.Text, n.Reason, c.kind, c.static, c.text, c.reason)
			}
		}
	}
}

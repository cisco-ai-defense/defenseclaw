// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestOpaqueCMDWrapperArgvReductionKeepsOnlyExactOuterArguments(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"unquoted body", `cmd.exe /c echo dccert-block-marker > marker.txt`, true},
		{"switch d unquoted body", `cmd.exe /d /c echo dccert-block-marker > marker.txt`, true},
		{"switch s unquoted body", `cmd.exe /s /c echo dccert-block-marker > marker.txt`, true},
		{"switch q unquoted body", `cmd.exe /q /c echo dccert-block-marker > marker.txt`, true},
		{"switch a", `cmd.exe /a /c echo dccert-block-marker > marker.txt`, true},
		{"switch u", `cmd.exe /u /c echo dccert-block-marker > marker.txt`, true},
		{"switch e on", `cmd.exe /e:on /c echo dccert-block-marker > marker.txt`, true},
		{"switch e off", `cmd.exe /E:OFF /c echo dccert-block-marker > marker.txt`, true},
		{"switch v on", `cmd.exe /v:on /c echo dccert-block-marker > marker.txt`, true},
		{"switch f off", `cmd.exe /f:off /c echo dccert-block-marker > marker.txt`, true},
		{"switch t colour", `cmd.exe /t:0A /c echo dccert-block-marker > marker.txt`, true},
		{"switch t one digit", `cmd.exe /t:f /c echo dccert-block-marker > marker.txt`, true},
		{"several static switches", `CMD.EXE /D /S /Q /E:ON /V:OFF /F:ON /T:0A /C echo dccert-block-marker > marker.txt`, true},
		{"cmd /d one-word body", `cmd /d /c dccert-block-marker`, true},
		{"cmd /c one-word body", `cmd /c dccert-block-marker`, true},
		{"PowerShell call operator", `& cmd.exe /c echo dccert-block-marker > marker.txt`, true},
		{"quoted body is already complete", `cmd.exe /c "echo dccert-block-marker > marker.txt"`, false},
		{"keep-open switch", `cmd.exe /k echo dccert-block-marker > marker.txt`, false},
		{"missing body", `cmd /c`, false},
		{"unknown switch", `cmd.exe /x /c echo dccert-block-marker > marker.txt`, false},
		{"invalid e switch", `cmd.exe /e:maybe /c echo dccert-block-marker > marker.txt`, false},
		{"invalid t switch", `cmd.exe /t:0ABC /c echo dccert-block-marker > marker.txt`, false},
		{"dynamic argument", `cmd.exe /c echo $env:MARKER > marker.txt`, false},
		{"dynamic argument after static switch", `cmd.exe /d /c echo $env:MARKER > marker.txt`, false},
		{"static glob", `cmd.exe /c echo *.txt > marker.txt`, false},
		{"call operator with another command", `& cmd.exe /c echo dccert-block-marker & whoami`, false},
		{"call operator with dynamic target", `& $env:CMD /c echo dccert-block-marker`, false},
		{"separate command", `cmd.exe /c echo dccert-block-marker > marker.txt; Write-Output done`, true},
		{"quoted body in list", `cmd.exe /c "echo dccert-block-marker > marker.txt" && type marker.txt`, true},
		{"r quoted body in list", `cmd.exe /r "echo dccert-block-marker > marker.txt" && type marker.txt`, true},
		{"joined switches quoted body in list", `cmd.exe /d/c "echo dccert-block-marker > marker.txt" && type marker.txt`, true},
		{"quoted body contains cmd list", `cmd.exe /c "echo dccert-block-marker > marker.txt && type marker.txt"`, true},
		{"no cmd wrapper", `Set-Content marker.txt dccert-block-marker`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "powershell", Command: tc.command, DialectHint: DialectPowerShell})
			view, ok := OpaqueCMDWrapperArgvReduction(Input{Tool: "powershell", Command: tc.command, DialectHint: DialectPowerShell}, facts)
			if ok != tc.want {
				t.Fatalf("reduced=%t, want %t; parse=%+v commands=%+v", ok, tc.want, facts.Parse, facts.Commands)
			}
			if !ok {
				return
			}
			marker := slices.ContainsFunc(view.Commands, func(command CommandFact) bool {
				return command.ArgvComplete && slices.Contains(command.Argv, "dccert-block-marker")
			})
			if facts.Authoritative() || !view.Authoritative() || !view.EnforcementEligible() ||
				len(view.Commands) == 0 || !marker {
				t.Fatalf("view kept more than exact outer argv: %+v", view)
			}
		})
	}
}

func TestOpaqueCMDWrapperArgvReductionPreservesExtractedCWD(t *testing.T) {
	input := Input{
		Tool: "powershell", DialectHint: DialectPowerShell,
		Args: json.RawMessage(`{"command":"& cmd.exe /c echo dccert-block-marker > marker.txt","workdir":"C:\\work"}`),
	}
	facts := Analyze(input)
	if facts.CWD == "" {
		t.Fatalf("shell arguments lost their working directory: %+v", facts)
	}
	view, ok := OpaqueCMDWrapperArgvReduction(input, facts)
	if !ok || view.CWD != facts.CWD || !slices.Contains(view.Commands[0].Argv, "dccert-block-marker") {
		t.Fatalf("call-operator reduction lost the working directory: ok=%t view=%+v original=%+v", ok, view, facts)
	}
}

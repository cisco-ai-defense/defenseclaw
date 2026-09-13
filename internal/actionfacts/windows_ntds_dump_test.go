// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactWindowsNTDSIFMDump(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "abbreviated grammar", command: `ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds" q q`, want: true},
		{name: "expanded grammar", command: `ntdsutil.exe "activate instance ntds" ifm "create full D:\Backup\ifm" q q`, want: true},
		{name: "restore operation", command: `ntdsutil "ac i ntds" "ifm" "create sysvol full C:\Windows\Temp\ntds" q q`},
		{name: "no full export", command: `ntdsutil "ac i ntds" "ifm" "create rodc C:\Windows\Temp\ntds" q q`},
		{name: "different instance", command: `ntdsutil "ac i foo" "ifm" "create full C:\Windows\Temp\ntds" q q`},
		{name: "relative output", command: `ntdsutil "ac i ntds" "ifm" "create full ntds" q q`},
		{name: "dynamic output", command: `ntdsutil "ac i ntds" "ifm" "create full %TEMP%\ntds" q q`},
		{name: "missing quit", command: `ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds" q`},
		{name: "extra operation", command: `ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds" q q whoami`},
		{name: "conditional", command: `if exist marker ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds" q q`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: DialectCMD})
			if got := ExactWindowsNTDSIFMDump(facts); got != test.want {
				t.Fatalf("proof=%t want=%t parse=%+v facts=%#v", got, test.want, facts.Parse, facts)
			}
		})
	}
}

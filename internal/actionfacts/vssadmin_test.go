// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactWindowsVSSDeleteAllShadows(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "atomic exact", command: `vssadmin.exe delete shadows /all /quiet`, want: true},
		{name: "case and option order", command: `VSSADMIN DELETE SHADOWS /QUIET /ALL`, want: true},
		{name: "scoped delete", command: `vssadmin delete shadows /for=C: /quiet`},
		{name: "interactive all delete", command: `vssadmin delete shadows /all`},
		{name: "resize", command: `vssadmin resize shadowstorage /For=C: /On=C: /MaxSize=20%`},
		{name: "list", command: `vssadmin list shadows`},
		{name: "dynamic switch", command: `vssadmin delete shadows %SCOPE% /quiet`},
		{name: "pipeline", command: `vssadmin delete shadows /all /quiet | findstr Success`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command,
				CWD: `C:\repo`, DialectHint: DialectCMD,
			})
			if got := ExactWindowsVSSDeleteAllShadows(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
			if test.want && (!facts.Authoritative() || len(facts.Commands) != 1) {
				t.Fatalf("exact invocation not authoritative: %#v", facts)
			}
		})
	}
}

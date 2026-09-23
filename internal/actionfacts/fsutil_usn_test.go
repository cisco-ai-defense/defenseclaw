// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactWindowsUSNJournalDelete(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		dialect Dialect
		want    bool
	}{
		{name: "cmd", command: `fsutil usn deletejournal /D C:`, dialect: DialectCMD, want: true},
		{name: "powershell", command: `fsutil.exe usn deletejournal /d D:`, dialect: DialectPowerShell, want: true},
		{name: "volume information", command: `fsutil fsInfo volumeInfo C:`, dialect: DialectCMD},
		{name: "volume list", command: `fsutil volume list`, dialect: DialectCMD},
		{name: "dirty set", command: `fsutil dirty set C:`, dialect: DialectCMD},
		{name: "query journal", command: `fsutil usn queryjournal C:`, dialect: DialectCMD},
		{name: "create journal", command: `fsutil usn createjournal m=1000 a=100 C:`, dialect: DialectCMD},
		{name: "wrong option", command: `fsutil usn deletejournal /N C:`, dialect: DialectCMD},
		{name: "dynamic volume", command: `fsutil usn deletejournal /D %DRIVE%`, dialect: DialectCMD},
		{name: "quoted volume", command: `fsutil usn deletejournal /D "C:"`, dialect: DialectCMD},
		{name: "extra argument", command: `fsutil usn deletejournal /D C: extra`, dialect: DialectCMD},
		{name: "conditional", command: `if exist C:\\data fsutil usn deletejournal /D C:`, dialect: DialectCMD},
		{name: "pipeline", command: `fsutil usn deletejournal /D C: | more`, dialect: DialectCMD},
		{name: "wrong dialect", command: `fsutil usn deletejournal /D C:`, dialect: DialectPOSIX},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "shell", Command: test.command, DialectHint: test.dialect})
			if got := ExactWindowsUSNJournalDelete(facts); got != test.want {
				t.Fatalf("ExactWindowsUSNJournalDelete() = %v, want %v; facts=%#v", got, test.want, facts)
			}
		})
	}
}

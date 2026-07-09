// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"
)

func TestLauncherArgs(t *testing.T) {
	tests := []struct {
		name string
		exe  string
		args []string
		want []string
	}{
		{name: "cli", exe: "defenseclaw.exe", args: []string{"status"}, want: []string{"-I", "-m", "defenseclaw", "status"}},
		{name: "scanner", exe: "skill-scanner.exe", args: []string{"scan", "fixture"}, want: []string{"-I", "-c", consoleEntryPointScript, "skill-scanner", "scan", "fixture"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := launcherArgs(test.exe, test.args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("launcherArgs() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestLauncherArgsRejectsUnknownName(t *testing.T) {
	if _, err := launcherArgs("renamed.exe", nil); err == nil {
		t.Fatal("launcherArgs() accepted an unknown launcher name")
	}
}

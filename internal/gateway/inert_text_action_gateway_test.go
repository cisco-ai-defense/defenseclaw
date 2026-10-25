// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// Ordinary awk data text stays allowed. A Python argument naming an active
// protected target is protected named even when its f-string writes elsewhere.
func TestR104Loop2DataTextDecisions(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"awk -v value data", `awk -v message='print > report.txt' '{print message}' input.txt`, false},
		{"awk regex data", `awk '/print > out/ {print}' input.txt`, false},
		{"awk comment data", `awk '{print} # print > out' input.txt`, false},
		{"awk operand data", `awk '{print}' 'msg=print > out' input.txt`, false},
		{"awk computed output after regex", `awk '/["]/ {print > out}' input.txt`, false},
		{"awk computed output with -v data", `awk -v m='print > report.txt' '{print > out}' input.txt`, false},
		{"python protected named f-string data", `python3 -c 'open("report.txt","w").write(f"~/.ssh/authorized_keys")'`, true},
		{"python protected named raw f-string data", `python3 -c 'open("report.txt","w").write(rf"~/.ssh/authorized_keys")'`, true},
		{"python Path protected named f-string data", `python3 -c 'from pathlib import Path; Path("report.txt").write_text(f"~/.ssh/authorized_keys")'`, true},
		{"python f-string field", `python3 -c 'open("report.txt","w").write(f"~/.ssh/{k}")'`, false},
		{"python f-string field opens protected file", `python3 -c 'open("report.txt","w").write(f"{open(\"alias\",\"a\")}")'`, true},
		{"python protected destination with f-string data", `python3 -c 'open("alias","w").write(f"x")'`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, blocked := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if blocked != tc.block {
					t.Fatalf("route %d blocked=%v, want %v", i, blocked, tc.block)
				}
			}
		})
	}
}

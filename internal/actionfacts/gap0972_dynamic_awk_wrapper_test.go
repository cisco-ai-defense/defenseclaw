// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package actionfacts

import "testing"

func TestGAP0972PossibleAwkBehindExpandingWrapper(t *testing.T) {
	cases := []struct {
		name, command string
		want          bool
	}{
		{"env assignment dynamic awk", `env FOO=$VALUE awk "$PROGRAM" /tmp/input.txt`, true},
		{"sudo user dynamic awk", `sudo -u $WHO awk "$PROGRAM" /tmp/input.txt`, true},
		{"env assignment static awk", `env FOO=$VALUE awk 'BEGIN { print 1 }' /tmp/input.txt`, false},
		{"sudo user static awk", `sudo -u $WHO awk 'BEGIN { print 1 }' /tmp/input.txt`, false},
		{"awk appears as data", `env FOO=$VALUE echo awk "$PROGRAM"`, false},
		{"inner program dynamic", `env FOO=$VALUE "$TOOL" "$PROGRAM"`, false},
		{"shell command string", `sudo -u $WHO sh -c 'awk "$PROGRAM" /tmp/input.txt'`, false},
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: row.command, CWD: "/tmp"})
			got := false
			for _, command := range facts.Commands {
				if inner, ok := AwkCallBehindWrappers(command); ok && AwkCall(inner).Read().Dynamic {
					got = true
				}
			}
			if got != row.want {
				t.Errorf("dynamic awk behind wrapper: got %t, want %t", got, row.want)
			}
		})
	}
}

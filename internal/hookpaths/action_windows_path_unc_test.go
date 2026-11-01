// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2256: a rooted path in a call with no working directory (the generic
// inspect hooks send none) names no file the gateway can know. It never
// becomes a network (UNC) name, which made the gateway look up a host named
// by the command. A real UNC path and the paths a working directory anchors
// keep their meaning.
func TestGAP2256RootedPathWithoutCWDIsNoNetworkName(t *testing.T) {
	home := `C:\Users\dev`
	for _, value := range []string{"/tmp/project", `\tmp\project`, "/build", "/"} {
		if resolved, ok := actionWindowsPath(value, "", home); ok {
			t.Fatalf("actionWindowsPath(%q, no cwd) = %q, want unresolved", value, resolved)
		}
		if mention := ActionStateTargetMention("ls -la "+value+" && echo build", "", home); mention {
			t.Fatalf("%q without a cwd was a state target", value)
		}
	}
	for _, tc := range []struct{ value, cwd, want string }{
		{`\\server\share\x`, "", "//server/share/x"},
		{"//server/share/x", `C:\proj`, "//server/share/x"},
		{"build", `C:\proj`, "c:/proj/build"},
		{"/c/tmp/x", "", "c:/tmp/x"},
		{"~/.ssh/authorized_keys", "", "c:/users/dev/.ssh/authorized_keys"},
	} {
		resolved, ok := actionWindowsPath(tc.value, tc.cwd, home)
		if !ok || resolved != tc.want {
			t.Fatalf("actionWindowsPath(%q, %q) = %q, %t; want %q", tc.value, tc.cwd, resolved, ok, tc.want)
		}
		if strings.HasPrefix(resolved, "//") != strings.HasPrefix(tc.want, "//") {
			t.Fatalf("%q changed its network form", tc.value)
		}
	}
}

// GAP-2256: repeating a word does not hide a later state target, and a state
// target among repeated ordinary words is still found.
func TestGAP2256RepeatedWordsKeepTheStateTarget(t *testing.T) {
	resetActiveStateIndex(t)
	home, cwd := activeStateIndexFixture(t, 0)
	repeated := strings.Repeat("echo build ; ", 300)
	if actionWindowsTargetMention(repeated+"Set-Content -Path out.txt -Value x", cwd, home, 0, false, actionfacts.DialectPowerShell) {
		t.Fatal("ordinary repeated words were a protected target")
	}
	if !actionWindowsTargetMention(repeated+"Add-Content -Path ~/.ssh/authorized_keys -Value x", cwd, home, 0, false, actionfacts.DialectPowerShell) {
		t.Fatal("authorized_keys after repeated words is no longer a protected target")
	}
	if !actionWindowsTargetMention(repeated+"Set-Content -Path ~/.defenseclaw/config.yaml -Value x", cwd, home, 0, true, actionfacts.DialectPowerShell) {
		t.Fatal("the active config after repeated words is no longer a state target")
	}
}

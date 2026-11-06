// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0706: the root-gateway remedy is written for the running OS. The macOS
// app is named on macOS only, a Unix remedy returns the root-owned files
// before the account start (GAP-0711, GAP-0713), and no remedy ends in a
// period that the sentence around it would double.
func TestGAP0706RootGatewayRemedyIsWrittenPerOS(t *testing.T) {
	home := filepath.Join(t.TempDir(), "account's home")
	for _, tc := range []struct {
		goos             string
		mac, sudo, chown bool
	}{
		{"linux", false, true, true},
		{"darwin", true, true, true},
		{"windows", false, false, false},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			remedy := rootGatewayRemedyFor(tc.goos, home)
			if got := strings.Contains(remedy, "DefenseClawMac"); got != tc.mac {
				t.Fatalf("names DefenseClawMac = %v: %q", got, remedy)
			}
			if got := strings.Contains(remedy, "Start Gateway"); got != tc.mac {
				t.Fatalf("names the app's Start Gateway = %v: %q", got, remedy)
			}
			if strings.Contains(remedy, "macOS") {
				t.Fatalf("remedy names macOS: %q", remedy)
			}
			if got := strings.Contains(remedy, "sudo env DEFENSECLAW_HOME="); got != tc.sudo {
				t.Fatalf("names the privileged stop = %v: %q", got, remedy)
			}
			if got := strings.Contains(remedy, `sudo chown -R "$(id -un)" `); got != tc.chown {
				t.Fatalf("returns the root-owned files = %v: %q", got, remedy)
			}
			if tc.chown && !strings.HasSuffix(remedy, " && defenseclaw-gateway start") {
				t.Fatalf("a Unix remedy ends with the account start: %q", remedy)
			}
			if strings.HasSuffix(remedy, ".") {
				t.Fatalf("remedy ends in a period the caller would double: %q", remedy)
			}
			for _, sentence := range []string{RootGatewayListenerReason + " " + remedy + ".", RootGatewayListenerReason + " " + remedy} {
				if strings.Contains(sentence, "..") {
					t.Fatalf("doubled period in %q", sentence)
				}
			}
		})
	}
	if got, want := RootGatewayListenerRemedy(home), rootGatewayRemedyFor(runtime.GOOS, home); got != want {
		t.Fatalf("RootGatewayListenerRemedy on %s = %q, want %q", runtime.GOOS, got, want)
	}
}

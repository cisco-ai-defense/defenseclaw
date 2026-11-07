// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// GAP-0747: the Windows remedy is rendered by managed.WindowsCommandLine, so
// a path with a space or an apostrophe is one inert literal, and the answer is
// the same wherever the table is read. The plain path is the benign twin.
func TestGAP0747WindowsRootGatewayRemedyIsRenderedNotTyped(t *testing.T) {
	for _, tc := range []struct{ name, executable string }{
		{"plain", `C:\Users\account\.local\bin\defenseclaw-gateway.exe`},
		{"space and apostrophe", `C:\Users\O'Brien Jr\bin\defenseclaw-gateway.exe`},
		{"bare name", "defenseclaw-gateway.exe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stop := managed.WindowsCommandLine(tc.executable, "stop")
			start := managed.WindowsCommandLine(tc.executable, "start")
			want := "Stop it from an elevated PowerShell prompt (" + stop + "), then start it as yourself from a normal PowerShell prompt (" + start + ")"
			if got := windowsRootGatewayRemedy(tc.executable); got != want {
				t.Fatalf("remedy = %q, want %q", got, want)
			}
			if !strings.HasPrefix(stop, "& '") || strings.Contains(want, "(defenseclaw-gateway ") {
				t.Fatalf("remedy names a bare command: %q", want)
			}
			// The call-operator form runs only in PowerShell (not cmd.exe): the text must say so.
			if !strings.Contains(want, "from an elevated PowerShell prompt (") || !strings.Contains(want, "from a normal PowerShell prompt (") {
				t.Fatalf("remedy does not name PowerShell for both steps: %q", want)
			}
			if strings.Contains(want, "administrator prompt") {
				t.Fatalf("remedy names an unnamed-shell prompt: %q", want)
			}
			if strings.Contains(want, "sudo") {
				t.Fatalf("a Windows remedy names sudo: %q", want)
			}
		})
	}
	if got, want := rootGatewayRemedyFor("windows", t.TempDir()), windowsRootGatewayRemedy(rootGatewayWindowsExecutable()); got != want {
		t.Fatalf("the OS table answers %q, want %q", got, want)
	}
}

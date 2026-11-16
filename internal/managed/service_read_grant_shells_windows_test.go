//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"encoding/base64"
	"encoding/binary"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// printedGrantCommand finds the PowerShell grant in a refusal or hint, in
// either printed form (-EncodedCommand, or the -Command "..." form before
// GAP-0087).
var printedGrantCommand = regexp.MustCompile(`powershell -NoProfile(?: -NonInteractive)? (?:-EncodedCommand [A-Za-z0-9+/=]+|-Command "[^"]*")`)

// printedGrantScripts returns the script of every PowerShell grant printed
// in text, decoded.
func printedGrantScripts(t *testing.T, text string) []string {
	t.Helper()
	var scripts []string
	for _, command := range printedGrantCommand.FindAllString(text, -1) {
		_, encoded, ok := strings.Cut(command, " -EncodedCommand ")
		if !ok {
			scripts = append(scripts, command)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw)%2 != 0 {
			t.Fatalf("printed -EncodedCommand is not base64 UTF-16LE: %v %q", err, command)
		}
		units := make([]uint16, len(raw)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(raw[2*i:])
		}
		scripts = append(scripts, string(utf16.Decode(units)))
	}
	return scripts
}

// GAP-0087: the grant printed before the gateway service exists runs as
// printed, pasted at cmd, at Windows PowerShell 5.1 and at PowerShell 7.
// The -Command "..." form ran only from cmd: a PowerShell prompt expanded
// its $ variables first. The rule-pack grant is inherited by everything in
// the folder; the parent-folder grant is on that folder only, as the icacls
// RX example beside it.
func TestServiceReadGrantHintsRunAsPrintedFromEveryShell(t *testing.T) {
	const account = `NT SERVICE\DefenseClawOOFNoSuchService` // no such service: its SID does not map yet
	sid := WindowsServiceSIDString("DefenseClawOOFNoSuchService")
	type shell struct {
		name string
		cmd  func(printed string) *exec.Cmd
	}
	shells := []shell{
		{"cmd", func(printed string) *exec.Cmd {
			c := exec.Command("cmd.exe")
			c.SysProcAttr = &syscall.SysProcAttr{CmdLine: "cmd.exe /d /c " + printed}
			return c
		}},
		{"Windows PowerShell", func(printed string) *exec.Cmd {
			return exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", printed)
		}},
	}
	if pwsh, err := exec.LookPath("pwsh.exe"); err == nil {
		shells = append(shells, shell{"PowerShell 7", func(printed string) *exec.Cmd {
			return exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", printed)
		}})
	} else {
		t.Log("pwsh.exe is not installed here; PowerShell 7 is not checked")
	}
	for _, folder := range []struct {
		name string
		hint func(path, serviceAccount string) string
		want string // the ACE the grant adds
	}{
		{"rule pack folder", beforeServiceExistsHint, "(A;OICI;0x1200a9;;;" + sid + ")"},
		{"parent folder", beforeServiceExistsParentHint, "(A;;0x1200a9;;;" + sid + ")"},
	} {
		for _, sh := range shells {
			t.Run(folder.name+"/"+sh.name, func(t *testing.T) {
				dir := t.TempDir()
				printed := printedGrantCommand.FindString(folder.hint(dir, account))
				if printed == "" {
					t.Fatalf("no PowerShell grant in %q", folder.hint(dir, account))
				}
				if out, err := sh.cmd(printed).CombinedOutput(); err != nil {
					t.Fatalf("%s: the printed grant failed: %v\n%s\nprinted: %s", sh.name, err, out, printed)
				}
				descriptor, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
				if err != nil {
					t.Fatal(err)
				}
				sddl := descriptor.String()
				if !strings.Contains(sddl, folder.want) {
					t.Fatalf("%s: the folder does not carry %s: %s", sh.name, folder.want, sddl)
				}
				if strings.Count(sddl, ";0x1200a9;;;"+sid+")") != 1 {
					t.Fatalf("%s: want exactly one grant for the service SID: %s", sh.name, sddl)
				}
			})
		}
	}
}

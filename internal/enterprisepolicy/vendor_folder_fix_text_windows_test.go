//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// g582 review 7 M1 and L3: the administrator's fix that the case c message
// prints works on a real folder under %ProgramData%, inherited entries
// included (icacls /remove:g and /setowner alone leave ProgramData's
// inherited "Users may add files and folders" entry in place). Each variant
// pastes the rendered text of every command, as the message prints it,
// into cmd.exe or Windows PowerShell, and then the production folder checks
// pass and DefenseClaw's protected file in the folder keeps its access list.
// It needs an elevated administrator or SYSTEM, and removes its folder.
func TestRecordedVendorFolderFixTextWorksOnARealProgramDataFolder(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator or SYSTEM")
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		t.Skip("ProgramData is not set")
	}
	variants := []struct {
		name   string
		shell  string
		icacls [][]string
		// keptSDDL is an entry of the folder's own list that the fix must not
		// remove: a read-only grant (g582 round 9 L5).
		keptSDDL string
	}{
		{name: "inherited ProgramData entries only", shell: "cmd"},
		{name: "inherited entries in PowerShell", shell: "powershell"},
		{name: "explicit Users modify", shell: "powershell", icacls: [][]string{{"/grant", "*S-1-5-32-545:(OI)(CI)M"}}},
		{name: "explicit Everyone and Authenticated Users", shell: "cmd",
			icacls: [][]string{{"/grant", "*S-1-1-0:(OI)(CI)W", "*S-1-5-11:(OI)(CI)M"}}},
		{name: "owned by Users", shell: "powershell", icacls: [][]string{{"/setowner", "*S-1-5-32-545"}}},
		// A read-only entry of a service account the vendor reads its policy
		// as stays; the Users owner and the explicit Users modify entry go.
		{name: "explicit read for another account is kept", shell: "cmd",
			icacls:   [][]string{{"/grant", "*S-1-5-19:(OI)(CI)R"}, {"/grant", "*S-1-5-32-545:(OI)(CI)M"}},
			keptSDDL: ";;;LS)"},
	}
	for index, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			// A unique name: an administrator and SYSTEM may run this at once.
			dir, err := os.MkdirTemp(programData, fmt.Sprintf("dc-g582-fixtext-%d-", index))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			file := filepath.Join(dir, "hooks.json")
			if err := os.WriteFile(file, []byte("{}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := applySDDL(file, publicFileSDDL); err != nil {
				t.Fatal(err)
			}
			fileBefore := folderSDDL(t, file)
			for _, change := range variant.icacls {
				if out, err := exec.Command("icacls.exe", append([]string{dir}, change...)...).CombinedOutput(); err != nil {
					t.Fatalf("icacls %v: %v\n%s", change, err, out)
				}
			}
			leafErr := managed.ValidateTrustedRuntimeDir(dir, "machine policy directory")
			if leafErr == nil {
				t.Fatalf("%s passes the leaf rule before the fix: %s", dir, folderSDDL(t, dir))
			}
			refused := &recordedVendorFolderError{dir: dir, file: file, err: leafErr, siblings: "the vendor loads every file in it"}
			text := refused.Error()
			for _, command := range recordedVendorFolderFix(dir, leafErr) {
				rendered := renderWindowsCommand(command)
				if !strings.Contains(text, rendered) {
					t.Fatalf("the message does not print %s:\n%s", rendered, text)
				}
				runPastedCommand(t, variant.shell, rendered)
			}
			if err := managed.ValidateTrustedRuntimeDir(dir, "machine policy directory"); err != nil {
				t.Fatalf("the leaf rule still fails after the printed fix: %v (%s)", err, folderSDDL(t, dir))
			}
			if err := managed.ValidateTrustedDirectoryAncestor(dir, "machine policy directory"); err != nil {
				t.Fatalf("the ancestor rule fails after the printed fix: %v", err)
			}
			if after := folderSDDL(t, file); after != fileBefore {
				t.Fatalf("the fix changed DefenseClaw's protected file: %s, was %s", after, fileBefore)
			}
			if variant.keptSDDL != "" && !strings.Contains(folderSDDL(t, dir), variant.keptSDDL) {
				t.Fatalf("the fix removed a read-only entry it should keep (%s): %s", variant.keptSDDL, folderSDDL(t, dir))
			}
		})
	}
}

// runPastedCommand runs command as an administrator pasting it would: the
// exact text on cmd.exe's command line, or as a Windows PowerShell script.
func runPastedCommand(t *testing.T, shell, command string) {
	t.Helper()
	var cmd *exec.Cmd
	switch shell {
	case "cmd":
		cmd = exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "cmd.exe /d /c " + command}
	default:
		script := utf16.Encode([]rune(command + "\nexit $LASTEXITCODE\n"))
		encoded := make([]byte, 2*len(script))
		for index, unit := range script {
			binary.LittleEndian.PutUint16(encoded[2*index:], unit)
		}
		cmd = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
			base64.StdEncoding.EncodeToString(encoded))
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", shell, command, err, out)
	}
}

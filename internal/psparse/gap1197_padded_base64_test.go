// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// gap1197PaddedRows are -EncodedCommand words with spaces before, after or
// inside the base64 text. .NET Convert.FromBase64String skips them, so the host
// runs the script and each is a Static table shape whose text is the decoded
// script (rel-1-0-10:GAP-1197). A tab, CR or LF in the word is skipped by the
// host too (gap1199_encoded_blanks_test.go).
func gap1197PaddedRows(script string) [][]string {
	enc := r6enc(script)
	return [][]string{
		{"-ec", " " + enc + " "},
		{"-EncodedCommand", "  " + enc},
		{"-enc", enc + " "},
		{"-e", enc[:4] + " " + enc[4:]},
		{"-nop", "-ec", enc[:8] + "  " + enc[8:] + " "},
	}
}

func TestGAP1197PaddedEncodedCommandWordIsRead(t *testing.T) {
	const script = "Remove-Item -Recurse -Force $HOME\\.defenseclaw"
	for _, argv := range gap1197PaddedRows(script) {
		for _, host := range []string{"pwsh", "powershell", "PowerShell.EXE"} {
			for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51, DialectPwsh7} {
				ns, ok := firstHostNested(hostShapeSource(host, argv), d)
				if !ok || !ns.Static || ns.Text != script {
					t.Errorf("host=%s d=%d argv=%q: want Static %q, got ok=%v %+v", host, d, argv, script, ok, ns)
				}
			}
		}
	}
	if dec, ok := DecodeEncodedCommand("\n " + r6enc("a b") + "\t "); !ok || dec != "a b" {
		t.Errorf("DecodeEncodedCommand padded: %q %v", dec, ok)
	}
}

// Blanks the host does not skip keep the word outside the table: the host
// rejects it and runs nothing.
func TestGAP1197OtherBlanksStayUnread(t *testing.T) {
	enc := r6enc("Write-Output a")
	for _, w := range []string{"\f" + enc, enc + "\v", "\u00a0" + enc} {
		ns, ok := firstHostNested(hostShapeSource("pwsh", []string{"-ec", w}), DialectPwsh7)
		if !ok || ns.Static || ns.Reason != ReasonNonLiteral {
			t.Errorf("%q: want NotStatic %s, got ok=%v %+v", w, ReasonNonLiteral, ok, ns)
		}
	}
}

// TestGAP1197HostRunsPaddedEncodedCommand is the host oracle: Windows
// PowerShell 5.1 (on Windows) and pwsh (PSPARSE_ORACLE or on PATH) run a padded
// -EncodedCommand word, so leaving it unread hides a script that runs.
func TestGAP1197HostRunsPaddedEncodedCommand(t *testing.T) {
	var hosts []string
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("powershell.exe"); err == nil {
			hosts = append(hosts, p)
		}
	}
	if p := os.Getenv("PSPARSE_ORACLE"); p != "" {
		hosts = append(hosts, p)
	} else if p, err := exec.LookPath("pwsh"); err == nil {
		hosts = append(hosts, p)
	}
	if len(hosts) == 0 {
		t.Skip("no PowerShell host")
	}
	for _, host := range hosts {
		for _, argv := range gap1197PaddedRows("Write-Output gap1197-ran") {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			cmd := exec.CommandContext(ctx, host, argv...)
			// Only stdout carries the script output: with redirected streams
			// Windows PowerShell 5.1 writes its progress records to stderr as
			// CLIXML ("Preparing modules for first use").
			var out, errOut bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errOut
			err := cmd.Run()
			cancel()
			if err != nil || strings.TrimSpace(out.String()) != "gap1197-ran" {
				t.Errorf("%s %q: err=%v stdout=%q stderr=%q; want the script to run", host, argv, err, out.String(), errOut.String())
			}
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// gap1199BlankRows are -EncodedCommand words with a tab, CR or LF before,
// inside or after the base64 text. .NET Convert.FromBase64String skips them as
// it skips spaces (GAP-1197), so the host runs the script; the word is a
// Static ps-encoded shape whose text is the decoded script
// (rel-1-0-10:GAP-1199).
func gap1199BlankRows(script string) [][]string {
	enc := r6enc(script)
	return [][]string{
		{"-enc", enc + "\t"},
		{"-ec", "\t" + enc},
		{"-EncodedCommand", enc[:8] + "\r\n" + enc[8:]},
		{"-e", enc[:4] + "\n" + enc[4:] + "\r"},
		{"-nop", "-enc", " \t" + enc[:12] + "\t \n" + enc[12:] + "\r\n"},
	}
}

func TestGAP1199EncodedCommandControlBlanksAreRead(t *testing.T) {
	for _, script := range []string{`Remove-Item -Recurse -Force $HOME\.defenseclaw`, `Get-ChildItem .`} {
		for _, argv := range gap1199BlankRows(script) {
			for _, host := range []string{"pwsh", "powershell", "PowerShell.EXE"} {
				for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51, DialectPwsh7} {
					ns, ok := firstHostNested(hostShapeSource(host, argv), d)
					if !ok || !ns.Static || ns.Kind != KindEncodedCommand || ns.Text != script {
						t.Errorf("host=%s d=%d argv=%q: want Static %q, got ok=%v %+v", host, d, argv, script, ok, ns)
					}
				}
			}
		}
	}
	// the same word in double quotes: one native word as written
	enc := r6enc("Remove-Item x")
	ns, ok := firstHostNested("pwsh -enc \""+enc+"\t\"", DialectPwsh7)
	if !ok || !ns.Static || ns.Text != "Remove-Item x" {
		t.Errorf("double-quoted tab: want Static, got ok=%v %+v", ok, ns)
	}
}

// The literal class stays strict for every other word: a tab, CR or LF outside
// an -EncodedCommand value, a backtick escape, a glued word or a blank the host
// decoder does not skip keeps the payload unread.
func TestGAP1199OtherWordsStayStrict(t *testing.T) {
	enc := r6enc("Remove-Item x")
	for _, src := range []string{
		"pwsh -c 'Remove-Item\tx'",
		"pwsh -wd 'C:\\p\t' -enc " + enc,
		"pwsh -enc \"" + enc + "`t\"",
		"pwsh -enc \"" + enc + "$x\t\"",
		"pwsh -enc '" + enc + "\t'x",
		"pwsh -enc:'" + enc + "\t'",
		"pwsh -enc '" + enc + "\t\f'",
		"pwsh '-enc\t' '" + enc + "\t'",
	} {
		ns, ok := firstHostNested(src, DialectPwsh7)
		if !ok || ns.Static {
			t.Errorf("%q: want NotStatic, got ok=%v %+v", src, ok, ns)
		}
	}
}

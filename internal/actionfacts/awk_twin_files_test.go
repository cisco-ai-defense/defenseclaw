// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// rel-1-0-10:GAP-0652, GAP-0653, GAP-0655 (s7-awkchk round 1): the twin reads
// program files for a caller with a reach, follows find -exec, xargs and
// busybox, and reports a file it could not read.
func TestAwkCommandTwinFilesFindXargsBusybox(t *testing.T) {
	files := map[string]string{
		"p.awk":   `BEGIN{system("touch a")}`,
		"dyn.awk": `{system("echo " $1)}`,
		"ok.awk":  `{print $1}`,
	}
	read := func(name string) (string, bool) { text, ok := files[name]; return text, ok }
	cases := []struct {
		name, command, text        string
		files                      bool
		programFiles, filesUnknown bool
	}{
		{name: "-f", command: `awk -f p.awk in`, text: "touch a", files: true, programFiles: true},
		{name: "--file=", command: `gawk --file=p.awk`, text: "touch a", files: true, programFiles: true},
		{name: "-E", command: `gawk -E p.awk`, text: "touch a", files: true, programFiles: true},
		{name: "--exec", command: `gawk --exec p.awk`, text: "touch a", files: true, programFiles: true},
		{name: "-W exec", command: `mawk -W exec p.awk`, text: "touch a", files: true, programFiles: true},
		{name: "in a shell string", command: `sh -c 'awk -f p.awk'`, text: "sh -c 'touch a'", files: true, programFiles: true},
		{name: "no reach", command: `awk -f p.awk`, text: "", programFiles: true},
		{name: "a missing file", command: `awk -f gone.awk`, text: "", files: true, programFiles: true, filesUnknown: true},
		{name: "a computed file name", command: `awk -f "$P"`, text: "", files: true, programFiles: true, filesUnknown: true},
		{name: "a file with a computed command", command: `awk -f dyn.awk`, text: "", files: true, programFiles: true, filesUnknown: true},
		{name: "a file with no command", command: `awk -f ok.awk in`, text: "", files: true, programFiles: true},
		{name: "inline program, no file", command: `awk 'BEGIN{system("touch a")}'`, text: "touch a", files: true},
		{name: "find -exec", command: `find . -maxdepth 0 -exec awk 'BEGIN{system("touch a")}' \;`, text: `find . -maxdepth 0 -exec sh -c 'touch a' \;`},
		{name: "find -exec plus", command: `find . -exec awk 'BEGIN{system("touch a")}' {} +`, text: `find . -exec sh -c 'touch a' +`},
		{name: "find -execdir", command: `find . -execdir awk 'BEGIN{system("touch a")}' \;`, text: `find . -execdir sh -c 'touch a' \;`},
		{name: "find -exec, benign awk", command: `find . -exec awk '{print $1}' {} \;`, text: ""},
		{name: "xargs", command: `echo | xargs awk 'BEGIN{system("touch a")}'`, text: `echo | xargs sh -c 'touch a'`},
		{name: "xargs -I", command: `echo | xargs -I{} awk 'BEGIN{system("touch a")}'`, text: `echo | xargs -I{} sh -c 'touch a'`},
		{name: "xargs, benign awk", command: `ls | xargs awk '{print $1}'`, text: ""},
		{name: "busybox", command: `busybox awk 'BEGIN{system("touch a")}'`, text: "busybox sh -c 'touch a'"},
		{name: "a computed operand", command: `awk 'BEGIN{system("touch a")}' "$f" *.txt`, text: "touch a"},
		{name: "a computed -F value", command: `awk -F"$s" 'BEGIN{system("touch a")}'`, text: "touch a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			twin := AwkCommandTwinFiles(tc.command, nilUnless(tc.files, read))
			if tc.text == "" && twin.Text != "" || tc.text != "" && !strings.Contains(twin.Text, tc.text) {
				t.Fatalf("text %q, want %q", twin.Text, tc.text)
			}
			if twin.ProgramFiles != tc.programFiles || twin.FilesUnknown != tc.filesUnknown {
				t.Fatalf("program files %v unknown %v, want %v %v", twin.ProgramFiles, twin.FilesUnknown, tc.programFiles, tc.filesUnknown)
			}
		})
	}
}

func nilUnless(on bool, read func(string) (string, bool)) func(string) (string, bool) {
	if on {
		return read
	}
	return nil
}

// ONE BOUND RULE: a program past the byte cap is read to the cap, and the call
// is truncated (cap bytes); a program of ordinary size is not.
func TestAwkCommandTwinReportsTheProgramByteCap(t *testing.T) {
	flood := strings.Repeat("print ", 100000)
	twin := AwkCommandTwin(`awk 'BEGIN{system("touch a")} ` + flood + `'`)
	if !twin.Truncated.Has(bounded.Bytes) {
		t.Fatalf("a %d byte program is not truncated: %s", len(flood), twin.Truncated.Reason())
	}
	if twin.Text != "touch a" {
		t.Fatalf("the command before the cap was not read: %q", twin.Text)
	}
	if AwkCommandTwin(`awk 'BEGIN{system("touch a")}'`).Truncated.Any() {
		t.Fatal("an ordinary program is truncated")
	}
}

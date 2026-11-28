// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// readerOracleTools are the reader rows checked against the tools themselves
// (GAP-2280; the GAP-2273 rows too): the GNU coreutils, diffutils,
// util-linux, binutils and file builds of the Linux build boxes.
var readerOracleTools = map[string]oracleTool{
	"cut": {bins: []string{"cut"}, version: "GNU coreutils"}, "wc": {bins: []string{"wc"}, version: "GNU coreutils"},
	"md5sum": {bins: []string{"md5sum"}, version: "GNU coreutils"}, "sha1sum": {bins: []string{"sha1sum"}, version: "GNU coreutils"},
	"sha256sum": {bins: []string{"sha256sum"}, version: "GNU coreutils"}, "sha512sum": {bins: []string{"sha512sum"}, version: "GNU coreutils"},
	"b2sum": {bins: []string{"b2sum"}, version: "GNU coreutils"}, "cksum": {bins: []string{"cksum"}, version: "GNU coreutils"},
	"du": {bins: []string{"du"}, version: "GNU coreutils"}, "stat": {bins: []string{"stat"}, version: "GNU coreutils"},
	"readlink": {bins: []string{"readlink"}, version: "GNU coreutils"}, "realpath": {bins: []string{"realpath"}, version: "GNU coreutils"},
	"diff": {bins: []string{"diff"}, version: "GNU diffutils"}, "cmp": {bins: []string{"cmp"}, version: "GNU diffutils"},
	"comm": {bins: []string{"comm"}, version: "GNU coreutils"}, "join": {bins: []string{"join"}, version: "GNU coreutils"},
	"paste": {bins: []string{"paste"}, version: "GNU coreutils"}, "fold": {bins: []string{"fold"}, version: "GNU coreutils"},
	"fmt": {bins: []string{"fmt"}, version: "GNU coreutils"}, "expand": {bins: []string{"expand"}, version: "GNU coreutils"},
	"unexpand": {bins: []string{"unexpand"}, version: "GNU coreutils"}, "od": {bins: []string{"od"}, version: "GNU coreutils"},
	"df":  {bins: []string{"df"}, version: "GNU coreutils"},
	"rev": {bins: []string{"rev"}, version: "util-linux"}, "column": {bins: []string{"column"}, version: "util-linux"},
	"hexdump": {bins: []string{"hexdump"}, version: "util-linux"}, "look": {bins: []string{"look"}, version: "util-linux"},
	"strings": {bins: []string{"strings"}, version: "GNU strings"}, "file": {bins: []string{"file"}, version: "file-"},
}

// readerBSDOnly are row flags only the BSD (macOS) tool takes; the GNU tool
// refuses them, so the run check skips them.
var readerBSDOnly = map[string]bool{
	"comm -i": true, "file -I": true, "file -D": true, "file -M": true, "strings -arch": true,
	"fmt -d": true, "fmt -l": true, "fmt -m": true, "fmt -n": true,
	"df -b": true, "df -c": true, "df -g": true, "df -I": true, "df -m": true, "df -n": true, "df -Y": true,
	"cmp -h": true, "cmp -x": true, "cmp -z": true,
}

// readerLeftOut are options the tool documents that the row leaves unknown on
// purpose (a file of more operands or patterns, GAP-2273), and help words
// that are not options.
var readerLeftOut = map[string]bool{
	"wc --files0-from": true, "du --files0-from": true, "du -X": true, "du --exclude-from": true,
	"diff -X": true, "diff --exclude-from": true,
	"strings -min-len":          true,                                   // man's spelling of the -NUM form (the digit switches)
	"cut -M":                    true,                                   // the LIST form -M (first to M'th), not an option
	"diff --GTYPE-group-format": true, "diff --LTYPE-line-format": true, // help placeholders for the --old-/new-/changed-/unchanged- formats
}

// readerOracleBins returns the installed binaries of tool whose --version
// names the expected build.
func readerOracleBins(tool oracleTool) []string {
	var out []string
	for _, b := range tool.bins {
		p, err := exec.LookPath(b)
		if err != nil {
			continue
		}
		if o, _ := exec.Command(p, "--version").CombinedOutput(); strings.Contains(string(o), tool.version) {
			out = append(out, p)
		}
	}
	return out
}

var reInvalidOption = regexp.MustCompile(`(?i)invalid option|unrecognized option|unknown option|illegal option`)

// TestReaderRowsMatchTheTools: every flag of a reader row is a flag of the
// tool with the row's arity, run against the tool (as TestFlagSpecRunOracle
// does for the spec programs): the tool takes it (no invalid option), a
// valued flag with no value is a missing argument and with one value is not,
// a long switch refuses --flag=value, and an attached-value flag takes one.
// Every option the tool's --help or man documents is in the row or in
// readerLeftOut, so a row lists the tool's whole grammar (GAP-2280).
func TestReaderRowsMatchTheTools(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the oracles run against the GNU userland of the Linux build boxes")
	}
	progs := make([]string, 0, len(readerOracleTools))
	for p := range readerOracleTools {
		progs = append(progs, p)
	}
	sort.Strings(progs)
	checked, absent := 0, []string{}
	for _, prog := range progs {
		row, ok := posixTable[prog]
		if !ok {
			t.Fatalf("%s: no row", prog)
		}
		bins := readerOracleBins(readerOracleTools[prog])
		if len(bins) == 0 {
			absent = append(absent, prog)
			continue
		}
		flags := make([]string, 0, len(row.Flags))
		for f := range row.Flags {
			flags = append(flags, f)
		}
		sort.Strings(flags)
		for _, bin := range bins {
			for _, flag := range flags {
				if readerBSDOnly[prog+" "+flag] {
					continue
				}
				fl, name := row.Flags[flag], filepath.Base(bin)+" "+flag
				long := strings.HasPrefix(flag, "--")
				run := func(args ...string) string { return oracleRun(t, bin, args) }
				switch {
				case fl.Optional:
					if se := run(flag); reMissingArg.MatchString(se) || reInvalidOption.MatchString(se) {
						t.Errorf("%s: row optional, but the switch alone is refused: %q", name, se)
					}
					attached := flag + "x"
					if long {
						attached = flag + "=x"
					}
					if se := run(attached); reNoArgAllow.MatchString(se) || reMissingArg.MatchString(se) || reInvalidOption.MatchString(se) {
						t.Errorf("%s: row optional, but an attached value is refused: %q", name, se)
					}
				case fl.Value:
					if se := run(flag); !reMissingArg.MatchString(se) {
						t.Errorf("%s: row takes a value, but no value is accepted (%q)", name, se)
					}
					if se := run(flag, "v0"); reMissingArg.MatchString(se) || reInvalidOption.MatchString(se) {
						t.Errorf("%s: row takes a value, but one value is refused: %q", name, se)
					}
					if long {
						if se := run(flag + "=v0"); reNoArgAllow.MatchString(se) || reMissingArg.MatchString(se) {
							t.Errorf("%s: row takes a value, but --flag=value is refused: %q", name, se)
						}
					}
				default:
					if se := run(flag); reMissingArg.MatchString(se) || reInvalidOption.MatchString(se) {
						t.Errorf("%s: row switch, but the tool refuses it or wants a value: %q", name, se)
					}
					if long {
						if se := run(flag + "=x"); !reNoArgAllow.MatchString(se) {
							t.Errorf("%s: row switch, but --flag=value is accepted (an optional value?): %q", name, se)
						}
					}
				}
				checked++
			}
			docs := parseHelp(helpText(bin))
			for f, d := range parseHelp(manText(bin)) {
				addDoc(docs, f, d)
			}
			for f := range docs {
				if _, ok := row.Flags[f]; !ok && !readerLeftOut[prog+" "+f] {
					t.Errorf("%s: %s is documented by the tool but not in the row (add it, or to readerLeftOut with the reason)", filepath.Base(bin), f)
				}
			}
		}
	}
	t.Logf("reader oracle: %d flag checks; tools absent here: %v", checked, absent)
	if checked == 0 {
		t.Skip("no reader tool installed")
	}
}

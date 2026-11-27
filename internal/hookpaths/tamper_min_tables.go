// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"sync"
)

// The word tables of the s7/tamper-min readers (archive members, inline
// hand-off) are one spec string, one table per line in the order of the
// tmin* indexes below, read once. As for newItemParamSpec, a table spelled
// one literal per word adds every word to the package's literal sweep
// (TestGAP0749BoundedSweepReadsEveryFormAndStaysInBudget): these tables
// added 3,500 forms and 323 through Resolve, past its 22,000 budget
// (rel-1-0-10:GAP-0828). The readers and their verdicts are unchanged.
const tminTableSpec = `--files-from --transform --xform
fCTXbHIKLNVg
--file --directory --exclude --files-from --exclude-from --transform --xform --owner --group --mode --mtime --format --use-compress-program --newer --after-date --label --blocking-factor --record-size --strip-components
--to-stdout --list --to-command
python pypy node bun ruby php
--command=
bcDEeFIiJLlmOopQRSWw
uv poetry pipenv conda pdm rye
run
tmin-entry
--strip-components
fCTXbFgHKLNVIs
file directory files-from exclude-from exclude format owner group mode mtime newer newer-mtime after-date transform xform use-compress-program listed-incremental label blocking-factor tape-length info-script new-volume-script starting-file volno-file record-size rsh-command to-command checkpoint-action exclude-tag exclude-tag-all exclude-tag-under exclude-ignore exclude-ignore-recursive owner-map group-map pax-option quoting-style strip-components suffix backup options include substitute newer-than newer-mtime-than older older-than older-mtime older-mtime-than uname gname uid gid level warning index-file hole-detection
eTfBM@
rsh rsync-path temp-dir include exclude filter exclude-from include-from files-from compare-dest copy-dest link-dest backup-dir suffix partial-dir log-file log-file-format out-format password-file chmod chown usermap groupmap block-size max-size min-size max-delete max-alloc bwlimit timeout contimeout port sockopts address iconv modify-window compress-level compress-choice zc zl checksum-choice cc skip-compress info debug remote-option only-write-batch write-batch read-batch protocol outbuf stop-after stop-at checksum-seed early-input copy-as time-limit config`

// The tables of tminTableSpec, by line.
const (
	tminTarMemberList       = iota // tar long options whose members the words cannot tell
	tminTarValueLetters            // tar short options that take a value
	tminTarValueOptions            // tar long options that take the next word
	tminTarStdout                  // tar long options that write no member to disk
	tminInterpreters               // substrings of an inline-code interpreter program
	tminCommandEquals              // the attached --command= of su and script
	tminSSHValueLetters            // ssh short options that take a value
	tminLaunchers                  // package launchers that run "<launcher> run <program>"
	tminLauncherRun                // their run word
	tminFindEntry                  // the plain name a find -exec child gets for {}
	tminTarStrip                   // tar's member path strip option
	tminExcludeTarLetters          // tar short options that take a value, every tar (actionExcludeValueTaken)
	tminExcludeTarOptions          // tar long options that take a value, no dashes
	tminExcludeRsyncLetters        // rsync short options that take a value
	tminExcludeRsyncOptions        // rsync long options that take a value, no dashes
	tminTableCount
)

var tminTables = sync.OnceValue(func() [][]string {
	lines := strings.Split(tminTableSpec, "\n")
	if len(lines) != tminTableCount {
		panic("hookpaths: tminTableSpec has a line per tmin table")
	}
	tables := make([][]string, len(lines))
	for i, line := range lines {
		tables[i] = strings.Fields(line)
	}
	return tables
})

// tminTable is table i of tminTableSpec.
func tminTable(i int) []string { return tminTables()[i] }

// tminTableSet is table i as a set.
func tminTableSet(i int) map[string]bool {
	set := map[string]bool{}
	for _, word := range tminTable(i) {
		set[word] = true
	}
	return set
}

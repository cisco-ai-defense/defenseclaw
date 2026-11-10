// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// gap0055ArchiveArgvPool is every option and operand shape the archive
// branches read by position or by cluster (unzip -v/-l/-t/-Z/-d/-:, 7z
// x/e/-o/-spf, tar x/-C/-f/-P/--extract, cpio -i/-p/-l/-D, pax -r/-w/-l,
// rsync -a/-H/--links/--link-dest, jar -x/--extract, ditto -x), an option
// with its value missing, the end-of-options marker and words the hook
// cannot read statically.
var gap0055ArchiveArgvPool = []string{
	"-v", "-x", "x", "e", "t", "l", "xf", "-l", "-t", "-Z", "-d", "-o", "-C", "-D", "-f", "-i", "-p", "-a", "-H",
	"-r", "-w", "-P", "-:", "-spf", "--", "-", "--extract", "--links", "--archive", "--list", "--directory",
	"--get", "--link-dest", "--hard-links", "''", "$X", "a.zip", "out",
}

// gap0055ArchiveSecondWords follow a pool word in the two-word argvs: an
// option whose value may be missing, a mode word, the end of options, an
// unreadable word and an operand.
var gap0055ArchiveSecondWords = []string{"-v", "-x", "x", "-d", "-o", "-C", "-f", "--", "$X", "a.zip"}

// gap0055ArchivePrefixes put an archive program behind a lookup or a
// launcher the readers unwrap.
var gap0055ArchivePrefixes = []string{
	"command -v ", "command -V ", "command ", "env ", "sudo -n ", "nice ", "nohup ", "exec ", "exec -a x ",
	"busybox ", "time ", "xargs ", "true && ",
}

// gap0055ArchiveTableParts is the number of tests the table is split into;
// part i reads the argvs whose index modulo this number is i. The table cost
// 730 s of a native Windows runner in one test (rel-1-0-9:GAP-0963), more
// than a CI part may take, and each part is a test of its own that the
// timing-balanced shards place apart.
const gap0055ArchiveTableParts = 16

// gap0055ArchiveTablePart is one part of a fuzz-style table over short
// argv for every archive program (gas-ux-r1 GAP-0055), one parallel subtest
// per program: zero, one and two words of the pool, bare, and with zero or
// one word behind each lookup and launcher, in a list and in a nested shell,
// through the link reader (with and without the disk), the extraction check
// and the hook client's evidence for both connector dialects; and each argv
// straight into the archive helpers. None may panic. Base 4e4e4e3136 panics
// on every unzip form with no argument (index out of range [0] with length
// 0).
func gap0055ArchiveTablePart(t *testing.T, part int) {
	argvs := [][]string{nil}
	for _, a := range gap0055ArchiveArgvPool {
		argvs = append(argvs, []string{a})
	}
	short := len(argvs)
	for _, a := range gap0055ArchiveArgvPool {
		for _, b := range gap0055ArchiveSecondWords {
			argvs = append(argvs, []string{a, b})
		}
	}
	cwd, home := t.TempDir(), t.TempDir()
	for _, program := range archivePrograms {
		t.Run(program, func(t *testing.T) {
			t.Parallel()
			panics, commands := 0, 0
			read := func(name string, fn func()) {
				t.Helper()
				defer func() {
					if recovered := recover(); recovered != nil {
						panics++
						if panics <= 20 {
							t.Errorf("%s: panic: %v", name, recovered)
						}
					}
				}()
				fn()
			}
			for n, argv := range argvs {
				if n%gap0055ArchiveTableParts != part {
					continue
				}
				words := make([]string, len(argv))
				for i, word := range argv {
					words[i] = strings.Trim(word, "'")
				}
				static := makeStatic(len(words))
				for i, word := range argv {
					static[i] = !strings.ContainsAny(word, "$'")
				}
				label := fmt.Sprintf("%s %q", program, argv)
				read("archiveMayLink "+label, func() { archiveMayLink(program, words, static) })
				read("archiveCopiesLinks "+label, func() { archiveCopiesLinks(program, words, static) })
				read("archiveNamesEscape "+label, func() { archiveNamesEscape(program, words, static) })
				read("archiveDestination "+label, func() { archiveDestination(program, words, static, cwd) })
				read("archiveTreeCopy "+label, func() { archiveTreeCopy(words, static, cwd, cwd) })
				prefixes := []string{""}
				if n < short {
					prefixes = append(prefixes, gap0055ArchivePrefixes...)
				}
				for _, prefix := range prefixes {
					command := strings.TrimSpace(prefix + program + " " + strings.Join(argv, " "))
					shapes := []string{command}
					if n < short {
						shapes = append(shapes, command+"; echo hi > out.txt", "sh -c '"+strings.ReplaceAll(command, "'", "")+"'")
					}
					for _, shaped := range shapes {
						commands++
						payload, err := json.Marshal(map[string]any{"session_id": "gap0055", "hook_event_name": "PreToolUse", "cwd": cwd,
							"tool_name": "Bash", "tool_input": map[string]any{"command": shaped}})
						if err != nil {
							t.Fatal(err)
						}
						read("commandLinksRead disk "+shaped, func() { commandLinksRead(shaped, cwd, home, nil, false, false, true) })
						read("commandLinksRead "+shaped, func() { commandLinksRead(shaped, cwd, home, nil, false, false, false) })
						read("ArchiveBeforeWrite "+shaped, func() { ArchiveBeforeWrite(shaped, home) })
						read("Resolve "+shaped, func() { Resolve(payload) })
						read("ResolveConnector codex "+shaped, func() { ResolveConnector("codex", "", "PreToolUse", payload) })
					}
				}
			}
			t.Logf("%d argvs, %d commands, %d panics", len(argvs), commands, panics)
		})
	}
	if part == 0 && (archiveMayLink("unzip", nil, nil) || archiveMayLink("unzip", []string{}, []bool{})) {
		t.Error("a bare unzip prints its usage and extracts nothing: archiveMayLink must be false")
	}
}

func TestGAP0055ArchiveProgramsShortArgvTablePart0(t *testing.T)  { gap0055ArchiveTablePart(t, 0) }
func TestGAP0055ArchiveProgramsShortArgvTablePart1(t *testing.T)  { gap0055ArchiveTablePart(t, 1) }
func TestGAP0055ArchiveProgramsShortArgvTablePart2(t *testing.T)  { gap0055ArchiveTablePart(t, 2) }
func TestGAP0055ArchiveProgramsShortArgvTablePart3(t *testing.T)  { gap0055ArchiveTablePart(t, 3) }
func TestGAP0055ArchiveProgramsShortArgvTablePart4(t *testing.T)  { gap0055ArchiveTablePart(t, 4) }
func TestGAP0055ArchiveProgramsShortArgvTablePart5(t *testing.T)  { gap0055ArchiveTablePart(t, 5) }
func TestGAP0055ArchiveProgramsShortArgvTablePart6(t *testing.T)  { gap0055ArchiveTablePart(t, 6) }
func TestGAP0055ArchiveProgramsShortArgvTablePart7(t *testing.T)  { gap0055ArchiveTablePart(t, 7) }
func TestGAP0055ArchiveProgramsShortArgvTablePart8(t *testing.T)  { gap0055ArchiveTablePart(t, 8) }
func TestGAP0055ArchiveProgramsShortArgvTablePart9(t *testing.T)  { gap0055ArchiveTablePart(t, 9) }
func TestGAP0055ArchiveProgramsShortArgvTablePart10(t *testing.T) { gap0055ArchiveTablePart(t, 10) }
func TestGAP0055ArchiveProgramsShortArgvTablePart11(t *testing.T) { gap0055ArchiveTablePart(t, 11) }
func TestGAP0055ArchiveProgramsShortArgvTablePart12(t *testing.T) { gap0055ArchiveTablePart(t, 12) }
func TestGAP0055ArchiveProgramsShortArgvTablePart13(t *testing.T) { gap0055ArchiveTablePart(t, 13) }
func TestGAP0055ArchiveProgramsShortArgvTablePart14(t *testing.T) { gap0055ArchiveTablePart(t, 14) }
func TestGAP0055ArchiveProgramsShortArgvTablePart15(t *testing.T) { gap0055ArchiveTablePart(t, 15) }

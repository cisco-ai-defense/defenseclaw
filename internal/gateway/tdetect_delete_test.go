// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestHomeDeleteSpellingsFiveTiers: rel-1-0-10:GAP-0743 and GAP-0762. The
// recursive delete of the home folder blocks in every tier; the spellings that
// reached it only through a wrapper the reader did not unwrap (nice, setsid,
// ionice, stdbuf, taskset, chrt, xargs) or through an rm option that is no
// -f (-r with no prompt option, --interactive=never, a prompting rm whose
// questions a yes answers) were clean allows. A prompting rm, a delete below the
// home and the same wrappers around a project path stay allowed.
// Letters: default, strict, permissive, managed, managed-strict.
func TestHomeDeleteSpellingsFiveTiers(t *testing.T) {
	// A glob of the home is read by the facts, not expanded: an empty home keeps the
	// scan off the real folder. The glob spellings are an alert in default and
	// permissive, and a block in strict and on a managed install (the call stays a partial parse, so the
	// semantic owner does not own it; the shell lane of the tool-shape table does).
	t.Setenv("HOME", t.TempDir())
	tdetectRunRows(t, []tdetectRow{
		{"td-del-plain", `rm -rf ~/`, "BBBBB"},
		{"td-del-nice", `nice rm -rf ~/`, "BBBBB"},
		{"td-del-nice-n", `nice -n 10 rm -rf ~/`, "BBBBB"},
		{"td-del-setsid", `setsid rm -rf ~/`, "BBBBB"},
		{"td-del-ionice", `ionice -c 3 rm -rf ~/`, "BBBBB"},
		{"td-del-stdbuf", `stdbuf -o0 rm -rf ~/`, "BBBBB"},
		{"td-del-taskset", `taskset 1 rm -rf ~/`, "BBBBB"},
		{"td-del-chrt", `chrt -i 0 rm -rf ~/`, "BBBBB"},
		{"td-del-xargs", `xargs rm -rf ~/`, "BBBBB"},
		{"td-del-xargs-opts", `xargs -0 -n1 rm -rf ~/`, "BBBBB"},
		{"td-del-two-wrappers", `nice setsid rm -rf ~/`, "BBBBB"},
		{"td-del-recursive-only", `rm -r ~`, "BBBBB"},
		{"td-del-interactive-never", `rm -r --interactive=never ~`, "BBBBB"},
		{"td-del-force-last", `rm -ir ~ -f`, "BBBBB"},
		{"td-del-yes-fed", `yes | rm -ri ~`, "BBBBB"},
		{"td-del-home-glob", `rm -rf ~/*`, "LBLBB"},
		{"td-del-home-glob-var", `rm -rf $HOME/*`, "LBLBB"},
		{"td-del-home-glob-hidden", `rm -rf ~/.[!.]* ~/*`, "LBLBB"},
		{"td-del-root-glob", `rm -rf /*`, "LBLBB"},
		{"td-del-home-dir-glob", `rm -rf /home/*`, "LBLBB"},
		{"td-del-glob-project", `rm -rf ~/proj/*`, "AAAAA"},
		{"td-del-glob-build", `rm -rf ./build/*`, "AAAAA"},
		{"td-del-glob-ext", `rm -rf ~/*.log`, "AAAAA"},
		{"td-del-glob-prompting", `rm -ri ~/*`, "AAAAA"},
		{"td-del-prompting", `rm -ri ~`, "AAAAA"},
		{"td-del-interactive-always", `rm -r --interactive=always ~`, "AAAAA"},
		{"td-del-prompt-last", `rm -fr -i ~`, "AAAAA"},
		{"td-del-project", `nice rm -rf ~/proj`, "AAAAA"},
		{"td-del-below-home", `rm -r ~/proj/build`, "AAAAA"},
		{"td-del-tmp", `nice -n 10 rm -rf /tmp/build`, "AAAAA"},
		{"td-del-relative", `setsid rm -rf ./dist`, "AAAAA"},
		{"td-del-xargs-stdin", `find . -name '*.pyc' | xargs rm -f`, "AAAAA"},
		{"td-del-yes-project", `yes | rm -ri ./build`, "AAAAA"},
		{"td-del-xargs-replace", `ls | xargs -I{} rm -rf {}`, "AAAAA"},
	})
}

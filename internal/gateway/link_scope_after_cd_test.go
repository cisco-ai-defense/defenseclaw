// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestR107LinkScopeOfAnArchiveAfterCdIsReadWhereTheWriteLands: a static cd
// before a tar extraction scoped with -C, followed by a plain write outside
// that scope, gets the verdict of the same command without the cd, per user
// and managed (rel-1-0-6:GAP-0260, the GAP-1557 FP-0001 form). The write is
// read in every directory a statement may stand in, a literal sh -c body
// runs where the statement walk placed its call (the GAP-2582 N03 and N04
// forms after cd), and a mkdir after cd is no write operand, as without
// the cd. The cd twins of the write into the extraction scope and of the
// sh -c link to the keys file still block.
func TestR107LinkScopeOfAnArchiveAfterCdIsReadWhereTheWriteLands(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"FP-0001 without cd", "project", `tar -xzf pkg.tgz --strip-components=1 -C build; echo hi > report.txt`, "allow"},
		{"FP-0001 after cd to the project", "project", `cd {P} && tar -xzf pkg.tgz --strip-components=1 -C build; echo hi > report.txt`, "allow"},
		{"FP-0001 after cd from home", "home", `cd {P} && tar -xf pkg.tgz -C build; echo hi > report.txt`, "allow"},
		{"FP-0001 after cd .", "project", `cd . && tar -xzf pkg.tgz -C build; echo hi > report.txt`, "allow"},
		{"mkdir, tar and write", "project", `mkdir -p build && tar -xzf pkg.tgz -C build && echo hi > report.txt`, "allow"},
		{"mkdir, tar and write after cd", "project", `cd {P} && mkdir -p build && tar -xzf pkg.tgz -C build && echo hi > report.txt`, "allow"},
		{"FP-0001 from a subdirectory after cd", "project", `cd {P}/sub && tar -xzf ../pkg.tgz -C ../build; echo hi > r.txt`, "allow"},
		{"GAP-2582 N03 after cd", "project", `cd {P} && sh -c "ln -s build/out bin && cp -a build dist"`, "allow"},
		{"GAP-2582 N04 after cd", "project", `cd {P} && ln -s build/out bin; sh -c "cp -a src dist"; echo x > notes.txt`, "allow"},
		{"write into the extraction scope", "project", `tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, "alert/block"},
		{"write into the extraction scope after cd", "project", `cd {P} && tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, "alert/block"},
		{"mkdir, then write into the extraction scope after cd", "project", `cd {P} && mkdir -p unpack && tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, "alert/block"},
		{"source after cd, then write into the extraction scope's name", "project", `cd {P} && tar -C unpack -xf keys.tar; . ./x.sh; echo k >> n1.txt`, "alert/block"},
		{"source in an && chain after cd, then write", "project", `cd {P} && tar -C unpack -xf keys.tar && source ./x.sh && echo k >> n1.txt`, "alert/block"},
		{"trap cd DEBUG after cd, then write", "project", `cd {P} && tar -C unpack -xf keys.tar; trap "cd unpack" DEBUG; echo k >> n1.txt`, "alert/block"},
		{"alias of cd after cd, then write", "project", `cd {P} && shopt -s expand_aliases; alias go=cd; tar -C unpack -xf keys.tar; go unpack; echo k >> n1.txt`, "alert/block"},
		{"eval of a variable after cd, then write", "project", `cd {P} && tar -C unpack -xf keys.tar; eval "$X"; echo k >> n1.txt`, "alert/block"},
		{"sh -c source body after cd", "project", `cd {P} && tar -C unpack -xf keys.tar; sh -c ". ./x.sh; echo k >> n1.txt"`, "alert/block"},
		{"source without cd, then write", "project", `tar -C unpack -xf keys.tar; . ./x.sh; echo k >> n1.txt`, "alert/block"},
		{"sh -c hard link of the keys file, then write", "project", `sh -c "ln ~/.ssh/authorized_keys notes.txt" && echo k >> notes.txt`, "block"},
		{"sh -c hard link of the keys file after cd, then write", "project", `cd {P} && sh -c "ln ~/.ssh/authorized_keys notes.txt" && echo k >> notes.txt`, "block"},
	})
}

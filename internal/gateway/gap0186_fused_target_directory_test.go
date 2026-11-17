// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFusedTargetDirectoryIntoKeysFolderBlocksInEveryTier: the target folder
// of cp, mv, install and ln written in the option word itself (-tDIR, a
// cluster that ends in t, an option after a prefix utility) is the
// destination of the call, as the next word of -t DIR is, and the Claude Code
// Bash hook blocks a copy into the keys folder in all five tiers
// (rel-1-0-10:GAP-0186, cert lane L63 on IB1: the fused -t forms were allowed
// in the default and strict packs while -t DIR and cp SRC DST blocked), also
// behind xargs, chroot, flock, sudo, busybox and the other wrappers of the
// shared reader (rel-1-0-10:GAP-1149). A fused folder outside the keys folder
// stays allowed. {keys} is the keys folder, {cwd} the project folder.
func TestFusedTargetDirectoryIntoKeysFolderBlocksInEveryTier(t *testing.T) {
	env := sedBackupTierFixture(t)
	for _, name := range []string{"authorized_keys", "authorized_keys2", "environment", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(env.cwd, name), []byte("k\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"build", "dist"} {
		if err := os.MkdirAll(filepath.Join(env.cwd, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	type row struct {
		id, command string
		block       bool
	}
	rows := []row{
		// The L63 replay (Claude Code Bash, standard user on dc-rhel).
		{"L63-fused-slash", "cp -t$HOME/.ssh/ ./authorized_keys", true},
		{"L63-fused", "cp -t$HOME/.ssh ./authorized_keys", true},
		{"L63-spaced-slash", "cp -t $HOME/.ssh/ ./authorized_keys", true},
		{"L63-src-dst", "cp ./authorized_keys $HOME/.ssh/authorized_keys", true},
		// Wrapped and nested spellings of the fused folder.
		{"G0186-env", "env cp -t{keys} ./authorized_keys", true},
		{"G0186-command", "command cp -t{keys} ./authorized_keys", true},
		{"G0186-nice", "nice -n 5 cp -t{keys} ./authorized_keys", true},
		{"G0186-bash-c", "bash -c 'cp -t{keys} ./authorized_keys'", true},
		{"G0186-quoted-tail", `cp -t"$HOME/.ssh" ./authorized_keys`, true},
		// GNU cp, mv, install and ln refuse a second target-directory option, so
		// every one given is judged, the first as well as the last (review P4).
		{"G0186-multi-t-last", "cp -tbuild -t{keys} ./authorized_keys", true},
		{"G0186-multi-t-first", "cp -t{keys} -t build ./authorized_keys", true},
		{"G0186-multi-t-both-fused", "cp -t{keys} -tbuild ./authorized_keys", true},
		// The program behind a wrapper the shared reader runs at its child index
		// (rel-1-0-10:GAP-1149: xargs and chroot were missed by the round-1
		// prefix reader, so the fused form was allowed while -t DIR blocked).
		{"G1149-xargs", "echo ./authorized_keys | xargs cp -t{keys}", true},
		{"G1149-xargs-n", "echo ./authorized_keys | xargs -n1 cp -t{keys}", true},
		{"G1149-chroot", "chroot / cp -t{keys} ./authorized_keys", true},
		{"G1149-flock", "flock /tmp/l cp -t{keys} ./authorized_keys", true},
		{"G1149-sudo", "sudo -u root cp -t{keys} ./authorized_keys", true},
		{"G1149-doas", "doas cp -t{keys} ./authorized_keys", true},
		{"G1149-stdbuf", "stdbuf -o0 cp -t{keys} ./authorized_keys", true},
		{"G1149-setsid", "setsid cp -t{keys} ./authorized_keys", true},
		{"G1149-timeout", "timeout 5 install -t{keys} ./authorized_keys", true},
		// The prefix forms the shared reader leaves to lateUnwrapCall.
		{"G1149-nice-num", "nice -10 cp -t{keys} ./authorized_keys", true},
		{"G1149-env-assign", "env LC_X=1 FOO=bar cp -t{keys} ./authorized_keys", true},
		// A multicall busybox or toybox runs the applet named next (review P3).
		{"G1149-busybox", "busybox cp -t{keys} ./authorized_keys", true},
		{"G1149-busybox-ln", "busybox ln -sft{keys} {cwd}/authorized_keys", true},
		{"G1149-toybox-mv", "toybox mv -t{keys} ./authorized_keys", true},
		{"G1149-xargs-busybox", "echo ./authorized_keys | xargs busybox cp -t{keys}", true},
		// Controls: the same wrappers with a fused folder in the project.
		{"G1149-C-xargs-build", "echo ./notes.txt | xargs cp -tbuild", false},
		{"G1149-C-chroot-build", "chroot / cp -t{cwd}/build ./notes.txt", false},
		{"G1149-C-busybox-build", "busybox cp -tbuild ./notes.txt", false},
		{"G1149-C-flock-build", "flock /tmp/l mv -tbuild ./notes.txt", false},
		{"G1149-C-multi-t-project", "cp -tbuild -tdist ./notes.txt", false},
		{"G0186-after-cd", "cd {cwd} && cp -t../.ssh ./authorized_keys", true},
	}
	for _, program := range []string{"cp", "mv", "install", "ln", "ln -s"} {
		source := "./authorized_keys"
		if program == "ln -s" {
			source = "{cwd}/authorized_keys"
		}
		id := "G0186-" + strings.ReplaceAll(program, " ", "")
		for _, form := range []row{
			{"-fused", "-t{keys} SRC", true},
			{"-fused-slash", "-t{keys}/ SRC", true},
			{"-cluster", "-ft{keys} SRC", true},
			{"-home-var", "-t$HOME/.ssh SRC", true},
			{"-long-eq", "--target-directory={keys} SRC", true},
			{"-long-abbrev-eq", "--target={keys} SRC", true},
			{"-keys2", "-t{keys} ./authorized_keys2", true},
			{"-environment", "-t{keys} ./environment", true},
			// A file of another name into the keys folder blocks as -t DIR does.
			{"-other-name", "-t{keys} ./notes.txt", true},
			// The spaced twins keep the rel verdict.
			{"-spaced", "-t {keys} SRC", true},
			{"-spaced-other-name", "-t {keys} ./notes.txt", true},
			// Controls: a fused folder outside the keys folder.
			{"-C-fused-project", "-tbuild SRC", false},
			{"-C-fused-project-abs", "-t{cwd}/dist SRC", false},
			{"-C-cluster-project", "-ftbuild SRC", false},
			{"-C-long-eq-project", "--target-directory=build SRC", false},
			{"-C-spaced-project", "-t build SRC", false},
			{"-C-fused-notes", "-tbuild ./notes.txt", false},
		} {
			rows = append(rows, row{id + form.id, program + " " + strings.ReplaceAll(form.command, "SRC", source), form.block})
		}
	}
	replacer := strings.NewReplacer("{keys}", filepath.Join(env.home, ".ssh"), "{cwd}", env.cwd)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, tc := range rows {
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(replacer.Replace(tc.command)))
			if blocked := action == "block"; blocked != tc.block {
				t.Errorf("%s in tier %s: action = %q (findings %q), want block=%v", tc.id, tier.name, action, findings, tc.block)
			}
		}
	}
}

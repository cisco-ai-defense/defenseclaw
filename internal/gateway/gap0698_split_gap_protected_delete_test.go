// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestGAP0698SplitGapKeepsTheProtectedDelete: a call the per-command split
// cannot flatten is never below rel 740c0de8fd when it deletes a protected
// home file (rm, unlink, shred -u, the source of mv), in the default and
// strict packs (substrate-1:GAP-0698: `f(){ cd /tmp; "$@"; }; f cd && rm
// .aws/credentials` from the home allowed at FU11 c8090b1056 and t6/fix-0690
// 8583fa0f61, where rel alerts in default and blocks in strict, and the
// plain delete blocks). A relative operand of such a call is a candidate,
// not a proof, so its floor is the unknown tier (an alert in default, a
// block in strict); a delete spelled from the home is its plain delete.
// Ordinary developer deletes in a project, and deletes of ordinary files
// after a split gap, stay an allow.
func TestGAP0698SplitGapKeepsTheProtectedDelete(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{
		filepath.Join(project, ".git"), filepath.Join(project, "build"), filepath.Join(project, "node_modules"),
		filepath.Join(home, ".aws"), filepath.Join(home, ".ssh"), filepath.Join(home, ".kube"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		filepath.Join(project, ".git", "HEAD"), filepath.Join(project, "go.mod"), filepath.Join(project, ".env.local"),
		filepath.Join(project, "build", "out.o"), filepath.Join(home, "x.txt"),
		filepath.Join(home, ".bashrc"), filepath.Join(home, ".netrc"), filepath.Join(home, ".git-credentials"),
		filepath.Join(home, ".aws", "credentials"), filepath.Join(home, ".ssh", "id_rsa"), filepath.Join(home, ".kube", "config"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	// The unknown tier: rel gives it for every GAP-0698 row below.
	floor := map[string]string{"default": "alert", "strict": "block"}
	const args, mover, dynamic = `f(){ cd /tmp; "$@"; }; f cd && `, `f(){ cd /tmp; $r ~; }; f && `, `f(){ $y; }; f && `
	// A delete spelled from the home names the file: its floor is its plain
	// delete.
	spelled := map[string]bool{"P04": true, "P15": true}
	rows := []struct{ name, command, plain string }{
		// FIX-0697-RV RV2 GAP-0698 rows.
		{"P03", args + "rm .bashrc", "rm .bashrc"},
		{"S07", args + "rm .aws/credentials", "rm .aws/credentials"},
		{"S08", mover + "rm .netrc", "rm .netrc"},
		{"P06", mover + "rm .git-credentials", "rm .git-credentials"},
		{"P08", args + "unlink .aws/credentials", "unlink .aws/credentials"},
		{"Q06", args + "rm -f .aws/credentials .netrc", "rm -f .aws/credentials .netrc"},
		{"Q07", args + "shred -u .aws/credentials", ""},
		// P09: the plain mv away allows on every tree (GAP-0700); rel alerts
		// or blocks the split-gap form.
		{"P09", args + "mv .aws/credentials /tmp/c", ""},
		// The same family through the other mover and other home files.
		{"S07v", mover + "rm .aws/credentials", "rm .aws/credentials"},
		{"P03v", mover + "rm .bashrc", "rm .bashrc"},
		{"P08v", mover + "unlink .aws/credentials", "unlink .aws/credentials"},
		{"Q07v", mover + "shred -u .aws/credentials", ""},
		{"id_rsa", args + "rm .ssh/id_rsa", "rm .ssh/id_rsa"},
		{"kube", mover + "rm .kube/config", "rm .kube/config"},
		{"mv bashrc", mover + "mv .bashrc /tmp/b", ""},
		// GAP-0700 shapes the same twins now judge (allow at rel and FU11).
		{"P04", args + "rm ~/.aws/credentials", "rm ~/.aws/credentials"},
		{"P15", dynamic + "rm ~/.aws/credentials", "rm ~/.aws/credentials"},
		{"P07", dynamic + "rm .aws/credentials", "rm .aws/credentials"},
	}
	controls := []struct{ cwd, command string }{
		{home, "cd proj && rm -rf node_modules"},
		{project, "rm build/out.o"},
		{project, "rm .env.local"},
		{project, "rm -rf build"},
		{project, args + "rm /tmp/x"},
		{project, mover + "rm /tmp/x"},
		{project, `f(){ "$@"; }; f true && rm -rf build`},
		{project, `f(){ "$@"; }; f true && rm .env.local`},
		{project, `f(){ "$@"; }; f make && rm build/out.o`},
		{project, `f(){ eval "$c"; }; f; rm -f out.txt`},
		{project, `f(){ "$@"; }; f true && mv build/out.o /tmp/o`},
		{home, args + "rm x.txt"},
		{home, mover + "rm x.txt"},
		{home, args + "rm -rf proj/build"},
		{home, args + "mv x.txt /tmp/x"},
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		decide := func(cwd, command string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "gap0698-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), command)
			ev["cwd"] = cwd
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, row := range rows {
			want := floor[pack]
			if row.plain != "" {
				plain := decide(home, row.plain)
				if plain == "allow" {
					t.Errorf("%s %s: the plain form %q is allow, want alert or block", pack, row.name, row.plain)
				}
				if spelled[row.name] {
					want = plain
				}
			}
			if got := decide(home, row.command); rank[got] < rank[want] {
				t.Errorf("%s %s: %q is %s, want at least %s", pack, row.name, row.command, got, want)
			}
		}
		for _, control := range controls {
			if got := decide(control.cwd, control.command); got != "allow" {
				t.Errorf("%s: control %q in %s is %s, want allow", pack, control.command, filepath.Base(control.cwd), got)
			}
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestHomeGlobDeleteInAHomeThisHostCannotReadBlocksFiveTiers pins BAR-T23E
// (rel-1-0-10:GAP-0879, GAP-1629): in a home this gateway cannot read (here
// a missing one, as behind ProtectHome or for an account the host does not
// have), the startup files may set dotglob, so a home-glob delete may reach
// ~/.ssh/authorized_keys and blocks in every tier, as in rel. The train read
// every missing home as one whose files set no dotglob (FOLD-3 1f8094496b,
// meant for the sandbox guest's HOME only): the find -exec and xargs
// wrappers of the delete and cd ~; shopt -s dotglob; rm -rf * on the hook
// route fell to allow. The sandbox guest keeps the laptop's answer
// (TestGAP1022And1023ActorAnswersAsTheLaptop, substrate-1 GAP-1024).
func TestHomeGlobDeleteInAHomeThisHostCannotReadBlocksFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell text")
	}
	// Never created: this host has no such home.
	home := filepath.Join(t.TempDir(), "homes", "alice")
	cwd := filepath.Join(home, "proj")
	t.Setenv("HOME", home)
	t.Setenv("BASHOPTS", "")
	t.Setenv("GLOBIGNORE", "")
	prevHost, prevSame := windowsHookHost, sameHostHomeForTest
	t.Cleanup(func() { windowsHookHost, sameHostHomeForTest = prevHost, prevSame })
	windowsHookHost = func() bool { return false }
	sameHostHomeForTest = ""
	// GAP-0879: the wrappers of a home-glob delete (the bar's inspect cells).
	var inspectRows []string
	for _, body := range []string{
		"env FOO=1 rm -rf $HOME/*", "nice rm -rf ~/*", "nohup rm -rf $HOME/*", "rm -rf ~/*",
		"setsid rm -rf $HOME/*", "sudo rm -rf " + home + "/*", "timeout 5 rm -rf ~/*",
	} {
		inspectRows = append(inspectRows, "find . -maxdepth 0 -exec sh -c '"+body+"' \\;", "xargs "+body)
	}
	// GAP-1629: the call's own words turn dotglob on: the bar's cells on both routes.
	seed := "cd ~; shopt -s dotglob; rm -rf *"
	bothRows := []string{
		seed,
		"cd ~; $'sh\\x6fpt' -s dotglob; rm -rf *",
		"sh -c '" + seed + "'",
		"bash -lc '" + seed + "'",
		"eval '" + seed + "'",
		"bash <<< '" + seed + "'",
		"echo x | xargs sh -c '" + seed + "' _",
	}
	// The bar's inspect cells of these two; rel allows them on the hook route.
	inspectRows = append(inspectRows,
		"cd ~; $'\\x65val' 'shopt -s dotglob'; rm -rf *",
		"find . -maxdepth 0 -exec sh -c '"+seed+"' \\;")
	allowed := []string{"nice rm -rf ./build/*", "find . -maxdepth 0 -exec sh -c 'rm -rf ./build/*' \\;"}
	for _, p := range gap0437Packs {
		inspect := gap0437Server(t, p, "openclaw", "action")
		inspect.inspectToolScanTimeout = time.Minute
		hook := gap0437Server(t, p, "claudecode", "action")
		for _, command := range append(append([]string(nil), inspectRows...), bothRows...) {
			if out := gap0437Inspect(t, inspect, cwd, command); out["action"] != "block" {
				t.Errorf("%s inspect %q: %v %v %v, want block", p.name, command, out["action"], out["severity"], out["rule_ids"])
			}
		}
		for i, command := range bothRows {
			if out := gap0437Hook(t, hook, cwd, "bar410-"+p.name+"-"+string(rune('a'+i)), command); out["action"] != "block" {
				t.Errorf("%s hook %q: %v %v %v, want block", p.name, command, out["action"], out["severity"], out["rule_ids"])
			}
		}
		for _, command := range allowed {
			if out := gap0437Inspect(t, inspect, cwd, command); out["action"] != "allow" {
				t.Errorf("%s inspect %q: %v %v, want allow", p.name, command, out["action"], out["rule_ids"])
			}
		}
	}
}

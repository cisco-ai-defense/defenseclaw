// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestGAP2200DigestOfAnotherHomesKeyKeepsThe1010Cell: a digest of another
// account's credential file (the owner transcripts' sudo sha256sum of a
// key in /home/<user>) gets the cell the same digest of an ordinary file
// gets, allow at 1.0.10 in every tier, plain and behind sudo (the exact
// wrapper twin reads the plain call). Red at 7798ee321d: block HIGH
// PATH-SSH-KEY in strict and managed strict. A content read of the same
// file keeps its raise.
func TestGAP2200DigestOfAnotherHomesKeyKeepsThe1010Cell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings")
	}
	// The shipped effects lane (Effects on): its read row of another
	// home made the raise.
	useEffectsRulesMode(t, "on")
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "proj")
	const other = "/home/bob/"
	for _, tier := range boundedTestTiers {
		for _, route := range r3PosixRoutesForReadRows() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, reader := range []string{"sha256sum", "md5sum", "cksum"} {
				wantAction, wantSeverity := route.decide(t, api, cwd, reader+" "+other+"proj/notes.txt")
				for _, file := range []string{".ssh/id_rsa", ".aws/credentials"} {
					for _, wrapper := range []string{"", "sudo "} {
						command := wrapper + reader + " " + other + file
						action, severity := route.decide(t, api, cwd, command)
						if action != wantAction || severity != wantSeverity {
							t.Errorf("%s %s %q = %s %s, want the ordinary file's digest cell %s %s",
								tier.name, route.connector, command, action, severity, wantAction, wantSeverity)
						}
					}
				}
			}
			// cmp -l and -b print the bytes they compare, and a plain cmp
			// names the first differing byte: the key read keeps its raise
			// there, the parent's block HIGH in the strict tiers (GAP-2212;
			// CHK-T23E-D2 N1 pins the cell and adds the plain cmp row). The
			// long spellings keep it too (GAP-2217).
			for _, command := range []string{"cmp -l " + other + ".ssh/id_ed25519 /dev/zero", "cmp -b " + other + ".ssh/id_ed25519 /dev/zero", "cmp " + other + ".ssh/id_ed25519 /dev/zero",
				"cmp --verbose " + other + ".ssh/id_ed25519 /dev/zero", "cmp --print-bytes " + other + ".ssh/id_ed25519 /dev/zero", "cmp -l --bytes=64 " + other + ".ssh/id_ed25519 /dev/zero"} {
				for _, wrapper := range []string{"", "sudo "} {
					ordinary, _ := route.decide(t, api, cwd, wrapper+strings.Replace(command, ".ssh/id_ed25519", "proj/notes.txt", 1))
					action, severity := route.decide(t, api, cwd, wrapper+command)
					if tier.tier == bounded.TierStrict && action == ordinary {
						t.Errorf("%s %s %q = %s %s: the compare of another home's key lost its raise", tier.name, route.connector, wrapper+command, action, severity)
					}
					if tier.tier == bounded.TierStrict && (action != "block" || severity != "HIGH") {
						t.Errorf("%s %s %q = %s %s, want the parent's block HIGH", tier.name, route.connector, wrapper+command, action, severity)
					}
				}
			}
			if tier.tier == bounded.TierStrict {
				digestAction, _ := route.decide(t, api, cwd, "sha256sum "+other+"proj/notes.txt")
				if action, _ := route.decide(t, api, cwd, "cat "+other+".ssh/id_rsa"); action == digestAction {
					t.Errorf("%s %s: the content read of another home's key lost its raise (%s)", tier.name, route.connector, action)
				}
			}
		}
	}
}

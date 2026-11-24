// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestGAP1191ManagedWindowsPlacesRelativeAndTildeStateWrites: behind a
// managed gateway on a Windows hook host, a PowerShell write of the
// DefenseClaw state spelled relative to the working folder (..\.defenseclaw)
// or with a leading ~ (the PowerShell home) is placed in the managed peer's
// home and judged like the same write with the path written out: at least the
// unknown tier in the managed and managed-strict packs, never below the
// written-out spelling or the lane-off verdict. The twins (the same
// spellings naming project files) keep their lane-off verdict. The effects
// path resolver places ~ by the PowerShell provider rule (internal/effects
// placeWindows). This Linux-host emulation is green at the base too (the
// legacy reader places these spellings here); it pins the effects lane on
// them. GAP-1191 itself stays open: natively the managed-peer cells of
// TestGAP1138PowerShellWriteSpellings still need its waiver.
func TestGAP1191ManagedWindowsPlacesRelativeAndTildeStateWrites(t *testing.T) {
	gap0589WindowsHost(t)
	const home, cwd = `C:\Users\alice`, `C:\Users\alice\proj`
	state := home + `\.defenseclaw\config.yaml`
	ctx := withManagedHookPeer(t.Context(), managedHookPeer{Home: home})
	type row struct {
		id, command, reference string
		attack                 bool
	}
	rows := []row{
		{"newitem-tilde", `New-Item -Path ~\.defenseclaw\config.yaml -Value x -Force`, `New-Item -Path ` + state + ` -Value x -Force`, true},
		{"newitem-dotdot", `New-Item -Path ..\.defenseclaw\config.yaml -Value x -Force`, `New-Item -Path ` + state + ` -Value x -Force`, true},
		{"setcontent-tilde", `Set-Content -Path ~\.defenseclaw\config.yaml -Value x`, `Set-Content -Path ` + state + ` -Value x`, true},
		{"setcontent-dotdot", `Set-Content -Path ..\.defenseclaw\config.yaml -Value x`, `Set-Content -Path ` + state + ` -Value x`, true},
		{"newitem-tilde-twin", `New-Item -Path ~\proj\notes.txt -Value x -Force`, "", false},
		{"newitem-dotdot-twin", `New-Item -Path ..\other\notes.txt -Value x -Force`, "", false},
	}
	for _, tier := range boundedTestTiers {
		if !tier.managed {
			continue
		}
		floor := bounded.Unknown(tier.tier)
		for _, route := range det111R1WindowsRoutes("powershell") {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			judge := func(command string, lane bool) bounded.Action {
				useEffectsRulesMode(t, "off")
				if lane {
					useDefaultEffectsLane(t)
				}
				return boundedParse(route.decide(t, api, ctx, cwd, command))
			}
			for _, r := range rows {
				off, on := judge(r.command, false), judge(r.command, true)
				where := tier.name + " " + route.name + " " + r.id
				if !r.attack {
					fmt.Printf("G1191\t%s\tbenign\toff=%s\ton=%s\n", where, off, on)
					if on != off {
						t.Errorf("%s %q: benign twin %s, lane off %s", where, r.command, on, off)
					}
					continue
				}
				ref := judge(r.reference, true)
				fmt.Printf("G1191\t%s\tattack\toff=%s\ton=%s\tref=%s\n", where, off, on, ref)
				if bounded.Stricter(on, floor) != on || bounded.Stricter(on, ref) != on || bounded.Stricter(on, off) != on {
					t.Errorf("%s %q: %s, want at least the unknown tier %s, the written-out spelling %s and lane off %s",
						where, r.command, on, floor, ref, off)
				}
			}
		}
	}
}

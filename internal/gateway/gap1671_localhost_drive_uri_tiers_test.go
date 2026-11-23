// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// On a Windows hook host localhost:///C:/x is the local drive path C:/x (the
// local file URI spelling of Windows tools): a write of a protected file
// through it is judged as the plain C:/x spelling in all five tiers, on the
// PowerShell route of two connectors (rel-1-0-10:GAP-1671). The 1.0.10
// readers read the spelling as a path under the working folder (a share on
// server "C:" in the mention scan), so the write was allowed; the effects
// lane resolves it, but its Maybe readings (scp, Copy-Item) are shadow-only.
// A write of an ordinary project file through the same spelling stays
// allowed.
func TestGAP1671LocalhostDriveURIWriteIsThePlainPath(t *testing.T) {
	useDefaultEffectsLane(t)
	gap0589WindowsHost(t)
	const home = `C:\Users\alice`
	sameHostHomeForTest = home
	t.Cleanup(func() { sameHostHomeForTest = "" })
	const keys = "C:/Users/alice/.ssh/authorized_keys"
	rows := []struct{ command, control string }{
		{`Set-Content -Path localhost:///` + keys + ` -Value k`, `Set-Content -Path ` + keys + ` -Value k`},
		{`Add-Content localhost:///` + keys + ` k`, `Add-Content ` + keys + ` k`},
		{`Copy-Item x.json localhost:///` + keys, `Copy-Item x.json ` + keys},
		{`scp x.json localhost:///` + keys, `scp x.json ` + keys},
		{`Set-Content -Path LOCALHOST:///c:\Users\alice\.ssh\authorized_keys -Value k`, `Set-Content -Path ` + keys + ` -Value k`},
		// Benign twins: an ordinary project file through the same spelling.
		{`Set-Content -Path localhost:///C:/Users/alice/project/notes.txt -Value k`, ""},
		{`scp x.json localhost:///C:/Users/alice/project/notes.txt`, ""},
		{`Copy-Item x.json localhost:///C:/Users/alice/project/notes.txt`, ""},
	}
	for _, tier := range boundedTestTiers {
		for _, route := range r3WindowsRoutes() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			ctx := t.Context()
			if tier.managed {
				ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
			}
			for _, row := range rows {
				action, findings := route.decide(t, api, ctx, home+`\project`, row.command)
				got := boundedParse(action)
				if row.control == "" {
					if got != bounded.Allow {
						t.Errorf("%s %s %q: %s, want allow (benign twin); findings %v", tier.name, route.name, row.command, action, findings)
					}
					continue
				}
				control, _ := route.decide(t, api, ctx, home+`\project`, row.control)
				want := boundedParse(control)
				if want == bounded.Allow {
					t.Fatalf("%s %s: control %q allows, the control is void", tier.name, route.name, row.control)
				}
				if bounded.Stricter(got, want) != got {
					t.Errorf("%s %s %q: %s, want at least %s (the plain spelling); findings %s",
						tier.name, route.name, row.command, action, control, strings.Join(findings, "; "))
				}
			}
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// gap1915PSQ quotes s as one PowerShell single-quoted string (” for ').
func gap1915PSQ(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// gap1915Fixture is the GAP-1915 class as a hermetic corpus: every mutation
// body of the DET111 wsh/protwrite and gap-1576 f12 seeds, on every protected
// target they name, sent plain (powershell -Command), POSIX-wrapped (find
// -exec sh -c, a dot-sourced here-string; the POSIX quote splice inside) and
// encoded (-EncodedCommand with tabs). Synthetic commands only.
func gap1915Fixture() (cmds []string, targets map[string]bool) {
	const home = `C:\Users\alice`
	list := []string{home + `\.defenseclaw\config.yaml`, home + `\.defenseclaw\audit.db`, home + `\.defenseclaw\guardrail_runtime.json`,
		home + `\.ssh\authorized_keys`, `C:\ProgramData\ssh\administrators_authorized_keys`}
	targets = map[string]bool{}
	for _, t := range list {
		targets[t] = true
		for _, body := range []string{
			"echo x >> " + t,
			gap1915PSQ("x") + " | Out-File -FilePath " + t + " -Append",
			gap1915SQ("x") + " | Out-File -FilePath " + t + " -Append",
			"Set-Content -Path " + t + " -Value x",
			"Add-Content -Path " + t + " -Value x",
			`Copy-Item .\x.txt ` + t + " -Force",
			`Move-Item .\x.txt ` + t + " -Force",
			"Remove-Item -Path " + t + " -Force",
			"echo k 1>&2 >> " + t,
		} {
			for _, q := range []func(string) string{gap1915PSQ, gap1915SQ} {
				ps := "powershell.exe -NoProfile -Command " + q(body)
				cmds = append(cmds, ps,
					"find . -maxdepth 0 -exec sh -c "+gap1915SQ(ps)+` \;`,
					". /dev/stdin <<< "+gap1915SQ(ps),
					gap1915Encoded(body))
			}
		}
	}
	return cmds, targets
}

// TestGAP1915PortKeepsEveryLegacyKnownMutation is the frontend differential
// of GAP-1915 (no-loss ruling R-NOLOSS): on a Windows call with no dialect
// hint, every known mutation of the named protected target the legacy reader
// (psparse.Parse) gives is a known mutation with the parser port too, and a call the legacy reader reads
// fully is read fully. Red at c953fc9fe2 (the port lost the rejected
// redirection and read the POSIX quote splice as PowerShell quoting).
func TestGAP1915PortKeepsEveryLegacyKnownMutation(t *testing.T) {
	port := psSourceParser
	t.Cleanup(func() { psSourceParser = port })
	legacy := func(src string, o psparse.Options) (*psparse.Script, bool, error) {
		sc, err := psparse.Parse(src, o)
		return sc, false, err
	}
	o := gap1915Options()
	lost := 0
	cmds, targets := gap1915Fixture()
	for _, cmd := range cmds {
		call := Call{Surface: SurfaceShell, Tool: "shell", Command: cmd}
		psSourceParser = legacy
		want := Extract(call, o)
		psSourceParser = port
		got := Extract(call, o)
		for _, e := range want.Effects {
			switch e.Kind {
			case KindWrite, KindAppend, KindDelete, KindLink, KindPermissionChange:
			default:
				continue
			}
			// only the protected target the command names: the legacy reader
			// also gives stray targets of its misread (C:\' from -Append'\'').
			if e.TargetState != TargetStateKnown || e.RoleState != RoleStateKnown || !targets[e.Target.Path] {
				continue
			}
			if !gap1915Has(got, e.Kind, e.Target.Path) {
				lost++
				t.Errorf("%q: legacy known %s of %s, port %+v", cmd, e.Kind, e.Target.Path, got.Effects)
			}
		}
		if len(want.Unknowns) == 0 && len(got.Unknowns) != 0 {
			t.Errorf("%q: legacy reads it fully, port has structure unknowns %v", cmd, got.Unknowns)
		}
	}
	if lost > 0 {
		t.Logf("%d legacy known mutations lost", lost)
	}
}

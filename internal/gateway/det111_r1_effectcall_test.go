// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effects"
)

func TestDET111R1EffectCallResolvesWindowsUserProfile(t *testing.T) {
	const home = `C:\Users\alice`
	call, opts, ok := effectCall("claudecode", actionfacts.Input{
		Tool: "PowerShell", Command: `Set-Content $env:USERPROFILE\x\.aws\credentials k`,
		ActiveHome: home, DialectHint: actionfacts.DialectPowerShell,
	})
	if !ok {
		t.Fatal("effectCall did not create a shell call")
	}
	if opts.Env["USERPROFILE"] != home {
		t.Fatalf("USERPROFILE=%q, want trusted hook home %q", opts.Env["USERPROFILE"], home)
	}
	for _, e := range effects.Extract(call, opts).Effects {
		if e.Kind == effects.KindWrite && e.TargetState == effects.TargetStateKnown && strings.EqualFold(e.Target.Path, home+`\x\.aws\credentials`) {
			return
		}
	}
	t.Fatalf("USERPROFILE fused path did not resolve: %+v", effects.Extract(call, opts).Effects)
}

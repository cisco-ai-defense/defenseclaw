// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
)

func TestDET111R2PwshLaunchFromPOSIXTable(t *testing.T) {
	for _, name := range []string{"pwsh", "powershell"} {
		p, ok := lookupProgram(name, FlavorPOSIX, DialectPOSIX, false)
		if !ok || !p.PSLaunch {
			t.Fatalf("lookupProgram(%q, POSIX, POSIX) = (%+v, %v), want PowerShell launcher row", name, p, ok)
		}
	}

	opt := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj", Env: map[string]string{"HOME": "/home/u"}}
	command := `pwsh -NoProfile -Command 'Add-Content -Path /home/u/.defenseclaw/config.yaml -Value x'`
	r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: command, Workdir: opt.CWD}, opt)
	for _, e := range r.Effects {
		if (e.Kind == KindAppend || e.Kind == KindWrite) && strings.Contains(e.Target.Path+e.Target.Spelling, "/home/u/.defenseclaw/config.yaml") {
			return
		}
	}
	t.Fatalf("pwsh POSIX launch did not expose protected append\n%s", fmtRes(r))
}

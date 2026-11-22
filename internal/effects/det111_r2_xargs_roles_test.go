// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
)

func TestDET111R2XargsCPLiteralInputRoles(t *testing.T) {
	opt := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj", Env: map[string]string{"HOME": "/home/u"}}
	r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: `echo /home/u/.ssh/authorized_keys | xargs cp -t /tmp/out`, Workdir: opt.CWD}, opt)
	var source, destination bool
	for _, e := range r.Effects {
		if e.Kind == KindRead && strings.HasSuffix(e.Target.Path, "/home/u/.ssh/authorized_keys") {
			source = true
		}
		if e.Kind == KindWrite && strings.HasSuffix(e.Target.Path, "/tmp/out/authorized_keys") {
			destination = true
		}
	}
	if !source || !destination {
		t.Fatalf("xargs cp -t roles: source=%v destination=%v\n%s", source, destination, fmtRes(r))
	}
}

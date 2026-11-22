// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// TestMCPPathUnderNonPathKey: a whole absolute path under a key that does not
// name a path is a target of unknown role, never dropped; prose that holds a
// path is not (S3-PRE security review relayed 2026-11-22, DET111 R1).
func TestMCPPathUnderNonPathKey(t *testing.T) {
	o := effects.Options{Flavor: effects.FlavorPOSIX, CWD: "/home/u/proj", Home: "/home/u"}
	args, _ := json.Marshal(map[string]string{"query": "/home/u/proj/notes.txt", "note": "see /home/u/proj/x.txt please"})
	r := effects.Extract(effects.Call{Surface: effects.SurfaceMCP, Tool: "frob", Args: args}, o)
	var hit, prose bool
	for _, e := range r.Effects {
		if e.Target.Path == "/home/u/proj/notes.txt" && e.RoleState == effects.RoleStateUnknown {
			hit = true
		}
		if e.Target.Path == "/home/u/proj/x.txt" {
			prose = true
		}
	}
	if !hit || prose {
		t.Fatalf("query path read=%v (want true), prose path read=%v (want false): %+v", hit, prose, r.Effects)
	}
}

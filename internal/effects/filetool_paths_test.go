// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// TestFileToolEveryPathKey: a file-tool call naming different paths under
// several path keys has each as a target of unknown role (the tool's own key
// precedence picks one); one path stays one known target (S3-PRE security
// review relayed 2026-11-22, DET111 R1).
func TestFileToolEveryPathKey(t *testing.T) {
	o := effects.Options{Flavor: effects.FlavorPOSIX, CWD: "/home/u/proj", Home: "/home/u"}
	args, _ := json.Marshal(map[string]string{"path": "/home/u/proj/a.txt", "file_path": "/home/u/proj/b.txt", "content": "x"})
	r := effects.Extract(effects.Normalize("claudecode", "Write", args), o)
	got := map[string]effects.RoleState{}
	for _, e := range r.Effects {
		if e.Kind == effects.KindWrite {
			got[e.Target.Path] = e.RoleState
		}
	}
	if len(got) != 2 || got["/home/u/proj/a.txt"] == effects.RoleStateKnown || got["/home/u/proj/b.txt"] == effects.RoleStateKnown {
		t.Fatalf("two path keys: want both writes with unknown role, got %v", got)
	}
	args, _ = json.Marshal(map[string]string{"path": "/home/u/proj/a.txt", "file_path": "/home/u/proj/a.txt", "content": "x"})
	r = effects.Extract(effects.Normalize("claudecode", "Write", args), o)
	if len(r.Effects) != 1 || r.Effects[0].RoleState != effects.RoleStateKnown {
		t.Fatalf("one path under two keys: want one known write, got %+v", r.Effects)
	}
}

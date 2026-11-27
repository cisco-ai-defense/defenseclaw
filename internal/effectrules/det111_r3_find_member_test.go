// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package effectrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// rel-1-0-10:GAP-1573c: find ROOT -name PATTERN -delete deletes an agent
// hook config member below the root when the member exists and the pattern
// matches its name: the delete's hook config match is Known, through the
// call's own link (spelled d/, absent before the call) or on a real folder.
func TestDET111R3FindMemberSettlesHookConfigDelete(t *testing.T) {
	home := t.TempDir()
	for _, f := range []string{".claude/settings.json", "proj/notes.txt"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(home, "proj", "have"), 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		command string
		known   bool
	}{
		{`ln -s ~/.claude d && find d/ -name '*.json' -delete`, true},
		{`ln -s ~/.claude d && find d/ -name 'settings.json' -delete`, true},
		{`find ~/.claude -name '[s]ettings.json' -delete`, true},
		// no member matches the pattern
		{`ln -s ~/.claude d && find d/ -name '*.log' -delete`, false},
		// find -P does not descend a link root spelled without a separator
		{`ln -s ~/.claude d && find d -name '*.json' -delete`, false},
		// ln puts the link inside an existing folder: d/ is that folder
		{`ln -s ~/.claude have && find have/ -name '*.json' -delete`, false},
		// a catch-all or opaque selection is not read
		{`ln -s ~/.claude d && find d/ -name '*' -delete`, false},
		{`ln -s ~/.claude d && find d/ -newer x -delete`, false},
		// a project folder holds no member
		{`ln -s ~/proj d && find d/ -name '*.json' -delete`, false},
	}
	for _, tc := range cases {
		opts := effects.Options{Flavor: effects.FlavorPOSIX, Home: home, CWD: filepath.Join(home, "proj"),
			Env: map[string]string{"HOME": home}}
		facts := Project(effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: tc.command}, opts),
			Env{Home: home, Flavor: effects.FlavorPOSIX})
		known := false
		for _, f := range facts {
			if f.GetKind() != string(effects.KindDelete) || f.GetTargetState() != string(effects.TargetStateKnown) ||
				f.GetTarget().GetPath() != filepath.Join(home, ".claude", "settings.json") {
				continue
			}
			for _, m := range f.GetTarget().GetProtected() {
				if m.GetSet() == SetAgentHookConfig && m.GetState() == string(gradeKnown) && m.GetReason() == "exact" {
					known = true
				}
			}
		}
		if known != tc.known {
			t.Errorf("%q: Known delete of the settings.json member = %v, want %v", tc.command, known, tc.known)
		}
	}
}

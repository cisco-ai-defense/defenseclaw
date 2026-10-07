// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import "testing"

func TestRememberedRootMustStillBeTheSameAgent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Proc)
	}{
		{"exec to another program", func(p *Proc) { p.Exe = "/bin/sh"; p.Cmdline = []string{"sh"} }},
		{"uid changed", func(p *Proc) { p.UID, p.EUID = 1002, 1002 }},
		{"moved to another pid namespace", func(p *Proc) { p.Host = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t, baseTargets)
			p := nativeProc(4001, 1, 100, 1001, aliceClaudeNew)
			if roots := w.roots(p); len(roots.Roots) != 1 {
				t.Fatalf("initial roots: %+v", roots.Roots)
			}
			tc.change(&p)
			if roots := w.roots(p); len(roots.Roots) != 0 {
				t.Fatalf("stale root retained: %+v", roots.Roots)
			}
		})
	}

	w := newWorld(t, baseTargets)
	p := codexProc(5001, 1, 120, 1002)
	if roots := w.roots(p); len(roots.Roots) != 1 {
		t.Fatalf("initial script root: %+v", roots.Roots)
	}
	p.Cmdline = []string{"node", "/home/bob/other.js"}
	if roots := w.roots(p); len(roots.Roots) != 0 {
		t.Fatalf("script root survived a different argv: %+v", roots.Roots)
	}

	w = newWorld(t, baseTargets)
	p = nativeProc(4001, 1, 100, 1001, aliceClaudeNew)
	if roots := w.roots(p); len(roots.Roots) != 1 {
		t.Fatalf("initial native root: %+v", roots.Roots)
	}
	w.enroll = mustEnrollment(t, `targets:
- user: alice
  uid: 1001
  user_home: /home/alice
  connector: codex
`)
	w.installs = ResolveInstalls(w.fs, w.enroll, ResolveOptions{ExtraPrefixes: []string{"/opt/agents"}})
	if roots := w.roots(p); len(roots.Roots) != 0 {
		t.Fatalf("root retained after connector was de-enrolled: %+v", roots.Roots)
	}
}

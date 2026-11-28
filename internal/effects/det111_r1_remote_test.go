// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// det111PosixCase is a Linux Bash call in /home/alice/proj (home /home/alice).
func det111PosixCase(t *testing.T, id, cmd string) det111Case {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"id": id,
		"payload": map[string]any{"args": map[string]string{"command": cmd},
			"cwd": "/home/alice/proj", "dialect": "posix", "tool_name": "Bash"},
		"strata": map[string]string{"platform": "linux"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var c det111Case
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestDET111R1RemoteHostBody is the GAP-0662/var8 ruling: ssh HOST CMD joins
// its words and runs them in the login shell of HOST, so the body is read and
// its effects are placed on that host: graded by name behind an unknown home
// and root (Maybe), never as a known local member, and never dropped. The
// host may be this one (ssh localhost). A tilde the walker cannot expand
// keeps its literal tail, so the name stays readable (sudo sh -c, the same
// unknown home).
func TestDET111R1RemoteHostBody(t *testing.T) {
	cases := []struct {
		id, cmd string
		set     string // the protected set that must be reached Maybe ("" = none at all)
		local   string // a local path that must stay placed and known
	}{
		{"var8-shape", `ssh localhost 'python3 -c "import sys; open(sys.argv[1],chr(97)).write(1)" ~/.defenseclaw/config.yaml'`, "self_protection", ""},
		{"keys-append", `ssh -p 2222 build1 'echo k >> ~/.ssh/authorized_keys'`, "ssh_authorized_keys", ""},
		{"local-tilde-abs", `ssh build1 cat ~/.ssh/id_rsa`, "credentials", ""},
		{"several-words", `ssh build1 echo k '>>' '~/.ssh/authorized_keys'`, "ssh_authorized_keys", ""},
		{"unknown-home-sudo", `sudo sh -c 'echo k >> ~/.ssh/authorized_keys'`, "ssh_authorized_keys", ""},
		{"benign-rc-read", `ssh build1 'cat ~/.bashrc; uptime'`, "", ""},
		{"benign-local-redirect", `ssh build1 ls > out.txt`, "", "/home/alice/proj/out.txt"},
	}
	for _, tc := range cases {
		res, facts, lines := det111Run(det111PosixCase(t, tc.id, tc.cmd))
		dump := strings.Join(lines, "\n  ")
		var reached bool
		for i, e := range res.Effects {
			remote := false
			for _, r := range e.Reasons {
				remote = remote || r.Code == effects.ReasonForeignContext
			}
			if remote && e.Target.Path != "" {
				t.Errorf("%s: effect %d of the remote body is placed on the local path %q:\n  %s", tc.id, i, e.Target.Path, dump)
			}
			if i >= len(facts) {
				continue
			}
			for _, m := range facts[i].GetTarget().GetProtected() {
				if m.GetState() == "known" && strings.HasPrefix(tc.id, "benign") {
					t.Errorf("%s: benign row reaches %s known:\n  %s", tc.id, m.GetSet(), dump)
				}
				if m.GetState() == "known" && remote {
					t.Errorf("%s: remote effect %d graded known local %s:\n  %s", tc.id, i, m.GetSet(), dump)
				}
				if tc.set == "" {
					t.Errorf("%s: reaches %s=%s:\n  %s", tc.id, m.GetSet(), m.GetState(), dump)
				}
				if m.GetSet() == tc.set && m.GetState() == "unknown" {
					reached = true
				}
			}
			if tc.local != "" && e.Target.Path == tc.local && remote {
				t.Errorf("%s: the local redirect %s is marked remote:\n  %s", tc.id, tc.local, dump)
			}
		}
		if tc.set != "" && !reached {
			t.Errorf("%s: %s not reached Maybe:\n  %s", tc.id, tc.set, dump)
		}
		if tc.local != "" {
			found := false
			for _, e := range res.Effects {
				found = found || (e.Target.Path == tc.local && e.TargetState == effects.TargetStateKnown)
			}
			if !found {
				t.Errorf("%s: the local write %s is not placed known:\n  %s", tc.id, tc.local, dump)
			}
		}
	}
	// ssh HOST alone is an interactive login: no child to read, as before.
	res, _, lines := det111Run(det111PosixCase(t, "login", `ssh -t build1`))
	for _, e := range res.Effects {
		if e.Origin.Depth > 0 || e.Origin.Program == "sh" {
			t.Errorf("ssh HOST with no command lowered a body:\n  %s", strings.Join(lines, "\n  "))
		}
	}
}

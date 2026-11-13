// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

const testHome = "/home/u"

// fakeResolver resolves the listed links; any path in unresolvable returns
// ok=false (the link reading could not complete); every other path resolves
// to itself, trusted.
func fakeResolver(links map[string]string, unresolvable ...string) func(string) (string, bool) {
	bad := map[string]bool{}
	for _, p := range unresolvable {
		bad[p] = true
	}
	return func(p string) (string, bool) {
		if bad[p] {
			return "", false
		}
		if r, ok := links[p]; ok {
			return r, true
		}
		return p, true
	}
}

func projectCommand(t *testing.T, command string, env Env) []*semanticpb.EffectFact {
	t.Helper()
	args, _ := json.Marshal(map[string]string{"command": command})
	call := effects.Normalize("claudecode", "bash", args)
	res := effects.Extract(call, effects.Options{Home: env.Home, CWD: env.Home + "/work", Flavor: env.Flavor})
	return Project(res, env)
}

// pathEffectState returns the folded protected state of the first path-target
// effect, for the named set ("" = any set).
func pathEffectState(facts []*semanticpb.EffectFact, set string) (string, bool) {
	for _, f := range facts {
		if f.GetTarget().GetType() == "path" {
			return semantic.ProtectedState(f.GetTarget(), set), true
		}
	}
	return "", false
}

// strongestState folds the protected state of a set across every path-target
// effect: known beats unknown beats no.
func strongestState(facts []*semanticpb.EffectFact, set string) string {
	best := semantic.ProtectedNo
	for _, f := range facts {
		if f.GetTarget().GetType() != "path" {
			continue
		}
		st := semantic.ProtectedState(f.GetTarget(), set)
		if st == semantic.ProtectedKnown {
			return semantic.ProtectedKnown
		}
		if st == semantic.ProtectedUnknown {
			best = semantic.ProtectedUnknown
		}
	}
	return best
}

func TestProjectNarrowedMutations(t *testing.T) {
	// Owner 2026-11-13: the unknown tier fires only when the target could
	// resolve to a protected file. A mutation whose target cannot (a workspace
	// path, an extraction into a non-protected dir, a fully dynamic dest) is
	// clean, not an alert.
	cases := []struct{ name, command, set, want string }{
		{"tar extract into a non-protected dir is clean", `tar -xf a.tar -C /etc`, "", semantic.ProtectedNo},
		{"fully dynamic write is clean", `echo x > "$DEST"`, "", semantic.ProtectedNo},
		{"ordinary workspace write is clean", `cp a.conf a.conf.bak`, "", semantic.ProtectedNo},
		{"ordinary workspace delete glob is clean", `rm -f build/*.o`, "", semantic.ProtectedNo},
		{"home write is clean", `echo x > ~/work/out.txt`, "", semantic.ProtectedNo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := projectCommand(t, tc.command, Env{Home: testHome, Resolve: fakeResolver(nil)})
			if got := strongestState(facts, tc.set); got != tc.want {
				t.Fatalf("command %q: state = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}

// A dynamic cwd that leaves the path empty but whose as-written spelling is a
// relative protected file (../.ssh/authorized_keys) still lands in the unknown
// tier via the shape match on the spelling (keep attacks).
func TestProjectRelativeProtectedSpelling(t *testing.T) {
	res := effects.Result{Effects: []effects.Effect{{
		Kind: effects.KindWrite, TargetState: effects.TargetStateUnknown, RoleState: effects.RoleStateKnown,
		Reasons: []effects.Reason{{Code: effects.ReasonDynamicCWD, Scope: effects.ScopeTarget}},
		Target:  effects.Target{Type: effects.TargetPath, Spelling: "../.ssh/authorized_keys", Flavor: effects.FlavorPOSIX},
	}}}
	facts := Project(res, Env{Home: testHome, Resolve: fakeResolver(nil)})
	if got := strongestState(facts, SetSSHAuthorizedKeys); got != semantic.ProtectedUnknown {
		t.Fatalf("relative protected spelling: ssh state = %q, want unknown", got)
	}
}

func TestProjectProtectedGrades(t *testing.T) {
	cases := []struct {
		name    string
		command string
		env     Env
		set     string
		want    string
	}{
		{
			name:    "protected-set case 1: append to authorized_keys is known",
			command: `echo k >> ~/.ssh/authorized_keys`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     SetSSHAuthorizedKeys, want: semantic.ProtectedKnown,
		},
		{
			name:    "protected-set case 2: write to .bashrc is known shell_rc",
			command: `echo x > ~/.bashrc`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     SetShellRC, want: semantic.ProtectedKnown,
		},
		{
			name:    "protected-set case 3: read of aws credentials is known",
			command: `cat ~/.aws/credentials`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     SetCredentials, want: semantic.ProtectedKnown,
		},
		{
			name:    "protected-set case 4: ordinary temp write is no",
			command: `echo x > /tmp/ordinary.txt`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     "", want: semantic.ProtectedNo,
		},
		{
			name:    "protected-set case 5: write through a link into .ssh is known",
			command: `echo x > /tmp/link`,
			env:     Env{Home: testHome, Resolve: fakeResolver(map[string]string{"/tmp/link": testHome + "/.ssh/authorized_keys"})},
			set:     SetSSHAuthorizedKeys, want: semantic.ProtectedKnown,
		},
		{
			name:    "protected-set case 6: a dynamic write that cannot resolve to a protected file is clean",
			command: `echo x > "$DEST"`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     "", want: semantic.ProtectedNo,
		},
		{
			name:    "protected-set case 6c: dynamic read has no protected signal",
			command: `cat "$SRC"`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     "", want: semantic.ProtectedNo,
		},
		{
			name:    "protected-set case 7: delete under .ssh (glob child) is unknown",
			command: `rm -rf ~/.ssh/*`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     SetSSHAuthorizedKeys, want: semantic.ProtectedUnknown,
		},
		{
			name:    "protected-set case 8: a link that cannot be followed is unknown, never no",
			command: `echo x > /tmp/maybe`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil, "/tmp/maybe")},
			set:     SetSSHAuthorizedKeys, want: semantic.ProtectedUnknown,
		},
		{
			name:    "protected-set case 9: write to a DefenseClaw state file is self_protection",
			command: `echo x > ~/.defenseclaw/config.yaml`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     SetSelfProtection, want: semantic.ProtectedKnown,
		},
		{
			name:    "protected-set case 10: write under the hooks tree is agent_hook_config",
			command: `echo x > ~/.claude/hooks/pre.sh`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     SetAgentHookConfig, want: semantic.ProtectedKnown,
		},
		{
			name:    "protected-set case 11: ordinary temp write is not credentials either",
			command: `echo x > /tmp/ordinary.txt`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     SetCredentials, want: semantic.ProtectedNo,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := projectCommand(t, tc.command, tc.env)
			got, ok := pathEffectState(facts, tc.set)
			if !ok {
				t.Fatalf("no path-target effect for %q", tc.command)
			}
			if got != tc.want {
				t.Fatalf("command %q set %q: protected = %q, want %q", tc.command, tc.set, got, tc.want)
			}
		})
	}
}

func TestProjectAgentCreated(t *testing.T) {
	created := map[string]bool{"/tmp/test-artifact": true}
	env := Env{
		Home:         testHome,
		Resolve:      fakeResolver(nil),
		AgentCreated: func(key string) bool { return created[key] },
	}
	facts := projectCommand(t, `rm /tmp/test-artifact`, env)
	var marked bool
	for _, f := range facts {
		if f.GetTarget().GetType() == "path" && f.GetTarget().GetAgentCreated() {
			marked = true
		}
	}
	if !marked {
		t.Fatalf("expected the agent-created target to be flagged; facts=%+v", facts)
	}
}

// R5F-3: a known write whose target IS a protected directory (~/.ssh itself,
// via ln -s to a dir, Copy-Item/Move-Item -Destination <dir>, robocopy) must
// be unknown, not clean, unless the joined file is a known member.
func TestProjectProtectedDirectoryWrite(t *testing.T) {
	dirWrite := effects.Result{Effects: []effects.Effect{{
		Kind:        effects.KindLink,
		TargetState: effects.TargetStateKnown,
		RoleState:   effects.RoleStateKnown,
		Target:      effects.Target{Type: effects.TargetPath, Path: testHome + "/.ssh", Flavor: effects.FlavorPOSIX},
	}}}
	facts := Project(dirWrite, Env{Home: testHome, Resolve: fakeResolver(nil)})
	if got := strongestState(facts, SetSSHAuthorizedKeys); got != semantic.ProtectedUnknown {
		t.Fatalf("write to ~/.ssh directory: ssh state = %q, want unknown (protected_dir)", got)
	}
	// A known file member under the directory is still known, not demoted.
	fileWrite := effects.Result{Effects: []effects.Effect{{
		Kind:        effects.KindWrite,
		TargetState: effects.TargetStateKnown,
		RoleState:   effects.RoleStateKnown,
		Target:      effects.Target{Type: effects.TargetPath, Path: testHome + "/.ssh/authorized_keys", Flavor: effects.FlavorPOSIX},
	}}}
	if got := strongestState(Project(fileWrite, Env{Home: testHome, Resolve: fakeResolver(nil)}), SetSSHAuthorizedKeys); got != semantic.ProtectedKnown {
		t.Fatalf("write to ~/.ssh/authorized_keys: ssh state = %q, want known", got)
	}
}

// Rule (c): a canonical path whose shape matches a protected file but in an
// unexpected directory (a CDPATH / reassigned-HOME resolution that came out
// canonical but wrong) is unknown, not clean, so it lands in the unknown tier.
func TestProjectWrongDirectoryShape(t *testing.T) {
	write := func(path string) []*semanticpb.EffectFact {
		return Project(effects.Result{Effects: []effects.Effect{{
			Kind: effects.KindWrite, TargetState: effects.TargetStateKnown, RoleState: effects.RoleStateKnown,
			Target: effects.Target{Type: effects.TargetPath, Path: path, Flavor: effects.FlavorPOSIX},
		}}}, Env{Home: testHome, Resolve: fakeResolver(nil)})
	}
	cases := []struct{ name, path, set, want string }{
		{"wrong-dir authorized_keys is unknown", "/tmp/stage/.ssh/authorized_keys", SetSSHAuthorizedKeys, semantic.ProtectedUnknown},
		{"wrong-home authorized_keys is unknown", "/srv/other/.ssh/authorized_keys", SetSSHAuthorizedKeys, semantic.ProtectedUnknown},
		{"wrong-dir bashrc is unknown", "/tmp/proj/.bashrc", SetShellRC, semantic.ProtectedUnknown},
		{"exact real-home authorized_keys stays known", testHome + "/.ssh/authorized_keys", SetSSHAuthorizedKeys, semantic.ProtectedKnown},
		{"ordinary unrelated path stays no", "/tmp/stage/notes.txt", "", semantic.ProtectedNo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := strongestState(write(tc.path), tc.set); got != tc.want {
				t.Fatalf("write %q set %q: state = %q, want %q", tc.path, tc.set, got, tc.want)
			}
		})
	}
}

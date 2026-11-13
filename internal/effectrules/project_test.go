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

func TestProjectOutsideHome(t *testing.T) {
	cases := []struct{ name, command, set, want string }{
		{"outside-home case 1: tar extract to /etc is outside_home unknown", `tar -xf a.tar -C /etc`, SetOutsideHome, semantic.ProtectedUnknown},
		{"outside-home case 2: dynamic destination is outside_home unknown", `echo x > "$DEST"`, SetOutsideHome, semantic.ProtectedUnknown},
		{"outside-home case 3: ordinary home write is clean everywhere", `echo x > ~/work/out.txt`, "", semantic.ProtectedNo},
		{"outside-home case 4: ordinary home write not outside_home", `echo x > ~/work/out.txt`, SetOutsideHome, semantic.ProtectedNo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := projectCommand(t, tc.command, Env{Home: testHome, Resolve: fakeResolver(nil)})
			if got := strongestState(facts, tc.set); got != tc.want {
				t.Fatalf("command %q set %q: state = %q, want %q", tc.command, tc.set, got, tc.want)
			}
		})
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
			name:    "protected-set case 6: dynamic write is outside_home unknown, not a named set",
			command: `echo x > "$DEST"`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     SetOutsideHome, want: semantic.ProtectedUnknown,
		},
		{
			name:    "protected-set case 6b: dynamic write does not claim the ssh set",
			command: `echo x > "$DEST"`,
			env:     Env{Home: testHome, Resolve: fakeResolver(nil)},
			set:     SetSSHAuthorizedKeys, want: semantic.ProtectedNo,
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

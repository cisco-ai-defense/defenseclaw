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

import (
	"strings"
	"testing"
)

// validControls returns a controls policy that passes lint, as typed data and
// the options lint needs.
func validControls(t *testing.T) (tracingPolicy, LintOptions, *world) {
	t.Helper()
	w := newWorld(t, baseTargets)
	roots := w.roots(nativeProc(4001, 1, 100, 1001, aliceClaudeNew), codexProc(5001, 1, 120, 1002))
	c := w.compile(Input{Controls: &Scope{Mode: PolicyEnforce, UIDs: []int{1001, 1002}}, Roots: roots.Roots})
	p := policyOf(t, c, FamilyControls)
	opts := LintOptions{Homes: []string{"/home/alice", "/home/bob"}, FS: w.fs}
	if v := Lint(p.YAML, opts); len(v) != 0 {
		t.Fatalf("the compiler's own output fails lint: %v", v)
	}
	return cloneTP(t, p.tp), opts, w
}

func cloneTP(t *testing.T, tp tracingPolicy) tracingPolicy {
	t.Helper()
	data, err := marshalPolicy(tp)
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodePolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func lintTP(t *testing.T, tp tracingPolicy, opts LintOptions) []Violation {
	t.Helper()
	data, err := render(FamilyControls, tp, PolicyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	return Lint(data, opts)
}

func hasRule(v []Violation, rule int) bool {
	for _, item := range v {
		if item.Rule == rule {
			return true
		}
	}
	return false
}

// Selector positions in the valid controls policy (two hooks, see
// compileControls): hook 0 = [NoPost, ssh bin, ssh pid, persist bin, persist pid].
const (
	selNoPost  = 0
	selSSHBins = 1
	selSSHPids = 2
)

func TestLintRefusesEveryEmptyList(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(tp *tracingPolicy)
	}{
		{"empty matchBinaries on an Override selector", func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchBinaries[0].Values = nil
		}},
		{"empty matchPIDs on an Override selector", func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHPids].MatchPIDs[0].Values = nil
		}},
		{"empty namespace values", func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchNamespaces[0].Values = nil
		}},
		{"empty uid list", func(tp *tracingPolicy) {
			sel := &tp.Spec.LsmHooks[0].Selectors[selSSHBins]
			sel.MatchArgs[len(sel.MatchArgs)-1].Values = nil
		}},
		{"empty path list", func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = nil
		}},
		{"empty exemption binaries", func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selNoPost].MatchBinaries[0].Values = nil
		}},
		{"empty exemption paths", func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selNoPost].MatchArgs[0].Values = nil
		}},
		{"exemption without binaries", func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selNoPost].MatchBinaries = nil
		}},
		{"persistence directory hook, empty binaries", func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[1].Selectors[0].MatchBinaries[0].Values = []string{}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tp, opts, _ := validControls(t)
			tc.mutate(&tp)
			if v := lintTP(t, tp, opts); !hasRule(v, 1) {
				t.Fatalf("violations = %v, want rule 1", v)
			}
		})
	}
}

func TestLintRules(t *testing.T) {
	five := -5
	cases := []struct {
		name   string
		rule   int
		mutate func(tp *tracingPolicy)
	}{
		// Rule 2: an Override selector is scoped to an enrolled lineage.
		{"override without lineage anchor", 2, func(tp *tracingPolicy) {
			sel := &tp.Spec.LsmHooks[0].Selectors[selSSHBins]
			sel.MatchBinaries = nil
		}},
		{"override with followChildren off", 2, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchBinaries[0].FollowChildren = false
		}},
		{"pid anchor without followForks", 2, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHPids].MatchPIDs[0].FollowForks = false
		}},
		{"override outside the host pid namespace", 2, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchNamespaces = nil
		}},
		{"override with another namespace", 2, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchNamespaces[0].Values = []string{"4026531836"}
		}},
		{"override without uid condition", 2, func(tp *tracingPolicy) {
			sel := &tp.Spec.LsmHooks[0].Selectors[selSSHBins]
			sel.MatchArgs = sel.MatchArgs[:len(sel.MatchArgs)-1]
		}},
		{"override mixing both anchors", 2, func(tp *tracingPolicy) {
			sel := &tp.Spec.LsmHooks[0].Selectors[selSSHBins]
			sel.MatchPIDs = tp.Spec.LsmHooks[0].Selectors[selSSHPids].MatchPIDs
		}},
		{"namespace pid in the pid anchor", 2, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHPids].MatchPIDs[0].IsNamespacePID = true
		}},
		{"pid 1 in the pid anchor", 2, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHPids].MatchPIDs[0].Values[0] = 1
		}},
		{"exemption follows children", 2, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selNoPost].MatchBinaries[0].FollowChildren = true
		}},
		// Rule 3: actions.
		{"sigkill", 3, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchActions = []tpAction{{Action: "Sigkill"}}
		}},
		{"signal", 3, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchActions = []tpAction{{Action: "Signal"}, {Action: "Post"}}
		}},
		{"override with another errno", 3, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchActions[0].ArgError = &five
		}},
		{"override without errno", 3, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchActions[0].ArgError = nil
		}},
		{"post with a global rate limit scope", 3, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchActions[1].RateLimitScope = "global"
		}},
		// Rule 4: paths an override never names.
		{"override on a provider credential", 4, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice/.aws/credentials"}
		}},
		{"override on gcloud", 4, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice/.config/gcloud/credentials.db"}
		}},
		{"override on the hook runtime", 4, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice/.defenseclaw/hooks/claude-code-hook.sh"}
		}},
		{"override on an agent state root", 4, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice/.claude/settings.json"}
		}},
		{"override on a repository file", 4, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice/CLAUDE.md"}
		}},
		{"override on .mcp.json", 4, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice/.mcp.json"}
		}},
		{"override under .git", 4, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice/.git/hooks/pre-commit"}
		}},
		// Rule 5: hooks.
		{"exec hook", 5, func(tp *tracingPolicy) { tp.Spec.LsmHooks[0].Hook = "bprm_check_security" }},
		{"another file hook", 5, func(tp *tracingPolicy) { tp.Spec.LsmHooks[0].Hook = "file_permission" }},
		{"kprobe with override", 5, func(tp *tracingPolicy) {
			tp.Spec.Kprobes = []tpKprobe{{Call: "tcp_connect", Args: []tpArg{{Index: 0, Type: "sock"}},
				Selectors: []tpSelector{tp.Spec.LsmHooks[0].Selectors[selSSHBins]}}}
		}},
		{"a syscall kprobe", 5, func(tp *tracingPolicy) {
			tp.Spec.Kprobes = []tpKprobe{{Call: "sys_execve", Syscall: true, Args: []tpArg{{Index: 0, Type: "string"}},
				Selectors: []tpSelector{{MatchActions: []tpAction{{Action: "Post"}}}}}}
		}},
		// Rule 6: paths.
		{"relative path", 6, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{".ssh/id_rsa"}
		}},
		{"dot-dot path", 6, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice/../bob/.ssh/id_rsa"}
		}},
		{"path outside every home", 6, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/root/.ssh/id_rsa"}
		}},
		{"the home itself", 6, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice"}
		}},
		{"exact path with a trailing slash", 6, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice/.ssh/id_rsa/"}
		}},
		{"prefix without a trailing slash", 6, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[1].Selectors[0].MatchArgs[0].Values = []string{"/home/alice/.config/autostart"}
		}},
		{"unclean path", 6, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice//.ssh/id_rsa"}
		}},
		{"substring operator", 6, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Operator = "SubString"
		}},
		{"relative binary", 6, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchBinaries[0].Values = []string{"claude"}
		}},
		{"binary of 256 bytes", 6, func(tp *tracingPolicy) {
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchBinaries[0].Values = []string{"/" + strings.Repeat("a", 255)}
		}},
		// Rule 7: counts and names.
		{"six selectors", 7, func(tp *tracingPolicy) {
			hook := &tp.Spec.LsmHooks[0]
			hook.Selectors = append(hook.Selectors, hook.Selectors[selSSHBins])
		}},
		{"sixty-five pids", 7, func(tp *tracingPolicy) {
			pids := make([]int, 65)
			for i := range pids {
				pids[i] = 9000 + i
			}
			tp.Spec.LsmHooks[0].Selectors[selSSHPids].MatchPIDs[0].Values = pids
		}},
		{"a foreign policy name", 7, func(tp *tracingPolicy) { tp.Metadata.Name = "someone-elses-policy" }},
		{"an uppercase policy name", 7, func(tp *tracingPolicy) { tp.Metadata.Name = "DefenseClaw-controls-abcdef12" }},
		{"too many values", 7, func(tp *tracingPolicy) {
			values := make([]string, maxValues+1)
			for i := range values {
				values[i] = "/home/alice/.ssh/id_rsa"
			}
			tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = values
		}},
		{"no selector", 7, func(tp *tracingPolicy) { tp.Spec.LsmHooks[1].Selectors = nil }},
		// Rule 8: the schema.
		{"wrong kind", 8, func(tp *tracingPolicy) { tp.Kind = "TracingPolicyNamespaced" }},
		{"unknown option", 8, func(tp *tracingPolicy) { tp.Spec.Options = []tpOption{{Name: "override-method", Value: "fmod-ret"}} }},
		{"a bad mode", 8, func(tp *tracingPolicy) { tp.Spec.Options = []tpOption{{Name: modeOption, Value: "sigkill"}} }},
		{"index outside the args", 8, func(tp *tracingPolicy) {
			sel := &tp.Spec.LsmHooks[0].Selectors[selSSHBins]
			sel.MatchArgs = append(sel.MatchArgs, tpMatchArg{Index: 9, Operator: "Equal", Values: []string{"1"}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tp, opts, _ := validControls(t)
			tc.mutate(&tp)
			// render adds the mode option unless told not to; the option cases
			// set their own.
			mode := PolicyEnforce
			if len(tp.Spec.Options) > 0 {
				mode = ""
			}
			data, err := render(FamilyControls, tp, mode)
			if err != nil {
				t.Fatal(err)
			}
			if v := Lint(data, opts); !hasRule(v, tc.rule) {
				t.Fatalf("violations = %v, want rule %d", v, tc.rule)
			}
		})
	}
}

func TestLintRule6SymlinkLeftInPath(t *testing.T) {
	tp, opts, w := validControls(t)
	w.fs.mkdir("/home/alice/elsewhere")
	w.fs.symlink("/home/alice/link", "elsewhere")
	tp.Spec.LsmHooks[0].Selectors[selSSHBins].MatchArgs[0].Values = []string{"/home/alice/link/id_rsa"}
	w.fs.file("/home/alice/elsewhere/id_rsa", 0o600)
	if v := lintTP(t, tp, opts); !hasRule(v, 6) {
		t.Fatalf("violations = %v, want rule 6 for a path with a symlink left in it", v)
	}
}

func TestLintRule8Text(t *testing.T) {
	tp, opts, _ := validControls(t)
	good, err := render(FamilyControls, tp, PolicyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"unknown field":    strings.Replace(string(good), "  - hook: file_open\n", "  - hook: file_open\n    returnArgAction: Post\n", 1),
		"extra document":   string(good) + "---\nkind: x\n",
		"reordered keys":   strings.Replace(string(good), "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\n", "kind: TracingPolicy\napiVersion: cilium.io/v1alpha1\n", 1),
		"not yaml":         "{{{",
		"trailing garbage": string(good) + "\n\nextra: 1\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if v := Lint([]byte(text), opts); !hasRule(v, 8) {
				t.Fatalf("violations = %v, want rule 8", v)
			}
		})
	}
	if v := Lint(good, opts); len(v) != 0 {
		t.Fatalf("the unmodified policy fails lint: %v", v)
	}
}

func TestLintObserveAndConnectAreClean(t *testing.T) {
	w := newWorld(t, baseTargets)
	c := w.compile(Input{Observe: true, Connect: true})
	opts := LintOptions{Homes: []string{"/home/alice", "/home/bob"}, FS: w.fs}
	for _, p := range c.Policies {
		if v := Lint(p.YAML, opts); len(v) != 0 {
			t.Errorf("%s: %v", p.Name, v)
		}
		if strings.Contains(string(p.YAML), "Override") || strings.Contains(string(p.YAML), "policy-mode") {
			t.Errorf("%s is post-only but carries an enforcement field", p.Name)
		}
	}
}

// A finding in a selector drops the selector; a finding in the exemption
// drops the policy, because removing the ssh exemption would widen a deny.
func TestFinalizeRepairNeverWidens(t *testing.T) {
	tp, opts, _ := validControls(t)
	tp.Metadata.Name = ""
	bad := cloneTP(t, tp)
	bad.Spec.LsmHooks[0].Selectors[selSSHPids].MatchPIDs[0].Values = make([]int, 65)
	for i := range bad.Spec.LsmHooks[0].Selectors[selSSHPids].MatchPIDs[0].Values {
		bad.Spec.LsmHooks[0].Selectors[selSSHPids].MatchPIDs[0].Values[i] = 9000 + i
	}
	policy, dropped, err := finalize(FamilyControls, PolicyEnforce, bad, Policy{}, opts)
	if err != nil || policy == nil {
		t.Fatalf("policy %v err %v dropped %v", policy, err, dropped)
	}
	if len(dropped) == 0 {
		t.Fatal("the removed selector was not reported")
	}
	if got := len(policy.tp.Spec.LsmHooks[0].Selectors); got != 4 {
		t.Fatalf("%d selectors left, want the one bad selector removed", got)
	}

	broken := cloneTP(t, tp)
	broken.Metadata.Name = ""
	broken.Spec.LsmHooks[0].Selectors[selNoPost].MatchBinaries[0].Values = []string{"relative"}
	if policy, dropped, _ := finalize(FamilyControls, PolicyEnforce, broken, Policy{}, opts); policy != nil {
		t.Fatalf("a broken exemption must drop the policy, got %v (%v)", policy.Name, dropped)
	}
}

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
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Violation is one lint finding. Hook and Selector are -1 when the finding
// is about the policy as a whole.
type Violation struct {
	Rule     int    `json:"rule"`
	Hook     int    `json:"hook"`
	Selector int    `json:"selector"`
	Message  string `json:"message"`
}

func (v Violation) String() string {
	where := "policy"
	if v.Hook >= 0 {
		where = fmt.Sprintf("hook %d", v.Hook)
		if v.Selector >= 0 {
			where += fmt.Sprintf(" selector %d", v.Selector)
		}
	}
	return fmt.Sprintf("rule %d (%s): %s", v.Rule, where, v.Message)
}

// LintOptions says what a path is allowed to be inside.
type LintOptions struct {
	// Homes are the enrolled users' resolved home directories.
	Homes []string
	// FS, when set, proves an existing path has no symlink left in it.
	FS FS
}

// systemPaths are the only paths outside a home a policy may name (the
// observe policy's system group).
var systemPaths = map[string]bool{"/etc/shadow": true, "/etc/sudoers.d/": true}

var dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// overrideForbiddenDirs and overrideForbiddenFiles are path fragments an
// Override selector must never name: the hook runtime, provider credentials
// (the agent's own authentication reads them), agent state roots and
// repository files.
var overrideForbiddenDirs = []string{
	"/.defenseclaw/", "/opt/defenseclaw/",
	"/.aws/", "/.config/gcloud/", "/.azure/", "/.kube/", "/.docker/", "/.config/anthropic/",
	"/.claude/", "/.codex/", "/.cursor/", "/.openclaw/", "/.zeptoclaw/", "/.config/github-copilot/",
	"/.git/",
}

var overrideForbiddenFiles = []string{"/claude.md", "/agents.md", "/.mcp.json", "/mcp.json"}

func isOverride(sel tpSelector) bool {
	for _, action := range sel.MatchActions {
		if action.Action == "Override" {
			return true
		}
	}
	return false
}

func isNoPost(sel tpSelector) bool {
	for _, action := range sel.MatchActions {
		if action.Action == "NoPost" {
			return true
		}
	}
	return false
}

// Lint checks rendered policy text against the design's rules (6.5):
//
//  1. no empty value list anywhere (Tetragon ignores an empty matchBinaries,
//     which would leave a selector scoped only by path and uid);
//  2. every Override selector carries a lineage anchor, a non-empty uid set
//     and the host pid namespace; an enforcing policy cannot use matchPIDs;
//  3. actions are only Post, NoPost and Override -EPERM;
//  4. no hook runtime, provider credential, agent state root or repository
//     path in an Override selector;
//  5. no exec hook, no kprobe Override, nothing but file_open and tcp_connect;
//  6. every path is absolute, clean, inside an enrolled home (or a listed
//     system path) and free of symlinks;
//  7. at most 5 selectors per hook, 64 pids per selector, DNS-1123 names,
//     bounded value lists, and at most 4 values in a numeric Equal list
//     (Tetragon refuses more; the uid list of a pid anchor uses InMap);
//  8. the text round-trips through the typed schema with unknown fields
//     refused.
//
// A finding is a refusal, never something the caller widens around.
func Lint(data []byte, opts LintOptions) []Violation {
	tp, err := decodePolicy(data)
	if err != nil {
		return []Violation{{Rule: 8, Hook: -1, Selector: -1, Message: "does not parse against the policy schema: " + err.Error()}}
	}
	var out []Violation
	add := func(rule, hook, selector int, format string, args ...any) {
		out = append(out, Violation{Rule: rule, Hook: hook, Selector: selector, Message: fmt.Sprintf(format, args...)})
	}

	// Rule 8: canonical text only.
	again, err := marshalPolicy(tp)
	if err != nil || !bytes.Equal(again, stripComments(data)) {
		add(8, -1, -1, "text is not the canonical rendering of its own parse")
	}
	if tp.APIVersion != apiVersion || tp.Kind != kindPolicy {
		add(8, -1, -1, "apiVersion/kind must be %s %s", apiVersion, kindPolicy)
	}
	// Rule 7: name.
	if len(tp.Metadata.Name) > 63 || !dns1123.MatchString(tp.Metadata.Name) || !IsDefenseClawName(tp.Metadata.Name) {
		add(7, -1, -1, "policy name %q is not a DefenseClaw DNS-1123 name", tp.Metadata.Name)
	}
	// Tetragon defaults a policy without policy-mode to enforcement. The
	// explicit monitor option is the only state that permits PID selectors.
	enforcing := true
	for _, option := range tp.Spec.Options {
		if option.Name == modeOption && option.Value == string(PolicyMonitor) {
			enforcing = false
		}
		if option.Name != modeOption || (option.Value != string(PolicyMonitor) && option.Value != string(PolicyEnforce)) {
			add(8, -1, -1, "option %q=%q is not allowed", option.Name, option.Value)
		}
	}
	if len(tp.Spec.LsmHooks)+len(tp.Spec.Kprobes) == 0 {
		add(7, -1, -1, "policy has no hook")
	}

	for h, hook := range tp.Spec.LsmHooks {
		// Rule 5: the only LSM hook is file_open. Exec hooks are never
		// rendered, with or without Override.
		if hook.Hook != "file_open" {
			add(5, h, -1, "LSM hook %q is not allowed", hook.Hook)
		}
		lintSelectors(h, hook.Args, hook.Selectors, true, enforcing, opts, add)
	}
	for k, probe := range tp.Spec.Kprobes {
		h := len(tp.Spec.LsmHooks) + k
		if probe.Call != "tcp_connect" || probe.Syscall {
			add(5, h, -1, "kprobe %q is not allowed", probe.Call)
		}
		lintSelectors(h, probe.Args, probe.Selectors, false, enforcing, opts, add)
	}
	return out
}

func lintSelectors(h int, args []tpArg, selectors []tpSelector, lsm, enforcing bool, opts LintOptions,
	add func(rule, hook, selector int, format string, args ...any)) {
	if len(selectors) == 0 {
		add(7, h, -1, "hook has no selector")
	}
	if len(selectors) > MaxSelectors {
		add(7, h, -1, "%d selectors; Tetragon accepts %d per hook", len(selectors), MaxSelectors)
	}
	uidIndex := -1
	pathIndex := -1
	for i, arg := range args {
		if arg.Resolve == "f_cred.uid.val" {
			uidIndex = i
		}
		if arg.Type == "file" && arg.Resolve == "" && pathIndex < 0 {
			pathIndex = i
		}
	}
	for s, sel := range selectors {
		override, noPost := isOverride(sel), isNoPost(sel)
		if !lsm && override {
			add(5, h, s, "a kprobe selector must not carry Override")
		}
		// Rule 3: actions.
		for _, action := range sel.MatchActions {
			switch action.Action {
			case "Post":
				if action.ArgError != nil || (action.RateLimitScope != "" && action.RateLimitScope != "process") {
					add(3, h, s, "Post carries an unexpected parameter")
				}
			case "NoPost":
			case "Override":
				if action.ArgError == nil || *action.ArgError != eperm {
					add(3, h, s, "Override must return -EPERM (argError -1)")
				}
			default:
				add(3, h, s, "action %q is not allowed (only Post, NoPost, Override)", action.Action)
			}
		}
		// Rule 1: empty lists, anywhere.
		for _, binaries := range sel.MatchBinaries {
			if len(binaries.Values) == 0 {
				add(1, h, s, "matchBinaries has no value")
			}
			if len(binaries.Values) > maxValues {
				add(7, h, s, "matchBinaries has %d values", len(binaries.Values))
			}
			for _, value := range binaries.Values {
				if len(value) > maxBinaryLen || !path.IsAbs(value) || path.Clean(value) != value {
					add(6, h, s, "binary %q is not a clean absolute path under %d bytes", value, maxBinaryLen)
				}
			}
		}
		if len(sel.MatchBinaries) > 1 {
			add(7, h, s, "Tetragon accepts one matchBinaries entry per selector")
		}
		if enforcing && len(sel.MatchPIDs) > 0 {
			add(2, h, s, "enforcing policy cannot use a reusable numeric pid anchor")
		}
		for _, pids := range sel.MatchPIDs {
			if len(pids.Values) == 0 {
				add(1, h, s, "matchPIDs has no value")
			}
			if len(pids.Values) > maxPIDsPerSelector {
				add(7, h, s, "matchPIDs has %d values (effective limit %d)", len(pids.Values), maxPIDsPerSelector)
			}
			for _, pid := range pids.Values {
				if pid <= 1 {
					add(2, h, s, "matchPIDs names pid %d", pid)
				}
			}
			if pids.IsNamespacePID {
				add(2, h, s, "matchPIDs must use host pids")
			}
		}
		hostNS := false
		for _, ns := range sel.MatchNamespaces {
			if len(ns.Values) == 0 {
				add(1, h, s, "matchNamespaces has no value")
			}
			if ns.Namespace == "Pid" && ns.Operator == "In" && len(ns.Values) == 1 && ns.Values[0] == hostNamespace {
				hostNS = true
			}
		}
		uidValues := 0
		for _, arg := range sel.MatchArgs {
			at := arg.position()
			if len(arg.Values) == 0 {
				add(1, h, s, "matchArgs args %v has no value", arg.Args)
			}
			if len(arg.Values) > maxValues {
				add(7, h, s, "matchArgs args %v has %d values", arg.Args, len(arg.Values))
			}
			if at < 0 || at >= len(args) {
				add(8, h, s, "matchArgs args %v does not name one of the hook's %d args", arg.Args, len(args))
				continue
			}
			if numericArg(args[at]) && !mapOperator(arg.Operator) && len(arg.Values) > maxNumericValues {
				add(7, h, s, "matchArgs args %v has %d values for %s; Tetragon accepts %d on a number (use InMap)",
					arg.Args, len(arg.Values), arg.Operator, maxNumericValues)
			}
			if at == uidIndex && (arg.Operator == "Equal" || arg.Operator == "InMap") {
				uidValues += len(arg.Values)
			}
			if at == pathIndex {
				lintPaths(h, s, arg, override, opts, add)
			}
		}
		if lsm && pathIndex < 0 {
			add(8, h, -1, "hook has no file argument")
		}
		// Rule 2: an Override selector is scoped to an enrolled lineage.
		if override {
			lineage := false
			for _, binaries := range sel.MatchBinaries {
				if binaries.FollowChildren && binaries.Operator == "In" && len(binaries.Values) > 0 {
					lineage = true
				}
			}
			for _, pids := range sel.MatchPIDs {
				if pids.FollowForks && pids.Operator == "In" && len(pids.Values) > 0 {
					lineage = true
				}
			}
			if !lineage {
				add(2, h, s, "Override selector has no lineage anchor")
			}
			if !hostNS {
				add(2, h, s, "Override selector is not restricted to the host pid namespace")
			}
			if uidValues == 0 {
				add(2, h, s, "Override selector has no uid condition")
			}
			if len(sel.MatchBinaries) > 0 && len(sel.MatchPIDs) > 0 {
				add(2, h, s, "Override selector mixes the binaries and pid anchors (they are alternatives)")
			}
		}
		if noPost {
			if len(sel.MatchBinaries) == 0 || len(sel.MatchArgs) == 0 {
				add(1, h, s, "NoPost exemption needs binaries and a path")
			}
			for _, binaries := range sel.MatchBinaries {
				if binaries.FollowChildren {
					add(2, h, s, "a NoPost exemption must not follow children")
				}
			}
		}
	}
}

// numericArg reports whether a hook argument is a number, which Tetragon
// matches from values written into the selector itself.
func numericArg(arg tpArg) bool {
	return strings.HasPrefix(arg.Type, "int") || strings.HasPrefix(arg.Type, "uint") ||
		arg.Type == "size_t" || arg.Type == "syscall64"
}

// mapOperator reports whether an operator keeps its values in a BPF map.
func mapOperator(operator string) bool {
	return operator == "InMap" || operator == "NotInMap"
}

func lintPaths(h, s int, arg tpMatchArg, override bool, opts LintOptions,
	add func(rule, hook, selector int, format string, args ...any)) {
	if arg.Operator != "Equal" && arg.Operator != "Prefix" {
		add(6, h, s, "path operator %q is not Equal or Prefix", arg.Operator)
	}
	for _, value := range arg.Values {
		trimmed := strings.TrimSuffix(value, "/")
		switch {
		case len(value) > maxPathLen || strings.ContainsRune(value, 0):
			add(6, h, s, "path %q is too long or contains NUL", value)
			continue
		case !path.IsAbs(value) || trimmed == "" || path.Clean(trimmed) != trimmed:
			add(6, h, s, "path %q is not absolute and clean", value)
			continue
		case arg.Operator == "Prefix" && !strings.HasSuffix(value, "/"):
			add(6, h, s, "prefix %q is not a directory with a trailing slash", value)
			continue
		case arg.Operator == "Equal" && strings.HasSuffix(value, "/"):
			add(6, h, s, "exact path %q ends with a slash", value)
			continue
		}
		allowed := systemPaths[value]
		for _, home := range opts.Homes {
			if inside(home, trimmed) && trimmed != strings.TrimSuffix(home, "/") {
				allowed = true
			}
		}
		if !allowed {
			add(6, h, s, "path %q is outside every enrolled home", value)
		}
		if opts.FS != nil {
			if real, err := opts.FS.EvalSymlinks(trimmed); err == nil && real != trimmed {
				add(6, h, s, "path %q resolves to %q; a symlink is left in it", value, real)
			}
		}
		if override {
			if fragment := forbiddenOverride(value); fragment != "" {
				add(4, h, s, "Override selector names %q (%s)", value, strings.Trim(fragment, "/"))
			}
		}
	}
}

// forbiddenOverride returns the forbidden fragment value contains, or "".
func forbiddenOverride(value string) string {
	lower := strings.ToLower(value)
	withSlash := lower
	if !strings.HasSuffix(withSlash, "/") {
		withSlash += "/"
	}
	for _, fragment := range overrideForbiddenDirs {
		if strings.Contains(withSlash, fragment) {
			return fragment
		}
	}
	for _, fragment := range overrideForbiddenFiles {
		if strings.Contains(lower, fragment) {
			return fragment
		}
	}
	return ""
}

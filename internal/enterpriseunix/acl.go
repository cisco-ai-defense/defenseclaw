// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// macOS keeps the owner and the mode bits of a path when an access control
// list entry is added (chmod +a), and the owner and mode checks of status,
// verify and repair read only those. A write entry for a standard user on
// the hook binary, bin/, a LaunchDaemon plist or the Claude Code drop-in let
// that user replace what root and every agent run while verify and repair
// stayed green and left the entry in place; only config.yaml was checked, by
// the gateway (GAP-0946). The lifecycle writes no ACL entries, so status and
// verify name every entry that lets another account change a file or folder
// the deployment installs, and every transaction (repair, ensure, the
// package postinstall ensure --from-package) removes them with chmod -N
// before it writes anything. Linux needs no twin: a named POSIX ACL entry
// shows in the group mode bits (the ACL mask), which the mode checks compare
// and chmod resets.

// aclListBatch bounds the paths of one ls call.
const aclListBatch = 200

// aclTarget is a rooted path whose macOS ACL the deployment checks.
type aclTarget struct {
	path string
}

// aclFinding is a path with the ACL entries that are wrong for it.
type aclFinding struct {
	path    string // canonical
	rooted  string
	entries []string
}

// aclTargets are the folders of the deployment, the files it installs
// (binaries, LaunchDaemon plists, config.yaml, the runtime descriptor) and
// the vendor machine-policy files and folders of the connectors whose hooks
// it publishes there. files are canonical paths.
func (e *Env) aclTargets(files, connectors []string) []aclTarget {
	if e.GOOS != "darwin" {
		return nil
	}
	seen := map[string]bool{}
	var targets []aclTarget
	add := func(rooted string) {
		if seen[rooted] {
			return
		}
		info, err := os.Lstat(rooted)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return
		}
		seen[rooted] = true
		targets = append(targets, aclTarget{path: rooted})
	}
	for _, dir := range e.managedDirs(Account{}, false) {
		if !dir.External {
			add(e.P(dir.Path))
		}
	}
	for _, file := range files {
		add(e.P(file))
	}
	for _, path := range e.machinePolicyACLPaths(connectors) {
		add(path)
	}
	return targets
}

// machinePolicyACLPaths are the rooted vendor machine-policy folders and
// files of connectors: the hooks agents load from there run for every user.
func (e *Env) machinePolicyACLPaths(connectors []string) []string {
	opts := enterprisepolicy.LayoutOptions(e.Layout, "", "")
	opts.GOOS, opts.Root = e.GOOS, e.Root
	var paths []string
	for _, name := range connectors {
		for _, dir := range machinePolicyDirs(e.GOOS, name) {
			paths = append(paths, e.P(dir))
		}
		if target, ok := enterprisepolicy.TargetFor(name); ok {
			if files, err := target.Paths(opts); err == nil {
				paths = append(paths, files...)
			}
		}
	}
	return paths
}

// aclFindings lists the targets with ACL entries that let another account
// change them. A path that went away before ls read it is skipped.
func (e *Env) aclFindings(ctx context.Context, targets []aclTarget) ([]aclFinding, error) {
	var findings []aclFinding
	var failure error
	for start := 0; start < len(targets); start += aclListBatch {
		batch := targets[start:min(start+aclListBatch, len(targets))]
		paths := make([]string, len(batch))
		for i, target := range batch {
			paths[i] = target.path
		}
		result, err := e.Runner.Run(ctx, "ls", append([]string{"-lde", "--"}, paths...)...)
		if err != nil && len(result.Stdout) == 0 {
			failure = err
			continue
		}
		listed, err := managed.ParseDarwinACLListing(string(result.Stdout), paths)
		if err != nil {
			failure = err
			continue
		}
		for _, target := range batch {
			var wrong []string
			for _, entry := range listed[target.path] {
				if entry.GrantsWrite() {
					wrong = append(wrong, entry.Text)
				}
			}
			if len(wrong) > 0 {
				findings = append(findings, aclFinding{path: e.canonical(target.path), rooted: target.path, entries: wrong})
			}
		}
	}
	return findings, failure
}

// canonical strips the test root from a rooted path.
func (e *Env) canonical(rooted string) string {
	if e.Root == "" {
		return rooted
	}
	return strings.TrimPrefix(rooted, e.Root)
}

// aclProblems are the status and verify problems of the deployment ACLs.
func (e *Env) aclProblems(ctx context.Context, record *Deployment) []string {
	findings, err := e.aclFindings(ctx, e.aclTargets(sortedKeys(record.Files), record.MachinePolicyConnectors))
	var problems []string
	if err != nil && e.Geteuid() == 0 {
		problems = append(problems, fmt.Sprintf("the macOS ACLs of the deployment could not be read (%v), so entries that let other accounts change it are not checked", err))
	}
	if len(findings) > 0 {
		problems = append(problems, fmt.Sprintf(
			"macOS ACL entries let other accounts change DefenseClaw files and folders that root and every agent rely on, although their owner and mode bits do not: %s; run `%s` to remove them (it runs chmod -N on each path)",
			describeACLFindings(findings), e.lifecycleCommand(ActionRepair)))
	}
	return problems
}

// describeACLFindings names every path, grouped by entry.
func describeACLFindings(findings []aclFinding) string {
	byEntry := map[string][]string{}
	for _, finding := range findings {
		for _, entry := range finding.entries {
			byEntry[entry] = append(byEntry[entry], finding.path)
		}
	}
	entries := make([]string, 0, len(byEntry))
	for entry := range byEntry {
		entries = append(entries, entry)
	}
	sort.Strings(entries)
	parts := make([]string, 0, len(entries))
	for _, entry := range entries {
		parts = append(parts, fmt.Sprintf("%q on %s", entry, strings.Join(byEntry[entry], ", ")))
	}
	return strings.Join(parts, "; ")
}

// removeACLs removes the macOS ACL of every target with an entry that lets
// another account change it. chmod -h never follows a link put in place of a
// path after it was listed.
func (l *lifecycle) removeACLs(ctx context.Context, files, connectors []string) error {
	env := l.env
	findings, err := env.aclFindings(ctx, env.aclTargets(files, connectors))
	if err != nil {
		return fmt.Errorf("read the macOS ACLs of the deployment: %w", err)
	}
	var removed []string
	for _, finding := range findings {
		if _, err := env.Runner.Run(ctx, "chmod", "-h", "-N", finding.rooted); err != nil {
			return fmt.Errorf("remove the macOS ACL of %s: %w; remove it with `chmod -N %s`, then rerun `%s`",
				finding.path, err, finding.path, env.lifecycleCommand(l.opts.Action))
		}
		removed = append(removed, finding.path)
	}
	if len(removed) > 0 {
		l.noteChange("removed the macOS ACL entries that let other accounts change %d %s (%s)", len(removed), plural(len(removed), "path", "paths"), examples(removed))
	}
	return nil
}

// planFiles are the canonical paths of the files a plan installs.
func planFiles(p *plan) []string {
	files := make([]string, 0, len(p.files)+len(p.binaries))
	for _, file := range append(append([]desiredFile{}, p.files...), p.binaries...) {
		files = append(files, file.Path)
	}
	return files
}

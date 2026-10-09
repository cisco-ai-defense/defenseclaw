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
	"io/fs"
	"os"
	"path/filepath"
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
// before it writes anything. A recursive read entry for a group of standard
// users on the install root let every user read runtime/device.key,
// runtime/.env and the lifecycle record while status and verify stayed green
// (GAP-0950): on a private path (one whose mode gives other accounts no
// access: the gateway data, the guardian records, the credentials, the
// lifecycle state, config.yaml) any allow entry is reported and removed, and
// every entry of those folders is checked. Linux needs no twin: a named POSIX ACL entry
// shows in the group mode bits (the ACL mask), which the mode checks compare
// and chmod resets.

// aclListBatch bounds the paths of one ls call.
const aclListBatch = 200

// aclTarget is a rooted path whose macOS ACL the deployment checks. On a
// private one any allow entry is wrong; on a published directory a deny
// entry that hides policy is also wrong; elsewhere an entry that grants write.
type aclTarget struct {
	path         string
	private      bool
	publishedDir bool
	requireList  bool
}

// aclFinding is a path with the ACL entries that are wrong for it; write is
// set when one of them grants write.
type aclFinding struct {
	path    string // canonical
	rooted  string
	entries []string
	write   bool
	deny    bool
}

// aclTargets are the folders of the deployment, the files it installs
// (binaries, LaunchDaemon plists, config.yaml, the runtime descriptor) and
// the vendor machine-policy files and folders of the connectors whose hooks
// it publishes there, every entry of the private folders and the files next
// to config.yaml. files are canonical paths.
func (e *Env) aclTargets(files, connectors []string) []aclTarget {
	if e.GOOS != "darwin" {
		return nil
	}
	seen := map[string]bool{}
	publishedDirs := map[string]bool{}
	for _, connector := range connectors {
		for _, dir := range machinePolicyDirs(e.GOOS, connector) {
			publishedDirs[e.P(dir)] = true
		}
	}
	var targets []aclTarget
	// private is nil to take it from the current mode.
	add := func(rooted string, private *bool) {
		if seen[rooted] {
			return
		}
		info, err := os.Lstat(rooted)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return
		}
		seen[rooted] = true
		closed := info.Mode().Perm()&0o007 == 0
		if private != nil {
			closed = *private
		}
		targets = append(targets, aclTarget{
			path: rooted, private: closed, publishedDir: info.IsDir() && publishedDirs[rooted],
			requireList: filepath.Base(rooted) == "managed-settings.d" || filepath.Base(rooted) == "policy.d",
		})
	}
	yes := true
	for _, dir := range e.managedDirs(Account{}, false) {
		if !dir.External {
			closed := dir.Mode&0o007 == 0
			add(e.P(dir.Path), &closed)
		}
	}
	for _, file := range files {
		add(e.P(file), nil)
	}
	for _, path := range e.machinePolicyACLPaths(connectors) {
		add(path, nil)
	}
	for _, dir := range []string{e.Layout.DataDir, filepath.Dir(e.Layout.ManifestPath), e.Layout.GuardianAuthDir, e.Layout.SecretsDir, e.Layout.LifecycleDir} {
		root := e.P(dir)
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || writerTemporary(d.Name()) {
				return nil
			}
			add(path, &yes)
			if d.IsDir() && path != root && strings.Count(strings.TrimPrefix(path, root), string(filepath.Separator)) >= maxStateDepth {
				return fs.SkipDir
			}
			return nil
		})
	}
	// A nested vendor pack can gain an ACL without changing its mode bits.
	// Include every installed entry, not just the top-level managed folders.
	_ = filepath.WalkDir(e.P(e.Layout.VendorPolicyDir), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		add(path, nil)
		return nil
	})
	for _, file := range e.configStateFiles(Account{}) {
		add(e.P(file.path), &yes)
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
// change them, or reach them when they are private. A path that went away
// before ls read it is skipped.
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
			finding := aclFinding{path: e.canonical(target.path), rooted: target.path}
			for _, entry := range listed[target.path] {
				deny := target.publishedDir && entry.DeniesDirectoryAccess(target.requireList)
				if entry.GrantsWrite() || (target.private && entry.GrantsAccess()) || deny {
					finding.entries = append(finding.entries, entry.Text)
					finding.write = finding.write || entry.GrantsWrite()
					finding.deny = finding.deny || deny
				}
			}
			if len(finding.entries) > 0 {
				findings = append(findings, finding)
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
		problems = append(problems, fmt.Sprintf("the macOS ACLs of the deployment could not be read (%v), so entries that grant write or deny policy access are not checked", err))
	}
	var write, read, deny []aclFinding
	for _, finding := range findings {
		if finding.write {
			write = append(write, finding)
		}
		if finding.deny {
			deny = append(deny, finding)
		}
		if !finding.write && !finding.deny {
			read = append(read, finding)
		}
	}
	if len(write) > 0 {
		problems = append(problems, fmt.Sprintf(
			"macOS ACL entries let other accounts change DefenseClaw files and folders that root and every agent rely on, although their owner and mode bits do not: %s; run `%s` to remove them (it runs chmod -N on each path)",
			describeACLFindings(write), e.lifecycleCommand(ActionRepair)))
	}
	if len(deny) > 0 {
		problems = append(problems, fmt.Sprintf(
			"macOS ACL entries deny users access to published machine-policy directories, so their agents cannot load DefenseClaw hooks: %s; run `%s` to remove them",
			describeACLFindings(deny), e.lifecycleCommand(ActionRepair)))
	}
	if len(read) > 0 {
		problems = append(problems, fmt.Sprintf(
			"macOS ACL entries let other accounts read private DefenseClaw files and folders (the device key, credentials, audit store and lifecycle state) that their owner and mode bits keep from them: %s; run `%s` to remove them (it runs chmod -N on each path)",
			describeACLFindings(read), e.lifecycleCommand(ActionRepair)))
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
// another account change it, or reach it when it is private. chmod -h never
// follows a link put in place of a path after it was listed. An entry still
// listed afterwards fails the transaction with the paths, so a repair never
// reports success while verify keeps naming them (GAP-0946).
func (l *lifecycle) removeACLs(ctx context.Context, files, connectors []string) error {
	env := l.env
	targets := env.aclTargets(files, connectors)
	findings, err := env.aclFindings(ctx, targets)
	if err != nil {
		return fmt.Errorf("read the macOS ACLs of the deployment: %w", err)
	}
	if len(findings) == 0 {
		return nil
	}
	var removed []string
	for _, finding := range findings {
		if _, err := env.Runner.Run(ctx, "chmod", "-h", "-N", finding.rooted); err != nil {
			return fmt.Errorf("remove the macOS ACL of %s: %w; remove it with `chmod -N %s`, then rerun `%s`",
				finding.path, err, finding.path, env.lifecycleCommand(l.opts.Action))
		}
		removed = append(removed, finding.path)
	}
	left, err := env.aclFindings(ctx, targets)
	if err != nil {
		return fmt.Errorf("read the macOS ACLs of the deployment after removing them: %w", err)
	}
	if len(left) > 0 {
		return fmt.Errorf("harmful macOS ACL entries are still there after chmod -N: %s; remove them with `chmod -N <path>`, then rerun `%s`",
			describeACLFindings(left), env.lifecycleCommand(l.opts.Action))
	}
	l.noteChange("removed harmful macOS ACL entries from %d %s (%s)", len(removed), plural(len(removed), "path", "paths"), examples(removed))
	return nil
}

// aclFiles are the canonical files whose ACLs a transaction clears: what the
// plan installs, the binaries it runs, and every file of the deployment
// record, which is what status and verify check. The package channel plans
// no binaries (the package placed them), so the hook and gateway binaries
// kept a write entry through repair while verify kept naming them
// (GAP-0946).
func aclFiles(env *Env, p *plan, record *Deployment) []string {
	files := make([]string, 0, len(p.files)+len(p.binaries))
	for _, file := range append(append([]desiredFile{}, p.files...), p.binaries...) {
		files = append(files, file.Path)
	}
	if p.payload != nil {
		for _, name := range sortedKeys(p.payload.Digests) {
			files = append(files, filepath.Join(env.Layout.BinDir, name))
		}
	}
	if record != nil {
		files = append(files, sortedKeys(record.Files)...)
	}
	return files
}

// aclConnectors are the connectors whose machine-policy files a transaction
// clears: the ones the config asks for and the ones the record names.
func aclConnectors(p *plan, record *Deployment) []string {
	connectors := append([]string{}, p.intended...)
	if record != nil {
		connectors = append(connectors, record.MachinePolicyConnectors...)
	}
	return connectors
}

// jsonlACLProblem checks a custom output file, which is outside the
// deployment's managed trees. Its mode is private even in a traversable log
// directory, so any allow ACL entry grants access the mode excludes.
func (e *Env) jsonlACLProblem(ctx context.Context, path string) (string, error) {
	if e.GOOS != "darwin" {
		return "", nil
	}
	info, err := os.Lstat(e.P(path))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", nil
	}
	findings, err := e.aclFindings(ctx, []aclTarget{{path: e.P(path), private: true}})
	if err != nil {
		return "", err
	}
	if len(findings) > 0 {
		return fmt.Sprintf("has a macOS ACL entry that lets another account read or write the JSONL output: %s; remove it with `chmod -N %s`", describeACLFindings(findings), path), nil
	}
	return "", nil
}

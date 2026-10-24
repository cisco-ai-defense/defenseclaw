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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
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
// every entry of those folders is checked. The folders above a vendor
// machine-policy folder (/Library/Application Support, /private/etc, up to /)
// are checked too: the machine-policy trust check reads only their owner and
// mode, and an entry that lets a standard user add or delete a child there
// let that user put another folder, with a policy without DefenseClaw hooks,
// in place of the one ensure protected (GAP-1458). DefenseClaw does not change
// system folders, so a transaction refuses them instead of removing the
// entries. Linux needs no twin: a named POSIX ACL entry
// shows in the group mode bits (the ACL mask), which the mode checks compare
// and chmod resets.

// aclListBatch bounds the paths of one ls call.
const aclListBatch = 200

// aclTarget is a rooted path whose macOS ACL the deployment checks. On a
// private one any allow entry is wrong; on a published directory a deny
// entry that hides policy is also wrong; on a published policy file a deny-read
// entry is wrong; on a folder above a vendor machine-policy folder an entry
// that grants write to an account other than root or an administrator group;
// elsewhere an entry that grants write.
type aclTarget struct {
	path          string
	private       bool
	publishedDir  bool
	publishedFile bool
	gatewayRead   bool
	requireList   bool
	ancestor      bool
}

// aclFinding is a path with the ACL entries that are wrong for it; write is
// set when one of them grants write; ancestor when the path is a folder above
// a vendor machine-policy folder.
type aclFinding struct {
	path     string // canonical
	rooted   string
	entries  []string
	write    bool
	deny     bool
	ancestor bool
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
	policyPaths := e.machinePolicyACLPaths(connectors)
	published := make(map[string]bool, len(policyPaths))
	for _, path := range policyPaths {
		published[path] = true
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
			path: rooted, private: closed,
			publishedDir: info.IsDir() && published[rooted], publishedFile: info.Mode().IsRegular() && published[rooted],
			gatewayRead: rooted == e.P(e.Layout.ConfigPath) || rooted == e.P(e.Layout.ConfigDir),
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
	for _, path := range policyPaths {
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
	// The public bundle parent is traversable; its other children still need
	// their own protection even if an ACL grants read despite their mode bits.
	bundles := e.P(filepath.Join(e.Layout.ConfigDir, "bundles"))
	events := filepath.Join(bundles, enterprisestatus.PublicReceiptEventsDirName)
	_ = filepath.WalkDir(bundles, func(path string, d fs.DirEntry, err error) error {
		if err != nil || writerTemporary(d.Name()) {
			return nil
		}
		if path == events && d.IsDir() {
			return fs.SkipDir
		}
		if path != bundles && path != filepath.Join(bundles, enterprisestatus.PublicReceiptName) {
			add(path, &yes)
		}
		return nil
	})
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
	// Last, so a folder the deployment also installs keeps its stricter check.
	for _, dir := range e.machinePolicyAncestors(policyPaths) {
		if seen[dir] {
			continue
		}
		if info, err := os.Lstat(dir); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			seen[dir] = true
			targets = append(targets, aclTarget{path: dir, ancestor: true})
		}
	}
	return targets
}

// machinePolicyAncestors are the folders above the rooted vendor
// machine-policy paths, up to / (or the test root). /etc, /var and /tmp are
// links to /private on macOS, so the folders of their targets are the ones
// checked, as the machine-policy trust check walks them.
func (e *Env) machinePolicyAncestors(policyPaths []string) []string {
	stop := "/"
	if e.Root != "" {
		stop = filepath.Clean(e.Root)
	}
	var dirs []string
	for _, path := range policyPaths {
		if e.Root == "" {
			for _, prefix := range []string{"/etc/", "/var/", "/tmp/"} {
				if strings.HasPrefix(path, prefix) {
					path = "/private" + path
				}
			}
		}
		for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
			dirs = append(dirs, dir)
			if dir == stop || dir == filepath.Dir(dir) {
				break
			}
		}
	}
	return dirs
}

// darwinACLAdminPrincipal reports an entry for root or an administrator
// group (wheel, admin); any other account, or one ls could not name, is not
// trusted with write on a folder above a vendor machine-policy folder.
func darwinACLAdminPrincipal(entry managed.DarwinACLEntry) bool {
	fields := strings.Fields(strings.ToLower(entry.Text))
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "user:root", "group:wheel", "group:admin":
		return true
	}
	return false
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
			entries, ok := listed[target.path]
			if !ok && target.ancestor {
				// Fail closed: an unread folder above a policy folder is not trusted.
				failure = fmt.Errorf("ls did not list the ACL of %s", target.path)
				continue
			}
			finding := aclFinding{path: e.canonical(target.path), rooted: target.path, ancestor: target.ancestor}
			for _, entry := range entries {
				if target.ancestor {
					if entry.GrantsWrite() && !darwinACLAdminPrincipal(entry) {
						finding.entries = append(finding.entries, entry.Text)
						finding.write = true
					}
					continue
				}
				deny := ((target.publishedDir || target.gatewayRead) && entry.DeniesDirectoryAccess(target.requireList)) ||
					((target.publishedFile || target.gatewayRead) && entry.DeniesFileRead())
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
	var write, read, deny, ancestors []aclFinding
	for _, finding := range findings {
		if finding.ancestor {
			ancestors = append(ancestors, finding)
			continue
		}
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
	if len(ancestors) > 0 {
		problems = append(problems, ancestorACLProblem(ancestors, e.lifecycleCommand(ActionRepair)))
	}
	if len(write) > 0 {
		problems = append(problems, fmt.Sprintf(
			"macOS ACL entries let other accounts change DefenseClaw files and folders that root and every agent rely on, although their owner and mode bits do not: %s; run `%s` to remove them (it runs chmod -N on each path)",
			describeACLFindings(write), e.lifecycleCommand(ActionRepair)))
	}
	if len(deny) > 0 {
		problems = append(problems, fmt.Sprintf(
			"macOS ACL entries deny users access to published machine-policy directories or files, so their agents cannot load DefenseClaw hooks: %s; run `%s` to remove them",
			describeACLFindings(deny), e.lifecycleCommand(ActionRepair)))
	}
	if len(read) > 0 {
		problems = append(problems, fmt.Sprintf(
			"macOS ACL entries let other accounts read private DefenseClaw files and folders (the device key, credentials, audit store and lifecycle state) that their owner and mode bits keep from them: %s; run `%s` to remove them (it runs chmod -N on each path)",
			describeACLFindings(read), e.lifecycleCommand(ActionRepair)))
	}
	return problems
}

// ancestorACLProblem names the entries that let a standard account change a
// folder above a vendor machine-policy folder; the administrator removes
// them, since DefenseClaw does not change system folders.
func ancestorACLProblem(findings []aclFinding, rerun string) string {
	return fmt.Sprintf(
		"macOS ACL entries let accounts other than root and administrators add or delete folders above the vendor machine-policy folders, so they could put a policy without DefenseClaw hooks in place of the published one: %s; remove those entries with `chmod -a \"<entry>\" <folder>` (DefenseClaw does not change system folders), then run `%s`",
		describeACLFindings(findings), rerun)
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
	return l.removeACLTargets(ctx, l.env.aclTargets(files, connectors))
}

// removeConfigACLs removes macOS ACL entries that let another account write
// the config or prevent the gateway from reading it or traversing its folder.
// replaceWritableConfig runs it before reading and replacing the file.
func (l *lifecycle) removeConfigACLs(ctx context.Context) error {
	env := l.env
	if env.GOOS != "darwin" {
		return nil
	}
	var targets []aclTarget
	for _, canonical := range []string{filepath.Dir(env.Layout.ConfigPath), env.Layout.ConfigPath} {
		if info, err := os.Lstat(env.P(canonical)); err == nil && info.Mode()&os.ModeSymlink == 0 {
			targets = append(targets, aclTarget{path: env.P(canonical), gatewayRead: true})
		}
	}
	return l.removeACLTargets(ctx, targets)
}

func (l *lifecycle) removeACLTargets(ctx context.Context, targets []aclTarget) error {
	env := l.env
	findings, err := env.aclFindings(ctx, targets)
	// Set before anything below can fail: a run that stops before chmod -N
	// cleared config.yaml (or could not list its ACL) must not keep bytes
	// written through the entry as a newer config (GAP-1518, GAP-1535).
	if err != nil && env.GOOS == "darwin" {
		l.configACLWritable = true
	}
	for _, finding := range findings {
		if finding.write && finding.path == env.Layout.ConfigPath {
			l.configACLWritable = true
		}
	}
	if err != nil {
		return fmt.Errorf("read the macOS ACLs of the deployment: %w", err)
	}
	if len(findings) == 0 {
		return nil
	}
	var ancestors []aclFinding
	for _, finding := range findings {
		if finding.ancestor {
			ancestors = append(ancestors, finding)
		}
	}
	if len(ancestors) > 0 {
		return errors.New(ancestorACLProblem(ancestors, env.lifecycleCommand(l.opts.Action)))
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

// darwinServiceACLDenial returns the first rooted path, of paths, whose
// macOS ACL denies the gateway service account one of the rights its entry
// in rights lists, with the denying entry. The owner and mode checks pass
// such a path, and the gateway failed only when it started (GAP-1414,
// GAP-1442). macOS reads the entries in order and the first applicable
// entry that names a right decides it, so an earlier allow wins over a
// later deny. An entry applies to the service account when it names the
// account, its group or everyone, or a principal ls could not name; the
// service account has no other groups. Inherit-only entries do not apply to
// the path itself. Every path must exist: an ls error, or a path ls did not
// list, is an error, never a pass. It does nothing off macOS.
func (e *Env) darwinServiceACLDenial(ctx context.Context, paths []string, rights map[string][]string) (string, string, error) {
	if e.GOOS != "darwin" || len(paths) == 0 {
		return "", "", nil
	}
	for start := 0; start < len(paths); start += aclListBatch {
		batch := paths[start:min(start+aclListBatch, len(paths))]
		result, err := e.Runner.Run(ctx, "ls", append([]string{"-lde", "--"}, batch...)...)
		if err != nil {
			return "", "", err
		}
		listed, err := managed.ParseDarwinACLListing(string(result.Stdout), batch)
		if err != nil {
			return "", "", err
		}
		for _, path := range batch {
			entries, ok := listed[path]
			if !ok {
				return "", "", fmt.Errorf("ls did not list the ACL of %s", e.canonical(path))
			}
			if entry, denied := e.darwinACLDeniesService(entries, rights[path]); denied {
				return path, entry, nil
			}
		}
	}
	return "", "", nil
}

// darwinACLDeniesService reports the entry, of entries in ACL order, that
// denies the gateway service account one of rights: for each right the
// first applicable entry naming it decides.
func (e *Env) darwinACLDeniesService(entries []managed.DarwinACLEntry, rights []string) (string, bool) {
	for _, right := range rights {
		for _, entry := range entries {
			if !e.darwinACLAppliesToService(entry) || !slices.Contains(entry.Rights, right) {
				continue
			}
			if !entry.Allow {
				return entry.Text, true
			}
			break
		}
	}
	return "", false
}

// darwinACLAppliesToService reports an entry that governs the path itself
// for the gateway service account.
func (e *Env) darwinACLAppliesToService(entry managed.DarwinACLEntry) bool {
	if slices.Contains(entry.Rights, "only_inherit") {
		return false
	}
	principal := ""
	if fields := strings.Fields(strings.ToLower(entry.Text)); len(fields) > 0 {
		principal = fields[0]
	}
	// A principal ls printed as a number (it could not name it) applies:
	// fail closed.
	kind, name, _ := strings.Cut(principal, ":")
	if strings.Trim(name, "0123456789") == "" {
		return true
	}
	switch kind {
	case "user":
		return name == strings.ToLower(e.Layout.ServiceUser)
	case "group":
		return name == strings.ToLower(e.Layout.ServiceGroup) || name == "everyone"
	}
	return true
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

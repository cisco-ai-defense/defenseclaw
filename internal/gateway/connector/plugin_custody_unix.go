// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// custodyFix collects what the refused elements need: commands a shell can
// run, and steps that only a person can do (replace a link, give a path back
// to this account). Each refused element gets its own repair, so one round of
// fixes clears every refusal the walk would meet in turn.
type custodyFix struct {
	failing, chmod, acl, owner, structure []string
}

func (f *custodyFix) seen(path string) bool {
	for _, p := range f.failing {
		if p == path {
			return true
		}
	}
	f.failing = append(f.failing, path)
	return false
}

func (f *custodyFix) add(path string, loose, acl, owner bool) {
	if f.seen(path) {
		return
	}
	if loose {
		f.chmod = append(f.chmod, path)
	}
	// On Linux the group bits of a path with an access ACL are its mask, so
	// the chmod above also removes the ACL entries effective write; a macOS
	// ACL is separate from the mode and needs its own removal.
	if acl && (!loose || runtime.GOOS == "darwin") {
		f.acl = append(f.acl, path)
	}
	if owner {
		f.owner = append(f.owner, path)
	}
}

// addStructure records a link or a non-folder that no permission change clears.
func (f *custodyFix) addStructure(path string) {
	if !f.seen(path) {
		f.structure = append(f.structure, path)
	}
}

// command is the shell part of the repair: only commands, joined with &&.
func (f *custodyFix) command() string {
	var steps []string
	if len(f.chmod) > 0 {
		steps = append(steps, "chmod go-w "+pluginCustodyQuoteAll(f.chmod))
	}
	if len(f.acl) > 0 {
		clear := "setfacl -b "
		if runtime.GOOS == "darwin" {
			clear = "chmod -N "
		}
		steps = append(steps, clear+pluginCustodyQuoteAll(f.acl))
	}
	return strings.Join(steps, " && ")
}

// manual is the part of the repair a person does by hand, as prose.
func (f *custodyFix) manual() string {
	var steps []string
	if len(f.structure) > 0 {
		steps = append(steps, "replace "+pluginCustodyQuoteAll(f.structure)+" with a real folder or file owned by this account (a link is refused whatever it points to, and changing permissions does not clear it)")
	}
	if len(f.owner) > 0 {
		steps = append(steps, "have an administrator give "+pluginCustodyQuoteAll(f.owner)+" back to this account")
	}
	return strings.Join(steps, "; ")
}

// explainPluginArtifactRefusal turns the refusal of checkPluginArtifactDestination
// into one that names what to fix. The walk checks the leaf folder first and
// stops there, but a folder above it can be just as open, so naming the leaf
// alone sends the user to a fix that does not clear the refusal. This asks the
// same per-element judgement (hookAPIValidateDirectoryMetadataWith, with the
// same advisory ancestors and the same agent-directory private-group rule, and
// hookAPISymlinkRefused for links) of every element from the top down, then of
// the plugin file. A link or a non-folder is a structural refusal that no
// permission change clears, so it gets a step by hand instead of a chmod; the
// elements above it still get their own repair, and the ones below it are left
// to the next walk, since replacing the link changes them. The walk validates
// the resolved chain too once the literal one passes, so a link it accepts
// (a root-owned system link) must not hide a target folder it refuses: that
// chain is judged the same way. When no element is refused (a change made
// since), cause is returned unchanged.
func explainPluginArtifactRefusal(path string, cause error) error {
	if cause == nil || !filepath.IsAbs(path) {
		return cause
	}
	dir := filepath.Dir(filepath.Clean(path))
	var fix custodyFix
	if pluginCustodyJudgeChain(dir, &fix) {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil && resolved != dir {
			pluginCustodyJudgeChain(resolved, &fix)
		}
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() {
				fix.addStructure(path)
			} else {
				ownerBad := hookAPIValidateOwnerFor(path, info, "") != nil
				if hookAPIValidatePluginFilePermissions(path, info) != nil || ownerBad {
					fix.add(path, info.Mode().Perm()&0o022 != 0, hookAPIValidateDirectoryACL(path) != nil, ownerBad)
				}
			}
		}
	}
	if len(fix.failing) == 0 {
		return cause
	}
	return &pluginCustodyError{cause: cause, failing: fix.failing, fix: fix.command(), manual: fix.manual()}
}

// pluginCustodyJudgeChain judges dir and every ancestor, outermost first, as
// the walk does. It reports false once it met a link or non-folder it refuses
// (structural), after which it stops: the elements below depend on what the
// user puts in that place.
func pluginCustodyJudgeChain(dir string, fix *custodyFix) bool {
	for _, cur := range pluginCustodyChain(dir) {
		info, err := os.Lstat(cur)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Stat(cur); hookAPISymlinkRefused(cur, dir, info) || err != nil || !target.IsDir() {
				fix.addStructure(cur)
				return false
			}
			continue
		}
		if !info.IsDir() {
			fix.addStructure(cur)
			return false
		}
		advisory := cur != dir && managed.AdvisoryAncestorPath(cur)
		if hookAPIValidateDirectoryMetadataWith(cur, info, cur != dir, advisory, true) == nil {
			continue
		}
		stat, _ := info.Sys().(*syscall.Stat_t)
		fix.add(cur, info.Mode().Perm()&0o022 != 0, hookAPIValidateDirectoryACL(cur) != nil, stat != nil && !hookAPITrustedOwner(stat.Uid))
	}
	return true
}

// pluginCustodyChain lists dir and every ancestor, outermost first.
func pluginCustodyChain(dir string) []string {
	var chain []string
	for cur := filepath.Clean(dir); ; cur = filepath.Dir(cur) {
		chain = append([]string{cur}, chain...)
		if cur == filepath.Dir(cur) {
			return chain
		}
	}
}

func pluginCustodyQuoteAll(paths []string) string {
	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = pluginCustodyQuote(p)
	}
	return strings.Join(quoted, " ")
}

// pluginCustodyQuote quotes p for a POSIX shell only when it needs it.
func pluginCustodyQuote(p string) string {
	if p != "" && strings.Trim(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-") == "" {
		return p
	}
	return "\x27" + strings.ReplaceAll(p, "\x27", "\x27\\\x27\x27") + "\x27"
}

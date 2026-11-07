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

// custodyFix collects what one command must change.
type custodyFix struct {
	failing, chmod, acl, owner []string
}

func (f *custodyFix) add(path string, loose, acl, owner bool) {
	for _, seen := range f.failing {
		if seen == path {
			return
		}
	}
	f.failing = append(f.failing, path)
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
	if len(f.owner) > 0 {
		steps = append(steps, "have an administrator give "+pluginCustodyQuoteAll(f.owner)+" back to this account")
	}
	return strings.Join(steps, " && ")
}

// explainPluginArtifactRefusal turns the refusal of validatePluginArtifactDestinationFor
// into one that names what to fix. The walk checks the leaf folder first and
// stops there, but a folder above it can be just as open, so naming the leaf
// alone sends the user to a fix that does not clear the refusal. This asks the
// same per-element judgement (hookAPIValidateDirectoryMetadataWith, with the
// same advisory ancestors and the same agent-directory private-group rule) of
// every element from the top down, then of the plugin file. When no element
// is refused on permissions (a structural refusal such as a link, or a change
// made since), cause is returned unchanged.
func explainPluginArtifactRefusal(path string, cause error) error {
	if cause == nil || !filepath.IsAbs(path) {
		return cause
	}
	dir := filepath.Dir(filepath.Clean(path))
	chains := [][]string{pluginCustodyChain(dir)}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil && resolved != dir {
		chains = append(chains, pluginCustodyChain(resolved))
	}
	var fix custodyFix
	for _, chain := range chains {
		leaf := chain[len(chain)-1]
		for _, cur := range chain {
			info, err := os.Lstat(cur)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				continue
			}
			advisory := cur != leaf && managed.AdvisoryAncestorPath(cur)
			if hookAPIValidateDirectoryMetadataWith(cur, info, cur != leaf, advisory, true) == nil {
				continue
			}
			stat, _ := info.Sys().(*syscall.Stat_t)
			fix.add(cur, info.Mode().Perm()&0o022 != 0, hookAPIValidateDirectoryACL(cur) != nil, stat != nil && !hookAPITrustedOwner(stat.Uid))
		}
	}
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
		ownerBad := hookAPIValidateOwnerFor(path, info, "") != nil
		if hookAPIValidatePluginFilePermissions(path, info) != nil || ownerBad {
			fix.add(path, info.Mode().Perm()&0o022 != 0, hookAPIValidateDirectoryACL(path) != nil, ownerBad)
		}
	}
	if len(fix.failing) == 0 {
		return cause
	}
	return &pluginCustodyError{cause: cause, failing: fix.failing, fix: fix.command()}
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

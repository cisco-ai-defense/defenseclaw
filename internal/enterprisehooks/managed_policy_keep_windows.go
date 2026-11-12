//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Teardown never prepares a vendor folder (GAP-0758).
//
// ensureWindowsManagedPolicyDirectory is the write side: it creates a missing
// vendor folder (ProgramData\Cursor, Program Files\ClaudeCode\managed-settings.d,
// ProgramData\<vendor>\...), records it as created, and takes over a folder
// that is already there. It refuses a reparse point on the path, which is
// right for an install, ensure or repair: DefenseClaw must not write through
// a link. A teardown, a read, and the publication of an empty enrollment are
// not writes. When the recorded folder is gone and a link sits at its path
// (a stale record, then a junction a user made later), those calls must keep
// the link, name it, and carry on: nothing DefenseClaw wrote is behind it,
// and the link is not an object DefenseClaw made.
//
// The standalone profile only. Secure Client keeps the write-side preparation
// it always ran, which fails closed on a link and creates the folder.

// windowsManagedPolicyDirState is what a teardown finds at a vendor folder.
type windowsManagedPolicyDirState int

const (
	// windowsManagedPolicyDirAbsent: nothing is at the path. A teardown has
	// nothing to read or remove and creates nothing.
	windowsManagedPolicyDirAbsent windowsManagedPolicyDirState = iota
	// windowsManagedPolicyDirPlain: a real directory with no link on its
	// path. The usual transaction (trust check, repair, lock) applies.
	windowsManagedPolicyDirPlain
	// windowsManagedPolicyDirKept: a reparse point is on the path, or
	// something that is not a directory sits there. It is not followed,
	// changed or removed, and no DefenseClaw artifact is read behind it.
	windowsManagedPolicyDirKept
)

// windowsReparseChainProbe finds the first reparse point on the path or one of
// its parents, without following it. Tests replace it with injected results.
var windowsReparseChainProbe = findWindowsReparsePointInChain

// inspectWindowsManagedPolicyDirectoryNoFollow classifies a vendor folder for
// a teardown. It touches nothing. The second result names the path that makes
// the folder kept (the link, or the folder itself when it is not a directory).
func inspectWindowsManagedPolicyDirectoryNoFollow(path string) (windowsManagedPolicyDirState, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return windowsManagedPolicyDirAbsent, "", fmt.Errorf("enterprise hooks: resolve managed policy directory: %w", err)
	}
	absolute = filepath.Clean(absolute)
	link, err := windowsReparseChainProbe(absolute)
	if err != nil {
		return windowsManagedPolicyDirAbsent, "", err
	}
	if link != "" {
		return windowsManagedPolicyDirKept, link, nil
	}
	info, err := os.Lstat(absolute)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return windowsManagedPolicyDirAbsent, "", nil
	case err != nil:
		return windowsManagedPolicyDirAbsent, "", fmt.Errorf("enterprise hooks: inspect managed policy directory %s: %w", absolute, err)
	case !info.IsDir() || info.Mode()&os.ModeSymlink != 0:
		return windowsManagedPolicyDirKept, absolute, nil
	}
	return windowsManagedPolicyDirPlain, "", nil
}

// windowsManagedPolicyKept is the set of paths a teardown kept in this
// process, with why. The uninstall report and tests read it.
var windowsManagedPolicyKept = struct {
	sync.Mutex
	paths map[string]string
}{paths: map[string]string{}}

// noteWindowsManagedPolicyFolderKept records a kept path once and logs it as a
// resilience boundary event, so the lifecycle log and the guardian log name
// the path (it is not an error).
func noteWindowsManagedPolicyFolderKept(folder, kept string) {
	const reason = "a link or a non-folder sits at a vendor folder the teardown would read"
	windowsManagedPolicyKept.Lock()
	_, seen := windowsManagedPolicyKept.paths[kept]
	windowsManagedPolicyKept.paths[kept] = folder
	windowsManagedPolicyKept.Unlock()
	if seen {
		return
	}
	managed.EmitResilienceEvent(managed.MarkerBoundary, map[string]string{
		"path":   kept,
		"folder": folder,
		"reason": reason + ": the link is not followed, changed or removed, and nothing of DefenseClaw is read or written behind it",
	})
}

// WindowsManagedPolicyFoldersKept returns, sorted, the vendor-folder paths
// this process's teardown kept because a link sits there (GAP-0758).
func WindowsManagedPolicyFoldersKept() []string {
	windowsManagedPolicyKept.Lock()
	defer windowsManagedPolicyKept.Unlock()
	out := make([]string, 0, len(windowsManagedPolicyKept.paths))
	for path := range windowsManagedPolicyKept.paths {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// windowsManagedPolicyTeardownState is what a teardown, a read or the
// publication of an enrollment finds at a vendor folder, and it never creates,
// repairs or follows anything. A kept path is named (once). Secure Client keeps
// the write-side preparation it always ran, so it reports the folder plain and
// its caller prepares the folder as before.
func windowsManagedPolicyTeardownState(folder string) (windowsManagedPolicyDirState, error) {
	if !windowsEnterpriseStandaloneProcess() {
		return windowsManagedPolicyDirPlain, nil
	}
	state, kept, err := inspectWindowsManagedPolicyDirectoryNoFollow(folder)
	if err != nil {
		return state, err
	}
	if state == windowsManagedPolicyDirKept {
		noteWindowsManagedPolicyFolderKept(folder, kept)
	}
	return state, nil
}

// windowsManagedPolicyLinkKept reports that a link or a non-folder sits at
// folder or on its path (standalone only). A reader of DefenseClaw files under
// folder then treats every artifact as absent, so nothing behind the link is
// read. An absent folder is not kept.
func windowsManagedPolicyLinkKept(folder string) (bool, error) {
	state, err := windowsManagedPolicyTeardownState(folder)
	return err == nil && state == windowsManagedPolicyDirKept, err
}

// WindowsManagedConnectorFolderKept names the link that keeps a connector's
// machine folder, or returns "" when the folder is absent or plain (GAP-0773,
// GAP-0829). The folder is the one that holds the connector's runtime selector
// and, for a per-user connector, its enrollment: ProgramData\Cursor,
// ProgramData\OpenAI\Codex, Program Files\ClaudeCode\managed-settings.d and the
// per-user connector folders. A teardown that compares what the manifest and
// the activation record say is enrolled with what it reads there must leave
// that connector out of the comparison when a link sits at the folder: nothing
// behind the link is read, so nothing there can be compared, and the link is
// kept and named (once). Standalone only; Secure Client always returns "" and
// keeps its comparison.
func WindowsManagedConnectorFolderKept(connectorName string) (string, error) {
	if !windowsEnterpriseStandaloneProcess() {
		return "", nil
	}
	path, err := windowsManagedRuntimeSelectorPath(connectorName)
	if err != nil {
		return "", err
	}
	folder := filepath.Dir(path)
	kept, err := WindowsManagedConnectorFolderLink(connectorName)
	if err != nil || kept == "" {
		return "", err
	}
	noteWindowsManagedPolicyFolderKept(folder, kept)
	return kept, nil
}

// WindowsManagedConnectorFolderLink returns the link, or non-folder, that sits
// on the path of a connector's machine folder, found without opening or
// following anything, and "" when there is none. It names nothing and creates
// nothing, so a status check or the guardian can ask as often as it likes. The
// callers are standalone paths (the CLI process of an administrator carries no
// standalone profile in its environment, so this does not test for one).
func WindowsManagedConnectorFolderLink(connectorName string) (string, error) {
	path, err := windowsManagedRuntimeSelectorPath(connectorName)
	if err != nil {
		return "", err
	}
	state, link, err := inspectWindowsManagedPolicyDirectoryNoFollow(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: inspect %s machine folder: %w", connectorName, err)
	}
	if state != windowsManagedPolicyDirKept {
		return "", nil
	}
	return link, nil
}

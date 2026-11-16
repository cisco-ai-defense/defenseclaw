// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/windows"
)

var keptPolicyFileSID = regexp.MustCompile(`S-1-[0-9]+(?:-[0-9]+)+`)

// keptPolicyFileFix is the icacls command that takes the untrusted account's
// entry off path (or gives the file back to Administrators when the account
// owns it), from the account the trust check named.
func keptPolicyFileFix(path, trustErr string) string {
	sid := keptPolicyFileSID.FindString(trustErr)
	switch {
	case sid == "":
		return fmt.Sprintf(`icacls "%s" /setowner "*S-1-5-32-544"`, path)
	case strings.Contains(strings.ToLower(trustErr), "owner"):
		return fmt.Sprintf(`icacls "%s" /setowner "*S-1-5-32-544"`, path)
	}
	return fmt.Sprintf(`icacls "%s" /remove:g "*%s"`, path, sid)
}

// StaleHookKept is the reason of a KeptUntrustedPolicyFiles entry.
const StaleHookKept = "stale hook: "

// KeptUntrustedPolicyFiles lists, after an uninstall, the vendor policy files
// of the Go-owned Windows connectors (Copilot's drop-in, OpenCode's managed
// config, Devin's two hooks.json files) that another account owns or can
// change and that still name DefenseClaw. The uninstall never writes through
// such a file (keepUntrustedRecordedFile), so the file stays byte for byte and
// its DefenseClaw hook entries now name programs the uninstall removed. Each
// entry is "path: stale hook: <why the file is not trusted>", for the
// lifecycle's machine_state_remaining report, so the administrator is told
// once, in the result, which files to clean (GAP-0761). A trusted file, or one
// that names no DefenseClaw program, is not listed. Nothing is followed: a
// path with a link on any part below ProgramData is skipped, so a linked
// vendor folder is reported only as a kept link (the teardown's
// machine_state_remaining "kept" entry) and never read through as SYSTEM.
func KeptUntrustedPolicyFiles(opts Options) []string {
	if opts.goos() != "windows" || opts.SkipTrustChecks {
		return nil
	}
	var paths []string
	if path, err := copilotDropInPath(opts); err == nil {
		paths = append(paths, path)
	}
	if path, err := OpenCodeManagedConfigPath(opts); err == nil {
		dir := dirFor(opts, path)
		paths = append(paths, joinFor(opts, dir, "opencode.jsonc"), joinFor(opts, dir, "opencode.json"))
	}
	if path, err := DevinSystemHooksPath(opts); err == nil {
		paths = append(paths, path)
	}
	if path, err := devinCascadeLegacyHooksPath(opts); err == nil {
		paths = append(paths, path)
	}
	var kept []string
	for _, path := range paths {
		path = platformPath(opts, path)
		if programDataPathHasLink(opts, path) {
			continue
		}
		trustErr := validateTrustedFileItself(path)
		if trustErr == nil {
			continue
		}
		data, err := readKeptPolicyFileNoFollow(path)
		if err != nil || !strings.Contains(strings.ToLower(string(data)), "defenseclaw") {
			continue
		}
		kept = append(kept, path+": "+StaleHookKept+trustErr.Error()+". Fix: "+keptPolicyFileFix(path, trustErr.Error()))
	}
	return kept
}

// programDataPathHasLink reports whether a part of path below ProgramData,
// the file included, is a reparse point, or path is not there or not below
// ProgramData. It only reads attributes.
func programDataPathHasLink(opts Options, path string) bool {
	root, rel, ok := programDataRelative(opts, path)
	if !ok {
		return true
	}
	cur := root
	for _, part := range strings.Split(rel, `\`) {
		cur = filepath.Join(cur, part)
		name, err := windows.UTF16PtrFromString(cur)
		if err != nil {
			return true
		}
		attributes, err := windows.GetFileAttributes(name)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return true
		}
	}
	return false
}

// readKeptPolicyFileNoFollow reads the regular file at path, up to
// policyFileLimit, through a handle that does not follow a reparse point at
// it. The folders above it were checked just before (programDataPathHasLink);
// this only reports, so that check is enough for them.
func readKeptPolicyFileNoFollow(path string) ([]byte, error) {
	handle, err := openNoDeleteShare(path, windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return readHandleBounded(handle, policyFileLimit)
}

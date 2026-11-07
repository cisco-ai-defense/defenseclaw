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
	"os"
	"regexp"
	"strings"
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
// config, Devin's and Windsurf's hooks.json) that another account owns or can
// change and that still name DefenseClaw. The uninstall never writes through
// such a file (keepUntrustedRecordedFile), so the file stays byte for byte and
// its DefenseClaw hook entries now name programs the uninstall removed. Each
// entry is "path: stale hook: <why the file is not trusted>", for the
// lifecycle's machine_state_remaining report, so the administrator is told
// once, in the result, which files to clean (GAP-0761). A trusted file, or one
// that names no DefenseClaw program, is not listed.
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
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > policyFileLimit {
			continue
		}
		trustErr := validateTrustedFileItself(path)
		if trustErr == nil {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(strings.ToLower(string(data)), "defenseclaw") {
			continue
		}
		kept = append(kept, path+": "+StaleHookKept+trustErr.Error()+". Fix: "+keptPolicyFileFix(path, trustErr.Error()))
	}
	return kept
}

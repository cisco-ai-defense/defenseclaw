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
	"path/filepath"
	"regexp"

	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// Devin Desktop runs Devin Local, the Devin CLI harness
// (https://docs.devin.ai/desktop/devin-local), from a Devin CLI it bundles
// under its resources/app folder. That CLI is the engine that runs the
// user's Devin hooks, so the Desktop is a desktop surface of the devin
// connector whose engine version is the bundled CLI's. The bundled CLI's
// man page names that version in its .TH header ("devin 3000.10.48
// (fcf7ba39)"), which discovery reads without running anything; the
// bundled changelog runs ahead of the build and the Windows devin.exe has
// no version resource, so neither is used. The install folders are the
// 3.10 packages' defaults (the vendor documents none):
//   - macOS: Devin.app in /Applications or ~/Applications;
//   - Linux: the .deb's /usr/share/devin-desktop, or the .tar.gz's Devin
//     folder unpacked in the home or /opt (live check);
//   - Windows: %LOCALAPPDATA%\Programs\Devin (per-user) or
//     %ProgramFiles%\Devin (machine).
//
// A Desktop that has not bundled its CLI (it may fetch one on first use,
// location is a live check) is reported without an engine version.

// devinDesktopManPage is the bundled CLI's man page under an app's
// resources/app folder.
func devinDesktopManPage(appRoot string) string {
	return filepath.Join(appRoot, legacyconnector.DesktopBundledCLIDir(), "share", "man", "man1", "devin.1")
}

// devinManPageVersion matches the man page header of the Devin CLI.
var devinManPageVersion = regexp.MustCompile(`(?m)^\.TH devin 1\s+"devin ([0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6})[ "]`)

// parseDevinManPageVersion returns the Devin CLI version a man page's .TH
// header names, or "".
func parseDevinManPageVersion(data []byte) string {
	match := devinManPageVersion.FindSubmatch(data)
	if match == nil {
		return ""
	}
	return string(match[1])
}

// devinDesktopCLI is the bundled CLI under an app's resources/app folder.
func devinDesktopCLI(appRoot, name string) string {
	return filepath.Join(appRoot, legacyconnector.DesktopBundledCLIDir(), "bin", name)
}

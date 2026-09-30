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
	"strings"
)

// Devin Desktop runs Devin Local, the Devin CLI harness it fetches from the
// server (https://docs.devin.ai/desktop/devin-local). A user who has the
// Desktop but no Devin CLI whose version discovery can read still runs
// Devin, so discovery reports the Desktop as an install without a readable
// version and the enumerator records the agent as unprotected instead of
// skipping it silently. The locations are the installers' defaults (the
// vendor documents none): macOS Devin.app in ~/Applications or
// /Applications; Windows the per-user install under
// %LOCALAPPDATA%\Programs\Devin or the machine install under
// %ProgramFiles%\Devin. Linux has no probe until the package layout is
// captured on a desktop host.

// desktopSurfaceProbe finds a connector's desktop app for a home. It
// returns the file that shows the install, or "".
type desktopSurfaceProbe func(goos, home, programFiles string, present func(string) bool) string

// desktopSurfaceProbes are the desktop apps that run a connector's agent.
var desktopSurfaceProbes = map[string]desktopSurfaceProbe{
	"devin": devinDesktopSurface,
}

func devinDesktopSurface(goos, home, programFiles string, present func(string) bool) string {
	var candidates []string
	switch goos {
	case "darwin":
		for _, root := range []string{filepath.Join(home, "Applications"), "/Applications"} {
			candidates = append(candidates, filepath.Join(root, "Devin.app", "Contents", "Info.plist"))
		}
	case "windows":
		candidates = append(candidates, filepath.Join(home, "AppData", "Local", "Programs", "Devin", "Devin.exe"))
		if programFiles != "" {
			candidates = append(candidates, filepath.Join(programFiles, "Devin", "Devin.exe"))
		}
	}
	for _, candidate := range candidates {
		if present(candidate) {
			return candidate
		}
	}
	return ""
}

// desktopSurfaceInstalled returns the file that shows connector's desktop
// app is installed for home, or "".
func desktopSurfaceInstalled(goos, home, connector, programFiles string, present func(string) bool) string {
	probe := desktopSurfaceProbes[strings.ToLower(strings.TrimSpace(connector))]
	if probe == nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return probe(goos, filepath.Clean(home), programFiles, present)
}

// desktopSurfaceReason is the discovery reason for a desktop app whose
// agent version cannot be read.
func desktopSurfaceReason(path string) string {
	return path + " (a desktop app that runs this agent; the version of the agent it runs cannot be read)"
}

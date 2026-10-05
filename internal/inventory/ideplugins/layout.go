// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import "path/filepath"

// layout holds the per-platform base directories of one home.
type layout struct {
	home string
	goos string
	// appSupport is where desktop apps keep their user data: macOS
	// ~/Library/Application Support, Linux ~/.config, Windows %APPDATA%.
	appSupport string
	// localData is the machine-local data directory: macOS
	// ~/Library/Application Support, Linux ~/.local/share, Windows
	// %LOCALAPPDATA%.
	localData string
	// cache is the cache directory: macOS ~/Library/Caches, Linux
	// ~/.cache, Windows %LOCALAPPDATA%.
	cache string
}

func newLayout(home, goos string, limits Limits) layout {
	l := layout{home: home, goos: goos}
	switch goos {
	case "darwin":
		l.appSupport = filepath.Join(home, "Library", "Application Support")
		l.localData = l.appSupport
		l.cache = filepath.Join(home, "Library", "Caches")
	case "windows":
		l.appSupport = limits.RoamingAppData
		if l.appSupport == "" {
			l.appSupport = filepath.Join(home, "AppData", "Roaming")
		}
		l.localData = limits.LocalAppData
		if l.localData == "" {
			l.localData = filepath.Join(home, "AppData", "Local")
		}
		l.cache = l.localData
	default:
		l.appSupport = filepath.Join(home, ".config")
		l.localData = filepath.Join(home, ".local", "share")
		l.cache = filepath.Join(home, ".cache")
	}
	return l
}

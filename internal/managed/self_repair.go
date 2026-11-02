// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
)

// OwnedObject names one object a root DefenseClaw service owns and repairs in
// place: what it is, the permission bits it is stamped with, and what to do
// when it is structurally wrong.
type OwnedObject struct {
	Path string
	Kind ObjectKind
	// Mode overrides the kind's canonical permission bits. Zero keeps them.
	Mode os.FileMode
	// MoveAsideStructural renames a symlink, an extra hard link or a wrong
	// object type aside (see MoveAsideStructural) so a writer can recreate
	// the object. Leave it unset for an object DefenseClaw cannot recreate.
	MoveAsideStructural bool
	// Recreate makes a directory again, canonically stamped, after it was
	// moved aside or found missing. Files are recreated by their writers.
	Recreate bool
}

// ManagedServiceLayout is the managed install as the LaunchDaemon environment
// pins it. Every path is absolute and clean; a field is empty when the
// environment does not pin it.
type ManagedServiceLayout struct {
	Home             string
	ConfigPath       string
	RuntimeDir       string
	AuthorizationDir string
	ManifestDir      string
	ManifestPath     string
}

// PinnedManagedServiceLayout derives the managed layout from the service
// environment (DEFENSECLAW_HOME, DEFENSECLAW_CONFIG and
// DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR) without reading config.yaml, so the
// services can repair these paths before config load. ok is false outside a
// managed_enterprise pin or when the pinned home is not an absolute path.
func PinnedManagedServiceLayout() (ManagedServiceLayout, bool) {
	if !IsManagedEnterprise(PinnedDeploymentMode()) {
		return ManagedServiceLayout{}, false
	}
	home := strings.TrimSpace(os.Getenv("DEFENSECLAW_HOME"))
	if home == "" || !filepath.IsAbs(home) {
		return ManagedServiceLayout{}, false
	}
	home = filepath.Clean(home)
	layout := ManagedServiceLayout{
		Home:        home,
		RuntimeDir:  filepath.Join(home, "runtime"),
		ManifestDir: filepath.Join(home, "hook-guardian"),
	}
	layout.ManifestPath = filepath.Join(layout.ManifestDir, "targets.yaml")
	if config := strings.TrimSpace(os.Getenv(ConfigPathEnv)); config != "" && filepath.IsAbs(config) &&
		pathAtOrUnder(filepath.Clean(config), home) && filepath.Clean(config) != home {
		layout.ConfigPath = filepath.Clean(config)
	}
	if auth := strings.TrimSpace(os.Getenv(HookGuardianAuthorizationDirEnv)); auth != "" && filepath.IsAbs(auth) &&
		pathAtOrUnder(filepath.Clean(auth), home) && filepath.Clean(auth) != home {
		layout.AuthorizationDir = filepath.Clean(auth)
	}
	return layout, true
}

// Within reports whether path is at or below the pinned managed home.
func (layout ManagedServiceLayout) Within(path string) bool {
	if layout.Home == "" || strings.TrimSpace(path) == "" {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	return pathAtOrUnder(filepath.Clean(abs), layout.Home)
}

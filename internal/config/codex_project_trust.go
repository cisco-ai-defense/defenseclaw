// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// codexProjectTrust is what the Codex user config.toml says about projects:
// the paths with trust_level "trusted" under [projects]. Codex reads the
// .codex/config.toml of a project only for a trusted project.
type codexProjectTrust struct {
	// unknown is set when the user config exists but cannot be read, so the
	// trust of a project cannot be told: every project then counts as trusted
	// (the protective reading) rather than letting a project definition pass
	// as ignored.
	unknown bool
	paths   []string
}

func readCodexProjectTrust(userPath string) codexProjectTrust {
	if _, err := os.Stat(userPath); errors.Is(err, os.ErrNotExist) {
		return codexProjectTrust{}
	}
	data, ok := gatewayconnector.ReadStableInventoryFile(userPath, maxCodexInventoryConfigBytes)
	if !ok {
		return codexProjectTrust{unknown: true}
	}
	var doc struct {
		Projects map[string]struct {
			TrustLevel string `toml:"trust_level"`
		} `toml:"projects"`
	}
	if tomlUnmarshal(data, &doc) != nil {
		return codexProjectTrust{unknown: true}
	}
	var out codexProjectTrust
	for path, project := range doc.Projects {
		if strings.EqualFold(strings.TrimSpace(project.TrustLevel), "trusted") {
			out.paths = append(out.paths, path)
		}
	}
	return out
}

// covers reports whether a trusted path is the project layer, a folder above
// it or one below it, or relates the same way to the working folder. Which
// folder Codex keys a project by (the repository root, the working folder)
// varies, so any relation counts as trusted: a project file is treated as
// ignored only when no trusted path touches it.
func (t codexProjectTrust) covers(layer, cwd string) bool {
	if t.unknown {
		return true
	}
	for _, path := range t.paths {
		if codexPathsRelated(path, layer) || (cwd != "" && codexPathsRelated(path, cwd)) {
			return true
		}
	}
	return false
}

func codexTrustPath(path string) string {
	path = strings.TrimPrefix(strings.TrimSpace(path), "\\\\?\\")
	return strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
}

func codexPathsRelated(a, b string) bool {
	a, b = codexTrustPath(a), codexTrustPath(b)
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.HasPrefix(a, strings.TrimSuffix(b, "/")+"/") || strings.HasPrefix(b, strings.TrimSuffix(a, "/")+"/")
}

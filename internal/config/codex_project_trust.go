// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// codexProjectTrust is what the Codex user config.toml says about projects:
// every path under [projects] with its trust_level. Codex reads the
// .codex/config.toml of a project only for a trusted project, and the entry
// nearest the project decides: a project marked untrusted below a trusted
// folder is not trusted.
type codexProjectTrust struct {
	// unknown is set when the user config exists but cannot be read, so the
	// trust of a project cannot be told: every project then counts as trusted
	// (the protective reading) rather than letting a project definition pass
	// as ignored.
	unknown bool
	entries []codexProjectEntry
}

type codexProjectEntry struct {
	path    string
	trusted bool
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
		entry := codexProjectEntry{
			path:    codexTrustPath(path),
			trusted: strings.EqualFold(strings.TrimSpace(project.TrustLevel), "trusted"),
		}
		// Two spellings of one path (case, separators) that disagree count as
		// trusted: the protective reading.
		if i := slices.IndexFunc(out.entries, func(e codexProjectEntry) bool { return e.path == entry.path }); i >= 0 {
			out.entries[i].trusted = out.entries[i].trusted || entry.trusted
			continue
		}
		out.entries = append(out.entries, entry)
	}
	return out
}

// covers reports whether the project layer, or the working folder, is
// trusted. The entry nearest a folder (the folder itself or the closest one
// above it) decides for that folder, so a project marked untrusted below a
// trusted folder stays untrusted. Which folder Codex keys a project by (the
// repository root, the working folder) varies, so either folder trusted
// counts as trusted. When no entry sits at or above either folder, a trusted
// entry below one still counts, as before: a project file is treated as
// ignored only when no trusted path touches it.
func (t codexProjectTrust) covers(layer, cwd string) bool {
	if t.unknown {
		return true
	}
	decided := false
	for _, folder := range []string{layer, cwd} {
		if codexTrustPath(folder) == "" {
			continue
		}
		if entry, ok := t.nearest(folder); ok {
			decided = true
			if entry.trusted {
				return true
			}
		}
	}
	if decided {
		return false
	}
	for _, entry := range t.entries {
		if entry.trusted && (codexPathsRelated(entry.path, layer) || (cwd != "" && codexPathsRelated(entry.path, cwd))) {
			return true
		}
	}
	return false
}

// nearest is the entry for folder itself or for the closest folder above it.
func (t codexProjectTrust) nearest(folder string) (codexProjectEntry, bool) {
	folder = codexTrustPath(folder)
	var best codexProjectEntry
	found := false
	for _, entry := range t.entries {
		if entry.path == "" || (folder != entry.path && !strings.HasPrefix(folder, strings.TrimSuffix(entry.path, "/")+"/")) {
			continue
		}
		if !found || len(entry.path) > len(best.path) {
			best, found = entry, true
		}
	}
	return best, found
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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// observabilityV8EvalSymlinks is filepath.EvalSymlinks; tests replace it to
// deny a folder where the test account cannot (root, Windows).
var observabilityV8EvalSymlinks = filepath.EvalSymlinks

type observabilityV8FileRole struct {
	name     string
	path     string
	writable bool
	// deferrable marks a jsonl destination file. The gateway prepares that
	// destination in a deferred state when it cannot reach the file yet, so
	// a folder this account may not traverse is a warning for it, not a
	// config error (GAP-1265). Every other role stays fatal.
	deferrable bool
}

// validateObservabilityV8FilePaths checks that the configured file roles
// resolve to distinct files. It returns a warning, not an error, for a jsonl
// destination path whose folders this account is denied: that path is
// compared by its literal name, as a path whose folders do not exist yet is.
// deferJSONL is false for a Secure Client source, which keeps main's startup
// refusal.
func validateObservabilityV8FilePaths(
	source *ObservabilityV8Source,
	configuredFiles []string,
	deferJSONL bool,
) ([]ObservabilityV8Warning, error) {
	if source == nil {
		return nil, nil
	}
	roles := []observabilityV8FileRole{
		{name: "observability.local.path", path: source.Local.Path, writable: true},
		{name: "observability.local.judge_bodies_path", path: source.Local.JudgeBodiesPath, writable: true},
	}
	for index, destination := range source.Destinations {
		if destination.Kind == ObservabilityV8DestinationJSONL {
			roles = append(roles, observabilityV8FileRole{
				name: fmt.Sprintf("observability.destinations[%d].path", index), path: destination.Path,
				writable: true, deferrable: deferJSONL,
			})
		}
		if destination.TLS.CACert != "" {
			roles = append(roles, observabilityV8FileRole{
				name: fmt.Sprintf("observability.destinations[%d].tls.ca_cert", index), path: destination.TLS.CACert,
			})
		}
	}
	for index, path := range configuredFiles {
		roles = append(roles, observabilityV8FileRole{name: fmt.Sprintf("configured_file[%d]", index), path: path})
	}

	type normalizedRole struct {
		observabilityV8FileRole
		normalized string
		info       os.FileInfo
	}
	normalized := make([]normalizedRole, 0, len(roles))
	var warnings []ObservabilityV8Warning
	for _, role := range roles {
		if strings.TrimSpace(role.path) == "" {
			continue
		}
		if observabilityV8HasParentSegment(role.path) {
			return nil, fmt.Errorf("%s: parent path segments are not allowed", role.name)
		}
		absolute, err := filepath.Abs(filepath.Clean(role.path))
		if err != nil {
			return nil, fmt.Errorf("%s: cannot normalize configured path", role.name)
		}
		// Both failures below describe the filesystem, not the document, so the
		// cause is kept rather than reported as a semantic error.
		resolved, denied, err := observabilityV8ResolveExistingPathPrefix(absolute, role.deferrable)
		if err != nil {
			return nil, newV8ConfigPathError(role.name, absolute, err)
		}
		var info os.FileInfo
		if candidate, err := os.Stat(resolved); err == nil {
			info = candidate
		} else if role.deferrable && errors.Is(err, fs.ErrPermission) {
			denied = err
		} else if !os.IsNotExist(err) {
			return nil, newV8ConfigPathError(role.name, resolved, err)
		}
		if denied != nil {
			warnings = append(warnings, ObservabilityV8Warning{
				Code: "destination_path_inaccessible", Path: role.name,
				Summary: fmt.Sprintf("cannot inspect %s (%v); the gateway starts without this destination "+
					"and retries the file on every delivery", absolute, denied),
			})
		}
		normalized = append(normalized, normalizedRole{observabilityV8FileRole: role, normalized: resolved, info: info})
	}
	for left := 0; left < len(normalized); left++ {
		for right := left + 1; right < len(normalized); right++ {
			aliases := normalized[left].normalized == normalized[right].normalized ||
				runtime.GOOS == "windows" && strings.EqualFold(normalized[left].normalized, normalized[right].normalized)
			if !aliases && normalized[left].info != nil && normalized[right].info != nil {
				aliases = os.SameFile(normalized[left].info, normalized[right].info)
			}
			if aliases && (normalized[left].writable || normalized[right].writable) {
				return nil, fmt.Errorf(
					"%s and %s: configured file roles must resolve to distinct files",
					normalized[left].name,
					normalized[right].name,
				)
			}
		}
	}
	return warnings, nil
}

// normalizeObservabilityV8EffectiveFilePaths freezes every configured runtime
// file identity after alias validation. Effective plans must not retain paths
// whose meaning can change if the process working directory changes between
// compilation, store construction, readiness verification, and reload.
func normalizeObservabilityV8EffectiveFilePaths(source *ObservabilityV8Source) error {
	if source == nil {
		return nil
	}
	normalize := func(name string, value *string) error {
		if value == nil || strings.TrimSpace(*value) == "" {
			return nil
		}
		resolved, err := normalizeObservabilityV8FilePath(name, *value)
		if err != nil {
			return err
		}
		*value = resolved
		return nil
	}
	if err := normalize("observability.local.path", &source.Local.Path); err != nil {
		return err
	}
	if err := normalize("observability.local.judge_bodies_path", &source.Local.JudgeBodiesPath); err != nil {
		return err
	}
	for index := range source.Destinations {
		destination := &source.Destinations[index]
		if destination.Kind == ObservabilityV8DestinationJSONL {
			if err := normalize(
				fmt.Sprintf("observability.destinations[%d].path", index),
				&destination.Path,
			); err != nil {
				return err
			}
		}
		caCertPath := fmt.Sprintf("observability.destinations[%d].tls.ca_cert", index)
		if destination.Kind == ObservabilityV8DestinationOTLP &&
			destination.TLS.CACert != "" &&
			!filepath.IsAbs(destination.TLS.CACert) {
			return fmt.Errorf("%s: must be an absolute path", caCertPath)
		}
		if err := normalize(caCertPath, &destination.TLS.CACert); err != nil {
			return err
		}
	}
	return nil
}

func normalizeObservabilityV8FilePath(name, value string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(value))
	if err != nil {
		return "", fmt.Errorf("%s: cannot normalize configured path", name)
	}
	return absolute, nil
}

// observabilityV8ResolveExistingPathPrefix resolves the links of the longest
// existing prefix of absolute and appends the rest literally. With
// tolerateDenied, a prefix this account may not inspect is treated like a
// missing one and the first such failure is returned as denied; any other
// failure (I/O, too many links, a file used as a folder) is returned as err.
func observabilityV8ResolveExistingPathPrefix(absolute string, tolerateDenied bool) (string, error, error) {
	candidate := absolute
	var suffix []string
	var denied error
	for {
		resolved, err := observabilityV8EvalSymlinks(candidate)
		if err == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), denied, nil
		}
		switch {
		case os.IsNotExist(err):
		case tolerateDenied && errors.Is(err, fs.ErrPermission):
			if denied == nil {
				denied = err
			}
		default:
			return "", nil, err
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return filepath.Clean(absolute), denied, nil
		}
		suffix = append(suffix, filepath.Base(candidate))
		candidate = parent
	}
}

func observabilityV8HasParentSegment(path string) bool {
	for _, segment := range strings.Split(strings.ReplaceAll(path, "\\", "/"), "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

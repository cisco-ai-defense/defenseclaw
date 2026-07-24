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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type observabilityV8FileRole struct {
	name     string
	path     string
	writable bool
}

func validateObservabilityV8FilePaths(source *ObservabilityV8Source, configuredFiles []string) error {
	if source == nil {
		return nil
	}
	roles := []observabilityV8FileRole{
		{name: "observability.local.path", path: source.Local.Path, writable: true},
		{name: "observability.local.judge_bodies_path", path: source.Local.JudgeBodiesPath, writable: true},
	}
	for index, destination := range source.Destinations {
		if destination.Kind == ObservabilityV8DestinationJSONL {
			roles = append(roles, observabilityV8FileRole{
				name: fmt.Sprintf("observability.destinations[%d].path", index), path: destination.Path, writable: true,
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
	for _, role := range roles {
		if strings.TrimSpace(role.path) == "" {
			continue
		}
		if observabilityV8HasParentSegment(role.path) {
			return fmt.Errorf("%s: parent path segments are not allowed", role.name)
		}
		absolute, err := filepath.Abs(filepath.Clean(role.path))
		if err != nil {
			return fmt.Errorf("%s: cannot normalize configured path", role.name)
		}
		resolved, err := observabilityV8ResolveExistingPathPrefix(absolute)
		if err != nil {
			return fmt.Errorf("%s: cannot resolve configured path safely", role.name)
		}
		var info os.FileInfo
		if candidate, err := os.Stat(resolved); err == nil {
			info = candidate
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("%s: cannot inspect configured path safely", role.name)
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
				return fmt.Errorf(
					"%s and %s: configured file roles must resolve to distinct files",
					normalized[left].name,
					normalized[right].name,
				)
			}
		}
	}
	return nil
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

func observabilityV8ResolveExistingPathPrefix(absolute string) (string, error) {
	candidate := absolute
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return filepath.Clean(absolute), nil
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

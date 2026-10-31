// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"path"
	"strings"
)

// Protected-file watch modes (guardrail.protected_files.on_change).
const (
	// ProtectedFilesAlert raises a HIGH alert for a change made while an
	// agent tool call ran for the file's user. It is the default.
	ProtectedFilesAlert = "alert"
	// ProtectedFilesRestore also puts back the last content the watch
	// accepted. Opt-in (strict) only.
	ProtectedFilesRestore = "restore"
	// ProtectedFilesOff turns the watch off.
	ProtectedFilesOff = "off"
)

// MaxProtectedFilePaths bounds guardrail.protected_files.paths.
const MaxProtectedFilePaths = 64

// ProtectedFilesConfig is guardrail.protected_files. Both fields are empty
// by default and the empty value means the built-in behaviour.
type ProtectedFilesConfig struct {
	// OnChange is alert (default when empty), restore or off.
	OnChange string `mapstructure:"on_change" yaml:"on_change,omitempty"`
	// Paths replaces the built-in list of home-relative names. A name that
	// ends in "/" is a directory whose entries are watched (one level).
	Paths []string `mapstructure:"paths" yaml:"paths,omitempty"`
}

// EffectiveOnChange is the watch mode: OnChange, or alert when unset.
func (p ProtectedFilesConfig) EffectiveOnChange() string {
	switch strings.ToLower(strings.TrimSpace(p.OnChange)) {
	case ProtectedFilesRestore:
		return ProtectedFilesRestore
	case ProtectedFilesOff:
		return ProtectedFilesOff
	default:
		return ProtectedFilesAlert
	}
}

// Validate refuses an unknown mode and a path that is not a clean
// home-relative name.
func (p ProtectedFilesConfig) Validate() error {
	switch strings.ToLower(strings.TrimSpace(p.OnChange)) {
	case "", ProtectedFilesAlert, ProtectedFilesRestore, ProtectedFilesOff:
	default:
		return fmt.Errorf("guardrail.protected_files.on_change %q: want alert, restore or off", p.OnChange)
	}
	if len(p.Paths) > MaxProtectedFilePaths {
		return fmt.Errorf("guardrail.protected_files.paths: at most %d names", MaxProtectedFilePaths)
	}
	for _, name := range p.Paths {
		clean := strings.TrimSuffix(strings.ReplaceAll(name, `\`, "/"), "/")
		if clean == "" || path.IsAbs(clean) || strings.Contains(clean, ":") || path.Clean(clean) != clean ||
			clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("guardrail.protected_files.paths: %q is not a clean home-relative name", name)
		}
	}
	return nil
}

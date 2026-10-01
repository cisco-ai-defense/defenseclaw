//go:build darwin

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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// codexManagedPreferencesPlist is the MDM managed-preferences domain whose
// requirements_toml_base64 key outranks /etc/codex/requirements.toml.
const codexManagedPreferencesPlist = "/Library/Managed Preferences/com.openai.codex.plist"

func platformCodexHigherSources(opts Options) (map[string][]byte, error) {
	sources := map[string][]byte{}
	candidates := []string{rooted(opts, codexManagedPreferencesPlist)}
	if matches, err := filepath.Glob(rooted(opts, "/Library/Managed Preferences/*/com.openai.codex.plist")); err == nil {
		candidates = append(candidates, matches...)
	}
	for _, path := range candidates {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return sources, err
		}
		if !info.Mode().IsRegular() {
			return sources, fmt.Errorf("%s is not a regular file", path)
		}
		data, err := plistToJSON(path)
		if err != nil {
			return sources, fmt.Errorf("convert %s: %w", path, err)
		}
		var prefs map[string]any
		if err := json.Unmarshal(data, &prefs); err != nil {
			return sources, fmt.Errorf("decode %s: %w", path, err)
		}
		encoded, _ := prefs["requirements_toml_base64"].(string)
		if encoded == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return sources, fmt.Errorf("%s requirements_toml_base64 is not base64: %w", path, err)
		}
		sources[path+" (requirements_toml_base64)"] = decoded
	}
	return sources, nil
}

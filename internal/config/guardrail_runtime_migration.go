// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const GuardrailRuntimeFileName = "guardrail_runtime.json"

// MigrateGuardrailRuntimeFile folds the removed guardrail_runtime.json overlay
// into config.yaml and deletes the overlay after the patched config validates.
// The runtime file is no longer a live config source; a migration failure is
// fatal so the gateway never runs with split-brain guardrail posture.
func MigrateGuardrailRuntimeFile(configFile, dataDir string) (bool, error) {
	if strings.TrimSpace(dataDir) == "" {
		return false, nil
	}
	runtimeFile := filepath.Join(dataDir, GuardrailRuntimeFileName)
	data, err := os.ReadFile(runtimeFile)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("config: read legacy %s: %w", runtimeFile, err)
	}

	updates, err := guardrailRuntimeUpdates(data)
	if err != nil {
		return false, fmt.Errorf("config: migrate legacy %s: %w", runtimeFile, err)
	}

	original, readErr := os.ReadFile(configFile)
	originalExisted := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		return false, fmt.Errorf("config: read %s before migration: %w", configFile, readErr)
	}
	if len(updates) > 0 && !originalExisted {
		return false, fmt.Errorf("config: cannot migrate legacy %s: primary config %s does not exist", runtimeFile, configFile)
	}

	if len(updates) > 0 {
		if err := PatchYAMLFile(configFile, updates); err != nil {
			return false, fmt.Errorf("config: patch %s from legacy runtime: %w", configFile, err)
		}
		if _, err := loadFromFile(configFile, false); err != nil {
			if restoreErr := restoreConfigAfterFailedMigration(configFile, original, originalExisted); restoreErr != nil {
				return false, fmt.Errorf("config: patched config invalid after legacy runtime migration: %w; restore failed: %v", err, restoreErr)
			}
			return false, fmt.Errorf("config: patched config invalid after legacy runtime migration: %w", err)
		}
	}

	if err := os.Remove(runtimeFile); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("config: delete legacy %s after migration: %w", runtimeFile, err)
	}
	return true, nil
}

func guardrailRuntimeUpdates(data []byte) (map[string]any, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	updates := make(map[string]any)
	for key, value := range raw {
		switch key {
		case "mode":
			s, err := runtimeStringValue(value, key)
			if err != nil {
				return nil, err
			}
			if s != "observe" && s != "action" {
				return nil, fmt.Errorf("%s must be observe or action", key)
			}
			updates["guardrail.mode"] = s
		case "scanner_mode":
			s, err := runtimeStringValue(value, key)
			if err != nil {
				return nil, err
			}
			if s != "local" && s != "remote" && s != "both" {
				return nil, fmt.Errorf("%s must be local, remote, or both", key)
			}
			updates["guardrail.scanner_mode"] = s
		case "block_message":
			s, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be a string", key)
			}
			updates["guardrail.block_message"] = s
		case "connector":
			s, err := runtimeStringValue(value, key)
			if err != nil {
				return nil, err
			}
			updates["guardrail.connector"] = s
		case "hilt_enabled":
			b, err := runtimeBoolValue(value, key)
			if err != nil {
				return nil, err
			}
			updates["guardrail.hilt.enabled"] = b
		case "hilt_min_severity":
			s, err := runtimeStringValue(value, key)
			if err != nil {
				return nil, err
			}
			updates["guardrail.hilt.min_severity"] = strings.ToUpper(s)
		}
	}
	return updates, nil
}

func runtimeStringValue(value any, key string) (string, error) {
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("%s must not be empty", key)
	}
	return s, nil
}

func runtimeBoolValue(value any, key string) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, fmt.Errorf("%s must be a boolean", key)
}

func restoreConfigAfterFailedMigration(path string, original []byte, existed bool) error {
	if existed {
		return writeFileAtomic(path, original, 0o600)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

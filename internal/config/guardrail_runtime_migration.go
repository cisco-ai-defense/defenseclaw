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
	"log"
	"os"
	"path/filepath"
	"strings"
)

const GuardrailRuntimeFileName = "guardrail_runtime.json"

// MigrateGuardrailRuntimeFile folds the removed guardrail_runtime.json overlay
// into config.yaml and deletes the overlay after the patched config validates.
// The legacy overlay was historically best-effort, so malformed or unreadable
// state is warned about and preserved rather than preventing gateway startup.
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
		log.Printf("WARNING: config: cannot read legacy %s; preserving it for repair: %v", runtimeFile, err)
		return false, nil
	}

	updates, err := guardrailRuntimeUpdates(data)
	if err != nil {
		// The legacy overlay was historically best-effort. A stale or hand-edited
		// value must not brick gateway startup during an upgrade; preserve the
		// file for operator repair and continue using the validated config.yaml.
		log.Printf("WARNING: config: preserving invalid legacy %s for repair: %v", runtimeFile, err)
		return false, nil
	}

	original, readErr := os.ReadFile(configFile)
	originalExisted := readErr == nil
	originalMode := os.FileMode(0o600)
	if readErr != nil && !os.IsNotExist(readErr) {
		log.Printf("WARNING: config: cannot read %s before legacy runtime migration; preserving %s: %v", configFile, runtimeFile, readErr)
		return false, nil
	}
	if originalExisted {
		if info, statErr := os.Stat(configFile); statErr == nil {
			originalMode = info.Mode().Perm()
		}
	}
	if len(updates) > 0 && !originalExisted {
		log.Printf("WARNING: config: cannot migrate legacy %s because primary config %s does not exist; preserving it for repair", runtimeFile, configFile)
		return false, nil
	}

	if len(updates) > 0 {
		if err := PatchYAMLFile(configFile, updates); err != nil {
			log.Printf("WARNING: config: cannot patch %s from legacy %s; preserving it for repair: %v", configFile, runtimeFile, err)
			return false, nil
		}
		if _, err := loadFromFile(configFile, false); err != nil {
			if restoreErr := restoreConfigAfterFailedMigration(configFile, original, originalMode, originalExisted); restoreErr != nil {
				return false, fmt.Errorf("config: patched config invalid after legacy runtime migration: %w; restore failed: %v", err, restoreErr)
			}
			log.Printf("WARNING: config: legacy %s produced an invalid config; restored %s and preserved the runtime file for repair: %v", runtimeFile, configFile, err)
			return false, nil
		}
	}

	if err := os.Remove(runtimeFile); err != nil && !os.IsNotExist(err) {
		log.Printf("WARNING: config: migrated legacy %s but could not delete it: %v", runtimeFile, err)
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
			s = strings.ToLower(s)
			if s != "observe" && s != "action" {
				return nil, fmt.Errorf("%s must be observe or action", key)
			}
			updates["guardrail.mode"] = s
		case "scanner_mode":
			s, err := runtimeStringValue(value, key)
			if err != nil {
				return nil, err
			}
			s = strings.ToLower(s)
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
			updates["guardrail.connector"] = strings.ToLower(s)
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
			s = strings.ToUpper(s)
			switch s {
			case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
				updates["guardrail.hilt.min_severity"] = s
			default:
				return nil, fmt.Errorf("%s must be CRITICAL, HIGH, MEDIUM, LOW, or INFO", key)
			}
		}
	}
	if len(raw) > 0 && len(updates) == 0 {
		return nil, fmt.Errorf("legacy runtime contains no supported values")
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

func restoreConfigAfterFailedMigration(path string, original []byte, mode os.FileMode, existed bool) error {
	if existed {
		return writeFileAtomic(path, original, mode)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

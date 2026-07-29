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
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// DefaultEnvConfigPath is the canonical location AVC drops the DefenseClaw
// env config on macOS installs. The file is authored (and re-authored, on
// upgrades and region changes) by the Cisco Secure Client AVC packaging
// pipeline. The installer at packaging/macos/install.sh reads it at
// install time; the gateway sidecar's ConfigManager re-reads it at every
// wake so region changes that arrive AFTER install take effect without a
// process restart.
const DefaultEnvConfigPath = "/opt/cisco/secureclient/defenseclaw/env_config.json"

// envConfigEndpointKey is the JSON key that carries the AI Defense inspect
// origin. Kept in one place so it stays aligned with the shell installer's
// resolve_aid_endpoint() at packaging/macos/lib/installer_lib.sh.
const envConfigEndpointKey = "cisco_ai_defense_endpoint"

// ErrEnvConfigMissing signals that env_config.json was not present on
// disk. Callers should treat this as "no override — fall through to the
// config.yaml value" rather than a hard failure; the AVC packaging
// contract permits the file to arrive AFTER DefenseClaw is installed.
var ErrEnvConfigMissing = errors.New("env_config: file not present")

// LoadEnvConfigEndpoint reads AVC's env_config.json at path, validates the
// cisco_ai_defense_endpoint field, and returns the origin as a string.
// Returns ("", ErrEnvConfigMissing) when path does not exist — this is
// the intended shape for pre-arrival installs. Any other failure
// (unreadable file, malformed JSON, missing key, invalid URL) returns a
// non-nil error and an empty string; callers should log and RETAIN the
// current effective endpoint rather than blowing away a working one.
//
// URL validation mirrors resolve_aid_endpoint()/_valid_aid_endpoint_url()
// in packaging/macos/lib/installer_lib.sh: HTTPS bare origin, no
// userinfo, no path (other than "" or "/"), no query, no fragment. A
// hostile env_config could otherwise exfiltrate tokens by pointing the
// bearer-authenticated inspect POSTs at an attacker-controlled host.
func LoadEnvConfigEndpoint(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", ErrEnvConfigMissing
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrEnvConfigMissing
		}
		return "", fmt.Errorf("env_config: read %s: %w", path, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("env_config: parse %s: %w", path, err)
	}
	raw, ok := payload[envConfigEndpointKey]
	if !ok {
		return "", fmt.Errorf("env_config: %s missing %q", path, envConfigEndpointKey)
	}
	endpoint, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("env_config: %s field %q is not a string", path, envConfigEndpointKey)
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("env_config: %s field %q is empty", path, envConfigEndpointKey)
	}
	if err := validateAIDefenseEndpoint(endpoint); err != nil {
		return "", fmt.Errorf("env_config: %s field %q: %w", path, envConfigEndpointKey, err)
	}
	return endpoint, nil
}

// validateAIDefenseEndpoint accepts only https://host[:port] with no
// userinfo, path, query, or fragment. Keep in sync with
// _valid_aid_endpoint_url() in packaging/macos/lib/installer_lib.sh —
// there is a sync-guard test that fails CI if the rules drift.
func validateAIDefenseEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("must be https (got %q)", u.Scheme)
	}
	if u.User != nil {
		return errors.New("must not contain userinfo")
	}
	if u.Host == "" {
		return errors.New("must contain a host")
	}
	// url.Parse folds `https://host` and `https://host/` identically;
	// reject anything with a real path segment.
	if p := strings.TrimPrefix(u.Path, "/"); p != "" {
		return errors.New("must be a bare origin (no path)")
	}
	if u.RawQuery != "" {
		return errors.New("must not contain a query string")
	}
	if u.Fragment != "" {
		return errors.New("must not contain a fragment")
	}
	// Belt-and-braces: url.Parse tolerates "https://" with an empty
	// host on some Go versions when the input is bare "https://".
	if strings.EqualFold(endpoint, "https://") {
		return errors.New("must contain a host")
	}
	return nil
}

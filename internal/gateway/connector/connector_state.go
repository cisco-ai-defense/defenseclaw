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

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const activeConnectorFile = "active_connector.json"

type connectorState struct {
	Name string `json:"name"`
}

// LoadActiveConnector reads the previously active connector name from
// <dataDir>/active_connector.json. Returns "" if the file does not
// exist or is unreadable.
func LoadActiveConnector(dataDir string) string {
	data, err := os.ReadFile(filepath.Join(dataDir, activeConnectorFile))
	if err != nil {
		return ""
	}
	var state connectorState
	if err := json.Unmarshal(data, &state); err != nil {
		return ""
	}
	return state.Name
}

// SaveActiveConnector persists the active connector name to
// <dataDir>/active_connector.json so the next sidecar boot can
// detect a connector change and teardown the old one.
func SaveActiveConnector(dataDir, name string) error {
	data, err := json.Marshal(connectorState{Name: name})
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dataDir, activeConnectorFile), data, 0o644)
}

// ClearActiveConnector removes the state file (used on full teardown
// when guardrails are disabled).
func ClearActiveConnector(dataDir string) {
	os.Remove(filepath.Join(dataDir, activeConnectorFile))
}

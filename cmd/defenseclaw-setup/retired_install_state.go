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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Install state written by pre-release native Windows builds made after
// 0.8.10 can still select the pre-rename Devin Desktop connector (windsurf)
// and carry its home bindings. The strict state decoder would reject those
// files, so upgrade, repair and uninstall would all fail. They are accepted on
// read only: the bindings are dropped, the retired selection becomes "none" in
// the loaded state, and repair and upgrade move it to its replacement
// (retiredConnectorReplacementAt). Nothing here is ever
// written; the normal state rewrite omits these fields.
//
// No other removed connector is accepted: a pre-release state that selected
// one fails strict validation, and the upgrade guide tells those users to
// uninstall with their original build first.
//
// This file and cli/defenseclaw/retired_install_state.py mirror each other;
// cli/tests/test_retired_connector_names.py allows both to name the old
// Desktop connector.

// retiredInstallStateFields are the home-binding fields older states carry.
var retiredInstallStateFields = []string{
	"windsurf_user_home",
	"windsurf_hooks_path",
}

// retiredInstallStateConnectors maps a retired connector selection to the
// connector repair and upgrade select instead.
var retiredInstallStateConnectors = map[string]string{
	"windsurf": "devin",
}

// readInstallStateJSON decodes install-state.json strictly after removing the
// retired home-binding fields. Each removed field must be a JSON string.
func readInstallStateJSON(path string, state *installState) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cleaned, err := stripRetiredInstallStateFields(data)
	if err != nil {
		return err
	}
	return decodeJSONStrict(cleaned, state)
}

func stripRetiredInstallStateFields(data []byte) ([]byte, error) {
	present := false
	for _, field := range retiredInstallStateFields {
		if bytes.Contains(data, []byte(`"`+field+`"`)) {
			present = true
			break
		}
	}
	if !present {
		return data, nil
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	for _, field := range retiredInstallStateFields {
		raw, ok := document[field]
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("installer state field %s is not a string", field)
		}
		delete(document, field)
	}
	return json.Marshal(document)
}

// retireInstallStateConnector moves a retired connector selection out of the
// loaded state before validation.
func retireInstallStateConnector(state *installState) {
	if state == nil {
		return
	}
	if _, retired := retiredInstallStateConnectors[strings.ToLower(strings.TrimSpace(state.Connector))]; retired {
		state.Connector = "none"
	}
}

// retiredConnectorReplacementAt returns the connector repair and upgrade
// select when the install state under treeRoot selected a retired connector.
// The caller has already loaded and validated that state.
func retiredConnectorReplacementAt(treeRoot string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(treeRoot, "installer", "install-state.json"))
	if err != nil {
		return "", false
	}
	var selection struct {
		Connector string `json:"connector"`
	}
	if err := json.Unmarshal(data, &selection); err != nil {
		return "", false
	}
	replacement, retired := retiredInstallStateConnectors[strings.ToLower(strings.TrimSpace(selection.Connector))]
	return replacement, retired
}

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

import "fmt"

// renderedHookFile is one generated hook-directory file, rendered in memory.
type renderedHookFile struct {
	Name string
	Data []byte
}

// renderHookTemplate renders one embedded hook template. The error text
// matches what the host writers have always reported for a missing or
// malformed template.
func renderHookTemplate(name string, data templateData) ([]byte, error) {
	content, err := hookFS.ReadFile("hooks/" + name)
	if err != nil {
		return nil, fmt.Errorf("read hook template %s: %w", name, err)
	}
	rendered, err := renderTemplate(string(content), data)
	if err != nil {
		return nil, fmt.Errorf("render hook %s: %w", name, err)
	}
	return []byte(rendered), nil
}

// renderHookScriptSet renders the executable scripts of one hook directory
// without touching disk: the generic inspect-* scripts with sharedData, then
// the connector-owned extras (de-duplicated, generic names win) with
// connectorData. Host writers and the sandbox image renderer both go through
// it, so the two can only differ by template data.
func renderHookScriptSet(connectorData, sharedData templateData, extras []string) ([]renderedHookFile, error) {
	names := hookScriptNamesFromExtras(extras)
	out := make([]renderedHookFile, 0, len(names))
	for i, name := range names {
		data := connectorData
		if i < len(genericHookScripts) {
			data = sharedData
		}
		rendered, err := renderHookTemplate(name, data)
		if err != nil {
			return nil, err
		}
		out = append(out, renderedHookFile{Name: name, Data: rendered})
	}
	return out, nil
}

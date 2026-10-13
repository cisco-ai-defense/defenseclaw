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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// derivedHookHeader is the first comment of every per-user (unmanaged)
// connector hook script: the digest of the config values rendered into it
// and the hook fail mode it bakes in, so doctor can tell a script rendered
// from another config apart from the current one (spec section 6). Managed
// installs compare the whole render instead (HookScriptRenderDrift).
const derivedHookHeader = "# defenseclaw-derived:"

// derivedHookLine is the header line for a connector script rendered from data.
func derivedHookLine(data templateData) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("defenseclaw-hook-render-v1\nconnector=%s\nfail_mode=%s\napi_addr=%s\n",
		data.ConnectorName, data.FailMode, data.APIAddr)))
	return fmt.Sprintf("%s sha256=%s fail_mode=%s\n", derivedHookHeader, hex.EncodeToString(sum[:]), data.FailMode)
}

// withDerivedHeader inserts the derived-from line after the shebang and the
// "# defenseclaw-managed-hook vN" marker, which stays the second line
// (scripts and setup read it there).
func withDerivedHeader(script []byte, data templateData) []byte {
	line := []byte(derivedHookLine(data))
	at := 0
	for _, prefix := range []string{"#!", hookSchemaVersionMarker} {
		if !bytes.HasPrefix(script[at:], []byte(prefix)) {
			break
		}
		end := bytes.IndexByte(script[at:], '\n')
		if end < 0 {
			return script
		}
		at += end + 1
	}
	out := make([]byte, 0, len(script)+len(line))
	out = append(out, script[:at]...)
	out = append(out, line...)
	return append(out, script[at:]...)
}

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
		if i >= len(genericHookScripts) && !data.Managed && strings.HasSuffix(name, ".sh") && !strings.HasPrefix(name, "_") {
			rendered = withDerivedHeader(rendered, data)
		}
		out = append(out, renderedHookFile{Name: name, Data: rendered})
	}
	return out, nil
}

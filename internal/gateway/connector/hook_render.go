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
// connector hook script: the digest of the config values rendered into it, so
// doctor can tell a script an older build rendered apart from the current one
// (spec section 6). Managed installs compare the whole render instead
// (HookScriptRenderDrift).
//
// The line names no fail mode. A per-user script reads its outage mode from
// the config when a call fails; the closed it bakes for every other failure
// is not a config value. Doctor compared a baked fail_mode=closed with the
// config's outage mode (open on the default tier) and called every fresh
// script stale (GAP-1347). Scripts from 1.0.3 and older, which did bake the
// config's mode, still carry the field, so doctor still finds those.
const derivedHookHeader = "# defenseclaw-derived:"

// derivedHookLine is the header line for a connector script rendered from data.
func derivedHookLine(data templateData) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("defenseclaw-hook-render-v1\nconnector=%s\nfail_mode=%s\napi_addr=%s\n",
		data.ConnectorName, data.FailMode, data.APIAddr)))
	return fmt.Sprintf("%s sha256=%s\n", derivedHookHeader, hex.EncodeToString(sum[:]))
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
	if data.Managed && !data.SecureClient && !data.Sandbox {
		data.ManagedHTTPFailureSH = managedShellHTTPFailure
	}
	rendered, err := renderTemplate(string(content), data)
	if err != nil {
		return nil, fmt.Errorf("render hook %s: %w", name, err)
	}
	if !data.Managed && !data.Sandbox && !data.SecureClient && strings.HasSuffix(name, ".sh") && !strings.HasPrefix(name, "_") {
		// Only a managed render may select the hook socket or managed fail mode.
		// Clear agent-inherited markers before any per-user bootstrap branch;
		// the managed and Secure Client render bytes stay unchanged.
		lines := strings.SplitN(rendered, "\n", 3)
		if len(lines) != 3 || !strings.HasPrefix(lines[1], hookSchemaVersionMarker) {
			return nil, fmt.Errorf("render hook %s: missing schema marker", name)
		}
		rendered = lines[0] + "\n" + lines[1] + "\nunset DEFENSECLAW_MANAGED_HOOK DEFENSECLAW_HOOK_SOCKET DEFENSECLAW_HOOK_SOCKET_UID\n" + lines[2]
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

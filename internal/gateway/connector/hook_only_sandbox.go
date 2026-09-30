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
	"encoding/json"
	"fmt"
	"path"
)

// hookOnlySandboxRenderer renders the OpenShell overlay artifacts of one
// hook-only connector from a validated target. The dispatcher finalizes the
// result (path checks, sorting).
type hookOnlySandboxRenderer func(c *hookOnlyConnector, rt resolvedSandboxTarget) (SandboxArtifacts, error)

// hookOnlySandboxRenderers holds the hook-only connectors that have an
// OpenShell sandbox variant. Each registers from its own <name>_sandbox.go.
var hookOnlySandboxRenderers = map[string]hookOnlySandboxRenderer{}

func registerHookOnlySandboxRenderer(name string, render hookOnlySandboxRenderer) {
	if _, dup := hookOnlySandboxRenderers[name]; dup {
		panic("connector: duplicate sandbox renderer for " + name)
	}
	hookOnlySandboxRenderers[name] = render
}

// SandboxArtifacts renders the connector's OpenShell overlay artifacts, or
// refuses a hook-only connector that has no reviewed sandbox variant.
func (c *hookOnlyConnector) SandboxArtifacts(target SandboxRenderTarget) (SandboxArtifacts, error) {
	render, ok := hookOnlySandboxRenderers[c.name]
	if !ok {
		return SandboxArtifacts{}, fmt.Errorf("connector %s has no OpenShell sandbox variant", c.name)
	}
	rt, err := resolveSandboxTarget(c.name, target)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	artifacts, err := render(c, rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if artifacts.Connector != c.name {
		return SandboxArtifacts{}, fmt.Errorf("%s sandbox renderer returned %q artifacts", c.name, artifacts.Connector)
	}
	return finalizeSandboxArtifacts(artifacts)
}

// sandboxArtifactsGate is implemented by connector types whose
// SandboxArtifacts method exists for more connectors than have a sandbox
// variant. A type that embeds *hookOnlyConnector and defines its own
// SandboxArtifacts must override sandboxArtifactsSupported as well.
type sandboxArtifactsGate interface {
	sandboxArtifactsSupported() bool
}

func (c *hookOnlyConnector) sandboxArtifactsSupported() bool {
	_, ok := hookOnlySandboxRenderers[c.name]
	return ok
}

// SandboxArtifactsSupported reports whether conn renders OpenShell overlay
// artifacts. Every hook-only connector shares one Go type (and amp embeds
// it), so implementing SandboxArtifactProvider does not answer it: only the
// ones with a registered sandbox variant do.
func SandboxArtifactsSupported(conn Connector) bool {
	if _, ok := conn.(SandboxArtifactProvider); !ok {
		return false
	}
	if gate, ok := conn.(sandboxArtifactsGate); ok {
		return gate.sandboxArtifactsSupported()
	}
	return true
}

// SandboxCanonicalDir holds the root-owned reference copies of user-tier
// harness configuration. A connector whose harness reads its hooks only from
// a user-scope file ships the reviewed file here, and the in-image launcher
// restores the user copy from it before every start: an agent that edits
// the user copy mid-session changes nothing after its next launch.
func SandboxCanonicalDir(connectorName string) string {
	return path.Join(SandboxLibDir, connectorName)
}

// userTierHookFiles returns a hook configuration twice: root-owned and
// read-only at SandboxCanonicalDir(connector)/name, and seeded in the
// workload HOME at userPath, which is what the harness reads.
func userTierHookFiles(connectorName, name, userPath string, data []byte) []SandboxFile {
	return []SandboxFile{
		{Path: path.Join(SandboxCanonicalDir(connectorName), name), Mode: 0o644, Owner: SandboxOwnerRoot, Data: data},
		{Path: userPath, Mode: 0o600, Owner: SandboxOwnerUser, Data: data},
	}
}

// marshalSandboxJSON renders a deterministic, indented JSON document with a
// trailing newline and no HTML escaping (hook commands carry '&' and '<'
// rarely, but a reviewer should read them verbatim).
func marshalSandboxJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var _ SandboxArtifactProvider = (*hookOnlyConnector)(nil)

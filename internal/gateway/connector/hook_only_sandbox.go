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
	"fmt"
	"regexp"
	"strings"
)

// hookOnlySandboxRenderers holds the OpenShell overlay renderer of every
// hook-only connector with a reviewed sandbox variant. The target is already
// validated (ingress address, fail-closed, Known Linux hook contract) when a
// renderer runs. Each connector keeps its renderer in its own
// <connector>_sandbox.go file.
var hookOnlySandboxRenderers = map[string]func(resolvedSandboxTarget) (SandboxArtifacts, error){
	"amp":      renderAmpSandboxArtifacts,
	"copilot":  renderCopilotSandboxArtifacts,
	"opencode": renderOpenCodeSandboxArtifacts,
}

// SandboxArtifacts renders the connector's OpenShell overlay artifacts, or
// refuses a hook-only connector that has no reviewed sandbox variant.
func (c *hookOnlyConnector) SandboxArtifacts(target SandboxRenderTarget) (SandboxArtifacts, error) {
	render, ok := hookOnlySandboxRenderers[c.name]
	if !ok {
		return SandboxArtifacts{}, fmt.Errorf("connector %q has no OpenShell sandbox variant", c.name)
	}
	rt, err := resolveSandboxTarget(c.name, target)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	artifacts, err := render(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if artifacts.Connector != c.name {
		return SandboxArtifacts{}, fmt.Errorf("connector %s rendered %q sandbox artifacts", c.name, artifacts.Connector)
	}
	return artifacts, nil
}

// sandboxPluginHostOnlyMarkers must never survive into a rendered sandbox
// plugin: each one reads a host token file or an unresolved template input.
var sandboxPluginHostOnlyMarkers = []string{"DC_TOKEN_FILE", "DC_MAX_TOKEN_FILE_BYTES", ".token", "127.0.0.1", "{{"}

// sandboxPluginRequiredMarkers must appear in a rendered sandbox plugin: the
// runtime binding token, the idempotency key and the baked closed fail mode.
var sandboxPluginRequiredMarkers = []string{SandboxTokenEnv, "X-DefenseClaw-Hook-Idempotency-Key", "sandbox hooks always fail closed"}

// renderSandboxPlugin renders a JS/TS bridge plugin template in its OpenShell
// sandbox variant (baked ingress, fail closed, token from the environment,
// retried requests with an idempotency key) and checks the result carries
// no host-only input.
func renderSandboxPlugin(asset string, rt resolvedSandboxTarget) ([]byte, error) {
	body, err := renderHookTemplate(asset, templateData{
		APIAddr:                  rt.ingressAddr,
		FailMode:                 rt.failMode,
		Managed:                  true,
		ConnectorName:            rt.contract.Connector,
		Sandbox:                  true,
		SandboxConnectTimeout:    sandboxHookConnectTimeoutSeconds,
		SandboxMaxTime:           sandboxHookMaxTimeSeconds,
		SandboxRetryMaxTime:      sandboxHookRetryMaxTimeSeconds,
		SandboxSessionEndMaxTime: sandboxHookSessionEndMaxTimeSeconds,
	})
	if err != nil {
		return nil, err
	}
	for _, marker := range sandboxPluginHostOnlyMarkers {
		if bytes.Contains(body, []byte(marker)) {
			return nil, fmt.Errorf("sandbox plugin %s still references host-only %q", asset, marker)
		}
	}
	for _, marker := range sandboxPluginRequiredMarkers {
		if !bytes.Contains(body, []byte(marker)) {
			return nil, fmt.Errorf("sandbox plugin %s lacks %q", asset, marker)
		}
	}
	if !bytes.Contains(body, []byte(`"`+rt.ingressAddr+`"`)) {
		return nil, fmt.Errorf("sandbox plugin %s does not bake the ingress %s", asset, rt.ingressAddr)
	}
	if bytes.Count(body, []byte("const DC_FAIL_MODE")) != 1 || !sandboxPluginFailModeRE.Match(body) {
		return nil, fmt.Errorf("sandbox plugin %s does not bake exactly one closed fail mode", asset)
	}
	return body, nil
}

var sandboxPluginFailModeRE = regexp.MustCompile(`const DC_FAIL_MODE(?:: string)? = "closed"`)

// harnessBinary names the agent CLI an overlay image must provide.
func harnessBinary(name string) SandboxBinary {
	return SandboxBinary{Name: strings.TrimSpace(name), Role: SandboxBinaryHarness}
}

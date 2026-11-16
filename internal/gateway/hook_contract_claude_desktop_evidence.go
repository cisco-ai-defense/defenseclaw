// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// claudeDesktopEngineVersion is enterprisehooks.ClaudeDesktopEngineVersion;
// tests replace it.
var claudeDesktopEngineVersion = enterprisehooks.ClaudeDesktopEngineVersion

// applyClaudeDesktopEngineEvidence gives the per-user Claude Code connector
// the version of Claude Desktop's own Claude Code engine when agent
// discovery recorded none (cowork-1-0-8 GAP-0037). An account with Claude
// Desktop and no claude CLI runs the connector's hooks from that engine
// (Cowork, the Code tab), so action mode is admitted against the engine's
// hook contract instead of refused for an empty agent version. The engine counts
// only as enrolment counts it: signed by Anthropic on macOS and Windows, an
// executable engine on Linux (enterprisehooks.ClaudeDesktopEngineVersion).
// Python discovery records the same engine in agent_discovery.json
// (GAP-0036), which wins when it has a version; this covers a cache that is
// missing or older than that. Managed installs keep their own admission.
func (s *Sidecar) applyClaudeDesktopEngineEvidence(connectorName, agentVersion string, resolution connector.HookContractResolution) (string, connector.HookContractResolution) {
	if s == nil || !strings.EqualFold(strings.TrimSpace(connectorName), "claudecode") ||
		strings.TrimSpace(agentVersion) != "" || resolution.Status == connector.HookCompatibilityKnown {
		return agentVersion, resolution
	}
	cfg := s.currentConfig()
	if cfg == nil || managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return agentVersion, resolution
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return agentVersion, resolution
	}
	version, engineDir := claudeDesktopEngineVersion(context.Background(), home)
	if version == "" {
		return agentVersion, resolution
	}
	fmt.Fprintf(os.Stderr, "[guardrail] connector %s: agent discovery recorded no claude version; using Claude Desktop's verified Claude Code engine %s in %s\n", connectorName, version, engineDir)
	return version, connector.ResolveHookContract(connectorName, version)
}

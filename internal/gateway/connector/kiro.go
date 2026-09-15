// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// KiroConnector represents Kiro's ACP-native security surface. The stdio
// mediator, rather than an LLM proxy or guessed hook file, is authoritative.
// Native Kiro v2/v3 hooks remain a separately versioned defense-in-depth
// contract and are not required for ACP enforcement.
type KiroConnector struct {
	gatewayToken string
	masterKey    string
	loopbackWarn sync.Once
}

func NewKiroConnector() *KiroConnector { return &KiroConnector{} }
func (*KiroConnector) Name() string    { return "kiro" }
func (*KiroConnector) Description() string {
	return "Kiro CLI ACP agent guarded through the local defenseclaw-acp stdio mediator"
}
func (*KiroConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (*KiroConnector) SubprocessPolicy() SubprocessPolicy     { return SubprocessNone }

func (*KiroConnector) Setup(_ context.Context, opts SetupOpts) error {
	locks, err := filepath.Glob(filepath.Join(opts.DataDir, "acp", "*-kiro.contract-lock.json"))
	if err != nil || len(locks) == 0 {
		return errors.New("Kiro is configured through `defenseclaw acp setup --client <zed|jetbrains> --agent kiro`; no ACP contract lock is installed")
	}
	for _, lock := range locks {
		if info, statErr := os.Lstat(lock); statErr == nil && info.Mode().IsRegular() {
			return nil
		}
	}
	return errors.New("Kiro ACP contract locks are not regular files")
}

func (*KiroConnector) Teardown(context.Context, SetupOpts) error { return nil }
func (*KiroConnector) VerifyClean(SetupOpts) error               { return nil }

func (c *KiroConnector) Authenticate(r *http.Request) bool {
	return authenticateHookBridgeRequest(r, c.gatewayToken, c.masterKey, c.Name(),
		"Kiro ACP traffic is authenticated by the scoped ACP evaluator token", &c.loopbackWarn)
}

func (c *KiroConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	return &ConnectorSignals{RawBody: body, RawModel: ParseModelFromBody(body), Stream: ParseStreamFromBody(body), PassthroughMode: true, ConnectorName: c.Name()}, nil
}

func (c *KiroConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken, c.masterKey = gatewayToken, masterKey
}

func (*KiroConnector) Capabilities(SetupOpts) ConnectorCapabilities {
	unsupported := unsupportedSurface("Kiro ACP mediation does not mutate this native asset surface.")
	return ConnectorCapabilities{
		LLMTrafficMode: LLMTrafficModeHooksOnly,
		Hooks:          HookCapability{CanBlock: true, SupportsFailClosed: true, Scope: "acp", BlockEvents: []string{"session/prompt", "session/request_permission", "fs/write_text_file", "terminal/create"}},
		MCP:            unsupported, Skills: unsupported, Rules: unsupported, Plugins: unsupported, Agents: unsupported,
		CodeGuard: CodeGuardCapability{OptInOnly: true, Idempotent: true, ConflictSafe: true},
		Telemetry: TelemetryCapability{HookSignals: []string{"logs", "metrics", "traces"}, AuthMode: "scoped-header-token-loopback", SourceModes: []string{"acp"}},
		ACP:       ACPAgentCapabilityForConnector("kiro"),
	}
}

func (c *KiroConnector) HookCapabilities(opts SetupOpts) HookCapability {
	return c.Capabilities(opts).Hooks
}

// HookProfile keeps Kiro visible to the connector-wide capability/profile
// registry. ACP requests are still evaluated by the dedicated ACP endpoint;
// these generic mappers are only the safe fallback if a caller asks the
// unified hook collector to render Kiro's declared enforcement capability.
func (c *KiroConnector) HookProfile(opts SetupOpts) HookProfile {
	return ApplyHookContract(HookProfile{
		Name:                c.Name(),
		Capabilities:        c.HookCapabilities(opts),
		SupportsTraceparent: true,
		MapVerdict:          hookOnlyProfileMapVerdict,
		Respond:             hookOnlyProfileRespond,
	}, opts)
}

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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// CodexConnector handles all security surfaces for OpenAI Codex.
// LLM traffic: sets OPENAI_BASE_URL to route through proxy.
// Tool inspection: hook script calls /api/v1/codex/hook.
// Implements ComponentScanner, StopScanner.
type CodexConnector struct {
	gatewayToken string
	masterKey    string
}

// NewCodexConnector creates a new Codex connector.
func NewCodexConnector() *CodexConnector {
	return &CodexConnector{}
}

func (c *CodexConnector) Name() string { return "codex" }
func (c *CodexConnector) Description() string {
	return "env var + hook script (6 events, component scanning)"
}
func (c *CodexConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *CodexConnector) SubprocessPolicy() SubprocessPolicy {
	return ResolveSubprocessPolicy(SubprocessSandbox)
}

func (c *CodexConnector) Setup(ctx context.Context, opts SetupOpts) error {
	if err := c.writeEnvOverride(opts); err != nil {
		return fmt.Errorf("codex env override: %w", err)
	}

	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScriptsWithToken(hookDir, opts.APIAddr, opts.APIToken); err != nil {
		return fmt.Errorf("codex hook script: %w", err)
	}

	policy := ResolveSubprocessPolicy(SubprocessSandbox)
	if err := SetupSubprocessEnforcement(policy, opts); err != nil {
		return fmt.Errorf("codex subprocess enforcement: %w", err)
	}

	return nil
}

func (c *CodexConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	c.removeEnvOverride(opts)
	TeardownSubprocessEnforcement(opts)
	return nil
}

func (c *CodexConnector) Authenticate(r *http.Request) bool {
	isLoopback := IsLoopback(r)

	if dcAuth := r.Header.Get("X-DC-Auth"); dcAuth != "" {
		token := strings.TrimPrefix(dcAuth, "Bearer ")
		if c.gatewayToken != "" && token == c.gatewayToken {
			return true
		}
	}

	if c.masterKey != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && strings.TrimPrefix(auth, "Bearer ") == c.masterKey {
			return true
		}
	}

	// No token configured: allow only loopback callers. Non-loopback traffic
	// is denied by default until the operator explicitly sets a gateway token.
	if c.gatewayToken == "" && c.masterKey == "" {
		return isLoopback
	}

	return false
}

func (c *CodexConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

func (c *CodexConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	cs := &ConnectorSignals{
		ConnectorName: "codex",
		RawAPIKey:     ExtractAPIKey(r),
		RawBody:       body,
		RawModel:      ParseModelFromBody(body),
		Stream:        ParseStreamFromBody(body),
		ExtraHeaders:  map[string]string{},
	}

	if !isChatPath(r.URL.Path) {
		cs.PassthroughMode = true
	}

	return cs, nil
}

// --- ComponentScanner interface ---

func (c *CodexConnector) SupportsComponentScanning() bool { return true }

func (c *CodexConnector) ComponentTargets(cwd string) map[string][]string {
	home := os.Getenv("HOME")
	codexDir := filepath.Join(home, ".codex")

	targets := map[string][]string{
		"skill":  {filepath.Join(codexDir, "skills"), filepath.Join(cwd, ".codex", "skills")},
		"plugin": {filepath.Join(codexDir, "plugins"), filepath.Join(codexDir, "plugins", "cache")},
		"mcp":    {filepath.Join(codexDir, "config.toml"), filepath.Join(cwd, ".mcp.json")},
	}
	return targets
}

// --- StopScanner interface ---

func (c *CodexConnector) SupportsStopScan() bool { return true }

// --- Env override ---

type codexBackup struct {
	HadBaseURL bool   `json:"had_base_url"`
	OldBaseURL string `json:"old_base_url"`
}

func (c *CodexConnector) saveBackup(dataDir string, backup codexBackup) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dataDir, "codex_backup.json"), data, 0o644)
}

const codexEnvFileName = "codex_env.sh"

func (c *CodexConnector) writeEnvOverride(opts SetupOpts) error {
	backup := codexBackup{}
	if v := os.Getenv("OPENAI_BASE_URL"); v != "" {
		backup.HadBaseURL = true
		backup.OldBaseURL = v
	}
	if err := c.saveBackup(opts.DataDir, backup); err != nil {
		return fmt.Errorf("save codex backup: %w", err)
	}

	proxyURL := "http://" + opts.ProxyAddr + "/c/codex"
	content := fmt.Sprintf(
		"# Generated by defenseclaw setup — source this file before running codex.\n"+
			"export OPENAI_BASE_URL=%q\n",
		proxyURL,
	)

	envPath := filepath.Join(opts.DataDir, codexEnvFileName)
	if err := os.WriteFile(envPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write codex env file: %w", err)
	}

	dotenvPath := filepath.Join(opts.DataDir, "codex.env")
	dotenvContent := fmt.Sprintf("OPENAI_BASE_URL=%s\n", proxyURL)
	if err := os.WriteFile(dotenvPath, []byte(dotenvContent), 0o644); err != nil {
		return fmt.Errorf("write codex .env: %w", err)
	}

	return nil
}

func (c *CodexConnector) removeEnvOverride(opts SetupOpts) {
	os.Remove(filepath.Join(opts.DataDir, codexEnvFileName))
	os.Remove(filepath.Join(opts.DataDir, "codex.env"))
	os.Remove(filepath.Join(opts.DataDir, "codex_backup.json"))
}

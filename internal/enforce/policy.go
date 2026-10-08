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

package enforce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// PolicyEngine answers enforcement questions for skills, MCP servers,
// plugins and tools.
//
// Operator block/allow decisions come from config.yaml asset_policy (the
// <type>.denied/allowed and tool lists), read through the config source set
// with WithConfig. The audit.db actions table is the enforcement journal:
// the watcher's automatic install blocks, quarantines and runtime disables.
// It is runtime state, never policy, except on Secure Client hosts, whose
// behaviour is unchanged and still reads operator rows from the table.
type PolicyEngine struct {
	store *audit.Store
	cfg   func() *config.Config
}

// NewPolicyEngine returns an engine over the enforcement journal in store.
// Without WithConfig it sees no operator block/allow entries.
func NewPolicyEngine(store *audit.Store) *PolicyEngine {
	return &PolicyEngine{store: store}
}

// WithConfig returns a copy of e whose operator block/allow checks read
// asset_policy from the config cfg returns at the time of each check.
func (e *PolicyEngine) WithConfig(cfg func() *config.Config) *PolicyEngine {
	if e == nil {
		return &PolicyEngine{cfg: cfg}
	}
	out := *e
	out.cfg = cfg
	return &out
}

func (e *PolicyEngine) config() *config.Config {
	if e == nil || e.cfg == nil {
		return nil
	}
	return e.cfg()
}

// legacyOperatorRows reports whether operator block/allow entries still come
// from the actions table: only on Secure Client hosts.
func (e *PolicyEngine) legacyOperatorRows() bool {
	cfg := e.config()
	return cfg != nil && cfg.SecureClientIntegration()
}

// ----------------------------------------------------------------------------
// Operator block/allow (asset_policy)
// ----------------------------------------------------------------------------

// IsBlockedForConnector reports whether asset_policy.<targetType>.denied
// blocks name for connector. A rule scoped to the connector decides before
// an unscoped one, so a connector-scoped allow overrides a global deny for
// that connector (config.AssetListDecision).
func (e *PolicyEngine) IsBlockedForConnector(targetType, name, connector string) (bool, error) {
	if e.legacyOperatorRows() {
		return e.journalInstallIs(targetType, name, connector, "block")
	}
	verdict, _ := e.config().AssetListDecision(config.AssetPolicyInput{TargetType: targetType, Name: name, Connector: connector})
	return verdict == config.AssetListDeny, nil
}

// IsMCPBlockedForConnector checks the server name and its configured endpoint.
// A CLI block by URL is stored under that URL, while a tool hook supplies the
// server name. Resolve the endpoint for the active connector before deciding.
func (e *PolicyEngine) IsMCPBlockedForConnector(server, connector string) (bool, error) {
	if e.legacyOperatorRows() {
		return e.IsBlockedForConnector("mcp", server, connector)
	}
	cfg := e.config()
	if cfg == nil {
		return false, nil
	}
	in := config.AssetPolicyInput{TargetType: "mcp", Name: server, Connector: connector}
	// Most calls have name-only rules. Avoid reading connector registries
	// unless some rule needs an endpoint to match.
	needsEndpoint := false
	for _, rules := range [][]config.AssetPolicyRule{cfg.AssetPolicy.MCP.Denied, cfg.AssetPolicy.MCP.Allowed} {
		for _, rule := range rules {
			if rule.URL != "" || strings.HasPrefix(rule.Name, "https://") || strings.HasPrefix(rule.Name, "http://") {
				needsEndpoint = true
				break
			}
		}
	}
	if !needsEndpoint {
		verdict, _ := cfg.AssetListDecision(in)
		return verdict == config.AssetListDeny, nil
	}
	entry, ok := cfg.LookupMCPServerForConnector(connector, "", server)
	if ok {
		in.URL = strings.TrimSpace(entry.URL)
		in.Command, in.Args, in.Transport = entry.Command, entry.Args, entry.Transport
	}
	nameVerdict, nameRule := cfg.AssetListDecision(in)
	if in.URL == "" {
		return nameVerdict == config.AssetListDeny, nil
	}
	in.Name = in.URL // CLI URL entries from 0.8.x are stored as rule names.
	urlVerdict, urlRule := cfg.AssetListDecision(in)
	if urlVerdict == "" {
		return nameVerdict == config.AssetListDeny, nil
	}
	if nameVerdict == "" {
		return urlVerdict == config.AssetListDeny, nil
	}
	nameScoped := strings.TrimSpace(nameRule.Connector) != ""
	urlScoped := strings.TrimSpace(urlRule.Connector) != ""
	if nameScoped != urlScoped {
		if urlScoped {
			return urlVerdict == config.AssetListDeny, nil
		}
		return nameVerdict == config.AssetListDeny, nil
	}
	return nameVerdict == config.AssetListDeny || urlVerdict == config.AssetListDeny, nil
}

// IsAllowedForConnector reports whether asset_policy.<targetType>.allowed
// allows name for connector. Callers check IsBlockedForConnector first.
func (e *PolicyEngine) IsAllowedForConnector(targetType, name, connector string) (bool, error) {
	if e.legacyOperatorRows() {
		return e.journalInstallIs(targetType, name, connector, "allow")
	}
	verdict, _ := e.config().AssetListDecision(config.AssetPolicyInput{TargetType: targetType, Name: name, Connector: connector})
	return verdict == config.AssetListAllow, nil
}

// IsToolBlockedForConnector reports whether asset_policy.tool.denied blocks
// toolName for connector: a rule for the connector decides before an
// unscoped rule (config.ToolListDecision).
func (e *PolicyEngine) IsToolBlockedForConnector(toolName, connector string) (bool, error) {
	if e.legacyOperatorRows() {
		return e.legacyToolInstallIs(toolName, connector, "block")
	}
	verdict, _ := e.config().ToolListDecision(toolName, connector)
	return verdict == config.AssetListDeny, nil
}

// IsToolAllowedForConnector reports whether asset_policy.tool.allowed allows
// toolName for connector. Callers check IsToolBlockedForConnector first.
func (e *PolicyEngine) IsToolAllowedForConnector(toolName, connector string) (bool, error) {
	if e.legacyOperatorRows() {
		return e.legacyToolInstallIs(toolName, connector, "allow")
	}
	verdict, _ := e.config().ToolListDecision(toolName, connector)
	return verdict == config.AssetListAllow, nil
}

// legacyToolInstallIs is the Secure Client read of tool rows keyed
// "@<connector>/<tool>" (scoped) before "<tool>" (global).
func (e *PolicyEngine) legacyToolInstallIs(toolName, connector, want string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	if connector != "" {
		entry, err := e.store.GetAction("tool", "@"+connector+"/"+toolName)
		if err != nil {
			return false, err
		}
		if entry != nil && entry.Actions.Install != "" {
			return entry.Actions.Install == want, nil
		}
	}
	return e.store.HasAction("tool", toolName, "install", want)
}

// ----------------------------------------------------------------------------
// Enforcement journal (audit.db actions)
// ----------------------------------------------------------------------------

// Block records an automatic install block (the watcher's scan verdict) in
// the journal. Operator blocks are asset_policy changes, not journal rows.
func (e *PolicyEngine) Block(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField(targetType, name, "install", "block", reason)
}

// JournalInstallBlocked reports whether the journal holds an install block
// for name: the watcher's automatic block that a restore keeps in place.
// The connector-scoped row decides before the global row.
func (e *PolicyEngine) JournalInstallBlocked(targetType, name, connector string) (bool, error) {
	return e.journalInstallIs(targetType, name, connector, "block")
}

func (e *PolicyEngine) journalInstallIs(targetType, name, connector, want string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	if connector != "" {
		action, ok, err := e.actionFieldForConnector(targetType, name, connector, "install")
		if err != nil {
			return false, err
		}
		if ok {
			return action == want, nil
		}
	}
	return e.store.HasAction(targetType, name, "install", want)
}

func (e *PolicyEngine) Quarantine(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField(targetType, name, "file", "quarantine", reason)
}

func (e *PolicyEngine) Disable(targetType, name, reason string) error {
	if e.store == nil {
		return nil
	}
	return e.store.SetActionField(targetType, name, "runtime", "disable", reason)
}

func (e *PolicyEngine) Enable(targetType, name string) error {
	if e.store == nil {
		return nil
	}
	return e.store.ClearActionField(targetType, name, "runtime")
}

func (e *PolicyEngine) SetSourcePath(targetType, name, path string) {
	if e.store == nil {
		return
	}
	_ = e.store.SetSourcePath(targetType, name, path)
}

func (e *PolicyEngine) GetAction(targetType, name string) (*audit.ActionEntry, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.GetAction(targetType, name)
}

// IsDisabledForConnector reports whether name is runtime-disabled for
// connector, checking the connector-scoped journal row first and then the
// bare global row.
func (e *PolicyEngine) IsDisabledForConnector(targetType, name, connector string) (bool, error) {
	if e.store == nil {
		return false, nil
	}
	if connector != "" {
		action, ok, err := e.actionFieldForConnector(targetType, name, connector, "runtime")
		if err != nil {
			return false, err
		}
		if ok {
			return action == "disable", nil
		}
	}
	return e.store.HasAction(targetType, name, "runtime", "disable")
}

func (e *PolicyEngine) actionFieldForConnector(targetType, name, connector, field string) (string, bool, error) {
	entry, err := e.store.GetActionForConnector(targetType, name, connector)
	if err != nil {
		return "", false, err
	}
	if entry == nil {
		return "", false, nil
	}
	switch field {
	case "install":
		return entry.Actions.Install, entry.Actions.Install != "", nil
	case "runtime":
		return entry.Actions.Runtime, entry.Actions.Runtime != "", nil
	default:
		return "", false, fmt.Errorf("enforce: unknown action field %q", field)
	}
}

// PolicyStableID returns a short stable identifier for the policy bundle
// rooted at policyDir (used in OTel spans and metrics).
func PolicyStableID(policyDir string) string {
	if strings.TrimSpace(policyDir) == "" {
		return "none"
	}
	sum := sha256.Sum256([]byte(policyDir))
	return hex.EncodeToString(sum[:8])
}

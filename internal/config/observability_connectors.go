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

package config

import (
	"fmt"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Per-connector webhook routing.
//
// Webhooks are a notification channel, separate from telemetry. Export
// routing belongs to the canonical v8 observability destinations and routes.
// ---------------------------------------------------------------------------

// PerConnectorObservability owns a connector's notification webhook override.
type PerConnectorObservability struct {
	Webhooks *[]WebhookConfig `mapstructure:"webhooks" yaml:"webhooks,omitempty"`
}

// ObservabilityConfig carries the per-connector notification webhook
// overrides.
type ObservabilityConfig struct {
	Connectors map[string]PerConnectorObservability `mapstructure:"connectors" yaml:"connectors,omitempty"`
}

// connectorOverride returns the override block for connector if configured.
// Mirrors GuardrailConfig.connectorOverride / AssetPolicyConfig.connectorOverride:
// an empty connector / nil receiver / empty map yields (zero, false); lookup is
// connector-name-insensitive (exact key first, then normalizeConnectorKey).
func (o *ObservabilityConfig) connectorOverride(connector string) (PerConnectorObservability, bool) {
	if o == nil || connector == "" || len(o.Connectors) == 0 {
		return PerConnectorObservability{}, false
	}
	if pc, ok := o.Connectors[connector]; ok {
		return pc, true
	}
	want := normalizeConnectorKey(connector)
	if want == "" {
		return PerConnectorObservability{}, false
	}
	for name, pc := range o.Connectors {
		if normalizeConnectorKey(name) == want {
			return pc, true
		}
	}
	return PerConnectorObservability{}, false
}

// EffectiveWebhooks resolves the webhooks a connector's events route to: the
// per-connector override (when the webhooks dimension is set, including an
// explicit empty list = suppress) wins; otherwise inherit global. global is
// the top-level cfg.Webhooks. Mirrors
// ObservabilityConfig.effective_webhooks in config.py.
func (o *ObservabilityConfig) EffectiveWebhooks(connector string, global []WebhookConfig) []WebhookConfig {
	if pc, ok := o.connectorOverride(connector); ok && pc.Webhooks != nil {
		return append([]WebhookConfig(nil), (*pc.Webhooks)...)
	}
	return append([]WebhookConfig(nil), global...)
}

// HasConnectorWebhooksOverride reports whether a connector explicitly owns
// the webhook dimension, including an empty suppression list.
func (o *ObservabilityConfig) HasConnectorWebhooksOverride(connector string) bool {
	pc, ok := o.connectorOverride(connector)
	return ok && pc.Webhooks != nil
}

// ConnectorNames returns the configured connector keys in deterministic
// (sorted) order. Used by the build/registration wiring to fan out over
// per-connector overrides without depending on Go map iteration order.
func (o *ObservabilityConfig) ConnectorNames() []string {
	if o == nil || len(o.Connectors) == 0 {
		return nil
	}
	names := make([]string, 0, len(o.Connectors))
	for name := range o.Connectors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Validate rejects empty / alias-duplicate connector names. Value-only check
// mirroring AssetPolicyConfig.Validate / ObservabilityConfig.validate in
// config.py — it never touches the connector registry. Returns the first
// violation.
func (o *ObservabilityConfig) Validate() error {
	if o == nil || len(o.Connectors) == 0 {
		return nil
	}
	seen := make(map[string]string, len(o.Connectors))
	for _, name := range o.ConnectorNames() {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("observability.connectors: empty connector name is not allowed")
		}
		norm := normalizeConnectorKey(name)
		if prev, ok := seen[norm]; ok {
			return fmt.Errorf("observability.connectors: %q and %q refer to the same "+
				"connector %q; keep only one", prev, name, norm)
		}
		seen[norm] = name
	}
	return nil
}

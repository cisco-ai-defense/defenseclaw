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
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// migrateLegacyConnectorIDs moves retired connector IDs in guardrail.connector,
// guardrail.connectors and claw.mode to their replacement. It must run right
// after decoding and before normalizeConnectorKey or the duplicate-key check,
// so a config holding both the retired and the replacement key loads with the
// replacement's settings instead of failing. The Python loader applies the
// same rule (defenseclaw.legacy_connector.migrate_raw_config).
func migrateLegacyConnectorIDs(cfg *Config) {
	if cfg == nil {
		return
	}
	keys := make([]string, 0, len(cfg.Guardrail.Connectors))
	for key := range cfg.Guardrail.Connectors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	primary, rename, dropped := legacyconnector.MigrateConnectorKeys(cfg.Guardrail.Connector, keys)
	changed := primary != cfg.Guardrail.Connector || len(rename) > 0 || len(dropped) > 0
	cfg.Guardrail.Connector = primary
	for old, replacement := range rename {
		cfg.Guardrail.Connectors[replacement] = cfg.Guardrail.Connectors[old]
		delete(cfg.Guardrail.Connectors, old)
	}
	for _, old := range dropped {
		delete(cfg.Guardrail.Connectors, old)
	}
	if mode, migrated := legacyconnector.Canonical(string(cfg.Claw.Mode)); migrated {
		cfg.Claw.Mode = ClawMode(mode)
		changed = true
	}
	if changed {
		cfg.LegacyConnectorNotices = append(cfg.LegacyConnectorNotices, legacyconnector.Notice(cfg.ConfigFilePath, dropped))
	}
}

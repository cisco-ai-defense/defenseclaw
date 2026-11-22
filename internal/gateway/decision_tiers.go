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

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// packTables holds the tier table of every pack directory: decide.Builtin()
// with the pack's own tiers.yaml column in the pack's own tier (DET111 D4),
// so a pack's cells, not only its tier name, decide its verdicts. Like
// packPostures it is keyed by directory and filled from what a generation
// build read (notePackTable), visible when the generation publishes
// (publishPackPostures); a directory no generation loaded reads its
// tiers.yaml once. A built-in pack's column is the built-in table itself
// (TestShippedTiersMatchBuiltin), so it decides with decide.Builtin().
var packTables sync.Map // directory -> *decide.Table

// pendingPackTables holds what builds read until a generation publishes.
var pendingPackTables sync.Map // directory -> *decide.Table

func notePackTable(dir string, col *decide.Column) {
	if dir = strings.TrimSpace(dir); dir != "" {
		pendingPackTables.Store(dir, decide.Builtin().WithColumn(col))
	}
}

func publishPackTables() {
	pendingPackTables.Range(func(dir, table any) bool {
		packTables.Store(dir, table)
		pendingPackTables.Delete(dir)
		return true
	})
}

// packTable is the tier table of the pack at dir ("" is decide.Builtin()).
// A tiers.yaml the loader would refuse (invalid_tiers) never loads a
// generation, so here it reads as no column.
func packTable(dir string) *decide.Table {
	if dir = strings.TrimSpace(dir); dir == "" {
		return decide.Builtin()
	}
	if v, ok := packTables.Load(dir); ok {
		return v.(*decide.Table)
	}
	var col *decide.Column
	if raw, err := os.ReadFile(filepath.Join(dir, decide.TiersFile)); err == nil {
		col, _ = decide.ParseColumn(raw)
	}
	table := decide.Builtin().WithColumn(col)
	packTables.Store(dir, table)
	return table
}

// configTierTable is the hook policy tier of connector under cfg and the
// tier table of its pack: the column and the table a tier gate reads.
func configTierTable(cfg *config.Config, connector string) (decide.Tier, *decide.Table) {
	if cfg == nil {
		return decide.TierDefault, decide.Builtin()
	}
	return decideTierOf(cfg.HookPolicyTierForConnector(connector)), configPackTable(cfg, connector)
}

func configPackTable(cfg *config.Config, connector string) *decide.Table {
	if cfg == nil {
		return decide.Builtin()
	}
	return packTable(cfg.ResolveRulePackDir(cfg.EffectiveRulePackRefForConnector(connector)))
}

// toolCallTierTable is the tier and tier table of the proxy's tool-call
// route: the request configuration's, else the proxy's guardrail block
// (toolCallStrictTier reads the same).
func (p *GuardrailProxy) toolCallTierTable(ctx context.Context, cfg *config.Config) (decide.Tier, *decide.Table) {
	connectorName := p.proxyRequestConnector(ctx)
	if cfg != nil {
		return configTierTable(cfg, connectorName)
	}
	p.rtMu.RLock()
	gc := p.cfg
	p.rtMu.RUnlock()
	if gc == nil {
		return decide.TierDefault, decide.Builtin()
	}
	ref := gc.EffectiveRulePackRef(connectorName)
	return decideTierOf(guardrailPackPosture(gc, ref)), guardrailPackTable(gc, ref)
}

// guardrailPackTable is the tier table of ref's pack for a caller that
// holds only the guardrail block, with guardrailPackPosture's folder choice:
// a usable custom_packs entry its own folder, a built-in name the built-in
// table, else ref's folder.
func guardrailPackTable(gc *config.GuardrailConfig, ref config.RulePackRef) *decide.Table {
	if gc == nil {
		return decide.Builtin()
	}
	if ref.Name != "" {
		if _, ok := gc.CustomPacks[ref.Name]; ok && (ManagedEnterpriseActive() || !gc.CustomRulePackFallsBack(ref.Name)) {
			return packTable(gc.CustomRulePackPath(ref.Name))
		}
		if gc.BuiltinRulePackFor(ref.Name) != "" {
			return decide.Builtin()
		}
	}
	return packTable(ref.Dir)
}

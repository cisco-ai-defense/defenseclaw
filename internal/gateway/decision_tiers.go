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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// The tier table of a pack directory is decide.Builtin() with the pack's own
// tiers.yaml column in the pack's own tier (DET111 D4), so a pack's cells,
// not only its tier name, decide its verdicts. A built-in pack's column is
// the built-in table itself (TestShippedTiersMatchBuiltin), so it decides
// with decide.Builtin().
//
// A build notes the table of each pack it loads on that pack
// (notePackTable); a published generation makes the tables of its own packs
// the live ones (publishPackTables). A note is keyed by the pack, weakly, so
// the note of a build that never publishes (superseded, failed) is never
// published by another build's generation and goes with its pack; and a
// directory the published generation no longer loads leaves the live tables
// (DET111 T19 review P3-4: one process-global pending map published every
// build's notes, and the fallback cache was never invalidated).
type packTableNote struct {
	dir   string
	table *decide.Table
}

var (
	// packTableNotes maps weak.Pointer[guardrail.RulePack] to packTableNote.
	packTableNotes sync.Map
	// A profile loaded outside a generation build still uses the table
	// checked at load. Entries disappear with their packs.
	latePackTables sync.Map // directory -> *latePackTable
	// livePackTables is the directory -> table map of the published
	// generation's packs; replaced whole, never written in place.
	livePackTables atomic.Pointer[map[string]*decide.Table]
	// packTableFallback holds the table of a directory no published
	// generation loaded, read from its tiers.yaml once per generation.
	packTableFallback sync.Map // directory -> *decide.Table
)

func notePackTable(pack *guardrail.RulePack, dir string, col *decide.Column) {
	if dir = strings.TrimSpace(dir); dir == "" || pack == nil {
		return
	}
	key := weak.Make(pack)
	packTableNotes.Store(key, packTableNote{dir: dir, table: decide.Builtin().WithColumn(col)})
	runtime.AddCleanup(pack, func(key weak.Pointer[guardrail.RulePack]) { packTableNotes.Delete(key) }, key)
}

type latePackTable struct {
	dir   string
	pack  weak.Pointer[guardrail.RulePack]
	table *decide.Table
}

// publishLatePackTable makes a successfully loaded profile pack's checked
// table available without publishing an unrelated generation candidate.
func publishLatePackTable(pack *guardrail.RulePack) {
	if pack == nil {
		return
	}
	v, ok := packTableNotes.Load(weak.Make(pack))
	if !ok {
		return
	}
	note := v.(packTableNote)
	entry := &latePackTable{dir: note.dir, pack: weak.Make(pack), table: note.table}
	latePackTables.Store(note.dir, entry)
	runtime.AddCleanup(pack, func(e *latePackTable) {
		latePackTables.CompareAndDelete(e.dir, e)
	}, entry)
}

// publishPackTables makes the tables noted on g's packs the live ones and
// drops the fallback reads of the previous generation.
func publishPackTables(g *Generation) {
	tables := make(map[string]*decide.Table)
	if g != nil {
		for _, pack := range g.RulePacks {
			if v, ok := packTableNotes.Load(weak.Make(pack)); ok {
				note := v.(packTableNote)
				tables[note.dir] = note.table
			}
		}
	}
	livePackTables.Store(&tables)
	packTableFallback.Clear()
}

// packTable is the tier table of the pack at dir ("" is decide.Builtin()).
// A tiers.yaml the loader would refuse (invalid_tiers) never loads a
// generation, so here it reads as no column.
func packTable(dir string) *decide.Table {
	if dir = strings.TrimSpace(dir); dir == "" {
		return decide.Builtin()
	}
	if live := livePackTables.Load(); live != nil {
		if table, ok := (*live)[dir]; ok {
			return table
		}
	}
	if v, ok := latePackTables.Load(dir); ok {
		entry := v.(*latePackTable)
		if entry.pack.Value() != nil {
			return entry.table
		}
		latePackTables.CompareAndDelete(dir, entry)
	}
	if v, ok := packTableFallback.Load(dir); ok {
		return v.(*decide.Table)
	}
	var col *decide.Column
	if raw, err := os.ReadFile(filepath.Join(dir, decide.TiersFile)); err == nil {
		col, _ = decide.ParseColumn(raw)
	}
	table := decide.Builtin().WithColumn(col)
	packTableFallback.Store(dir, table)
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

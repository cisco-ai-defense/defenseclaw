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

package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// AI Visibility panel — the in-TUI counterpart of `defenseclaw agent
// usage`. The Overview tab already hosts a "DISCOVERED AI AGENTS"
// box; this dedicated panel is the high-fidelity drill-down: the
// full grouped table, per-component identity / presence, evidence
// drill-in, and `/`-search across every visible field.
//
// Two design choices the existing Overview AI box does NOT make:
//
//  1. We dedup signals at render time the same way cli/cmd_agent.py
//     does. Operators looking at 488 manifest hits for one SDK want
//     ONE row with Count=488, not a wall of identical product rows.
//     The Overview already truncates to a top-5 box, so it dodged
//     this entirely.
//
//  2. We show identity/presence per (ecosystem, name) component
//     just once, on the first row of each group, and we render a
//     row with the same numbers the gateway returned to
//     /api/v1/ai-usage. Confidence MUST agree with the CLI; the
//     gateway's EnrichSignalsWithComponentConfidence stamps the
//     same scores on every signal in a component group, so we
//     can pull from the first one we encounter without a second
//     round-trip to /components.
//
// Live data:
//   * The root Model already polls /api/v1/ai-usage on the slow tick
//     (30s). When the panel is OPEN we additionally fire a poll on
//     every fast (5s) tick so an operator watching the table sees
//     fresh process / state changes within the discovery scan
//     interval (default 5 minutes -- so realistically the GET is
//     idempotent, but we want the "Updated 3s ago" hint to feel
//     live). The same `pollAIUsage()` Cmd already exists in
//     app.go, so we reuse it instead of opening a second HTTP path.
//
// Graceful degradation:
//   * SetSnapshot(nil) is the explicit "sidecar offline" signal --
//     we paint a dim placeholder in View() rather than showing an
//     empty table. Update() in app.go preserves the prior snapshot
//     on transient fetch errors, so a `defenseclaw-gateway restart`
//     does NOT make the panel flap.

// aiVisibilityRow is the dedup'd, render-friendly form of a group
// of AISignals that share (state, product, vendor, ecosystem,
// name). The slice of underlying signals is kept so the detail
// overlay can drill into per-instance evidence (basenames,
// detector match-kind, runtime PID/uptime, etc.).
//
// Normalization choice (mirrors cli/cmd_agent.py): we
// deliberately drop `category` and `detector` from the dedup key
// so a product like "Claude Code" -- which is independently
// discovered by binary, process, mcp, config, shell-history,
// provider-history, and desktop-app detectors -- shows up as ONE
// row with the constituent categories / detectors aggregated
// into list columns. Pre-normalization an operator with Claude
// Code installed saw 7 near-identical rows; post-normalization
// they see one row tagged "via 7 channels" and can drill in for
// the per-detector breakdown.
type aiVisibilityRow struct {
	State     string
	Product   string
	Vendor    string
	Ecosystem string
	Component string
	Version   string

	// Categories / Detectors are populated from EVERY signal in
	// the group, deduped, in discovery order. The renderer
	// joins them with ", " and truncates with "+N" to keep the
	// row from blowing the table width.
	Categories []string
	Detectors  []string

	// Identity/Presence are taken from the first signal in the
	// group that carries them. Per-component confidence is stamped
	// identically across every member (see
	// inventory.EnrichSignalsWithComponentConfidence) so this is
	// safe; using "first non-empty" defends against a future
	// where some detectors omit the score.
	IdentityScore float64
	IdentityBand  string
	PresenceScore float64
	PresenceBand  string

	Count        int
	LastActiveAt time.Time
	Basenames    []string

	// Signals retains the original entries -- ordered as they
	// appeared in the snapshot -- so the detail overlay can render
	// per-instance rows (one per matched file or process) without
	// re-scanning the full snapshot.
	Signals []AIUsageSignal
}

// AIVisibilityPanel renders the AI discovery snapshot as a deduped,
// searchable, drill-downable table. Mirrors SkillsPanel's filter
// pattern (filter / filtering / Apply / IsFiltering) so the global
// `/` filter router in app.go picks it up via the same switch arms.
type AIVisibilityPanel struct {
	snapshot *AIUsageSnapshot

	// Materialized state -- recomputed whenever snapshot or filter
	// changes. We keep both rows (the unfiltered, deduped form)
	// and filtered (the substring-filtered subset View() iterates)
	// so toggling / clearing the filter does NOT require re-walking
	// the raw signals.
	rows     []aiVisibilityRow
	filtered []aiVisibilityRow

	cursor int
	width  int
	height int

	// Filter mode mirrors SkillsPanel.filter / .filtering exactly
	// so the existing handleFilterKey switch in app.go can route
	// keys without a third pattern.
	filter    string
	filtering bool

	// Detail overlay is the per-signal drill-down for the row the
	// cursor is on. We snapshot the row instead of holding a
	// pointer so a refresh that re-orders rows mid-overlay does
	// not change what the operator is looking at.
	detailOpen bool
	detailRow  *aiVisibilityRow

	// scroll is the top-of-view offset into filtered. We let the
	// renderer compute it from cursor/height instead of tracking
	// it as state -- the table is short enough that recomputing
	// per paint is cheaper than threading a scroll offset through
	// every cursor mutation.
}

// NewAIVisibilityPanel returns a fresh, empty panel. The first
// SetSnapshot call (driven by aiUsageUpdateMsg in app.go) populates
// rows; until then View() renders the offline placeholder so an
// operator landing on the panel before the first poll completes
// gets a clear "loading…" state instead of a confusing empty table.
func NewAIVisibilityPanel() AIVisibilityPanel {
	return AIVisibilityPanel{}
}

// SetSnapshot replaces the cached snapshot and rebuilds the row
// cache. nil clears the panel (the Overview offline placeholder
// is mirrored here -- "sidecar offline / discovery disabled").
func (p *AIVisibilityPanel) SetSnapshot(s *AIUsageSnapshot) {
	p.snapshot = s
	p.rebuild()
}

// Snapshot returns the current snapshot for tests / overlays.
func (p *AIVisibilityPanel) Snapshot() *AIUsageSnapshot { return p.snapshot }

// Rows returns the deduped rows pre-filter. Exposed for tests.
func (p *AIVisibilityPanel) Rows() []aiVisibilityRow { return p.rows }

// FilteredRows returns the post-filter rows the table renders.
// Exposed for tests so they can assert the search behaviour without
// parsing the rendered string.
func (p *AIVisibilityPanel) FilteredRows() []aiVisibilityRow { return p.filtered }

// Filter accessors mirror SkillsPanel so handleFilterKey works.
func (p *AIVisibilityPanel) FilterText() string { return p.filter }
func (p *AIVisibilityPanel) IsFiltering() bool  { return p.filtering }
func (p *AIVisibilityPanel) StartFilter()       { p.filtering = true }
func (p *AIVisibilityPanel) StopFilter()        { p.filtering = false }
func (p *AIVisibilityPanel) ClearFilter() {
	p.filter = ""
	p.filtering = false
	p.applyFilter()
}

// SetFilter replaces the substring filter and re-applies. Empty
// filter is the "show everything" sentinel.
func (p *AIVisibilityPanel) SetFilter(f string) {
	p.filter = f
	p.applyFilter()
}

// IsDetailOpen reports whether the per-signal drill-down overlay
// is active. Used by panelExclusive in app.go so digit keys are
// routed to the panel (close-on-Esc) instead of switching tabs
// while the overlay is up.
func (p *AIVisibilityPanel) IsDetailOpen() bool { return p.detailOpen }

// ToggleDetail opens/closes the per-row drill-down. When opening
// we snapshot the row at the current cursor; if the cursor is out
// of range (empty filtered list) the call is a no-op.
func (p *AIVisibilityPanel) ToggleDetail() {
	if p.detailOpen {
		p.detailOpen = false
		p.detailRow = nil
		return
	}
	if p.cursor < 0 || p.cursor >= len(p.filtered) {
		return
	}
	row := p.filtered[p.cursor]
	p.detailRow = &row
	p.detailOpen = true
}

// SetSize is called by the root Model on WindowSize messages.
func (p *AIVisibilityPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

// CursorUp / CursorDown move the highlight; they intentionally do
// NOT trigger a re-poll -- the table only changes when the slow /
// panel-active tick brings in a new snapshot.
func (p *AIVisibilityPanel) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}

func (p *AIVisibilityPanel) CursorDown() {
	if p.cursor < len(p.filtered)-1 {
		p.cursor++
	}
}

// rebuild collapses the snapshot's signals into deduped rows. The
// grouping key matches the default normalized grouping in
// cli/defenseclaw/commands/cmd_agent.py::_summarize_ai_usage_signals_full
// (i.e. category and detector are NOT in the key; they're
// aggregated as Categories / Detectors list columns) so an
// operator switching between `agent usage` (CLI default) and
// this panel sees the SAME row count and the SAME aggregated
// categories/detectors per row.
func (p *AIVisibilityPanel) rebuild() {
	p.rows = nil
	if p.snapshot == nil {
		p.applyFilter()
		return
	}
	type rowKey struct {
		state, product, vendor, ecosystem, name, version string
	}
	groups := make(map[rowKey]*aiVisibilityRow, len(p.snapshot.Signals))
	order := make([]rowKey, 0, len(p.snapshot.Signals))

	for _, sig := range p.snapshot.Signals {
		eco, name, version := "", "", sig.Version
		if sig.Component != nil {
			eco = strings.ToLower(sig.Component.Ecosystem)
			name = strings.ToLower(sig.Component.Name)
			if sig.Component.Version != "" {
				version = sig.Component.Version
			}
		}
		k := rowKey{
			state:     sig.State,
			product:   sig.Product,
			vendor:    sig.Vendor,
			ecosystem: eco,
			name:      name,
			version:   version,
		}
		row, ok := groups[k]
		if !ok {
			row = &aiVisibilityRow{
				State:     sig.State,
				Product:   sig.Product,
				Vendor:    sig.Vendor,
				Ecosystem: "",
				Component: "",
				Version:   version,
			}
			if sig.Component != nil {
				// Preserve the original case for display --
				// lowercased only goes into the dedup key.
				row.Ecosystem = sig.Component.Ecosystem
				row.Component = sig.Component.Name
			}
			groups[k] = row
			order = append(order, k)
		}
		row.Count++
		row.Signals = append(row.Signals, sig)
		// Aggregate categories / detectors in discovery order.
		// We dedupe via a tiny linear scan because n is small
		// (typically 1..7) and a map allocation per signal would
		// dominate this hot path.
		if sig.Category != "" && !containsString(row.Categories, sig.Category) {
			row.Categories = append(row.Categories, sig.Category)
		}
		if sig.Detector != "" && !containsString(row.Detectors, sig.Detector) {
			row.Detectors = append(row.Detectors, sig.Detector)
		}
		// First non-empty wins -- subsequent signals in the same
		// component group MUST agree (gateway-side enrichment), but
		// we defend against a future where they don't.
		if row.IdentityBand == "" && sig.IdentityBand != "" {
			row.IdentityBand = sig.IdentityBand
			row.IdentityScore = sig.IdentityScore
		}
		if row.PresenceBand == "" && sig.PresenceBand != "" {
			row.PresenceBand = sig.PresenceBand
			row.PresenceScore = sig.PresenceScore
		}
		// Track the most recent last_active_at across the group so
		// the table column reflects "freshest evidence I have for
		// this component", not "first signal I happened to see".
		if sig.LastActiveAt != nil && sig.LastActiveAt.After(row.LastActiveAt) {
			row.LastActiveAt = *sig.LastActiveAt
		}
		// We can't peek inside AIUsageSignal for basenames -- the
		// wire shape doesn't surface them as a slice. The detail
		// overlay therefore renders per-signal rows directly from
		// row.Signals; the top-level "Sample" column shows the
		// signature name + " ×N" instead.
	}

	out := make([]aiVisibilityRow, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
	}

	// Sort by state weight (new > changed > active > seen > gone),
	// then descending count, then product alphabetically. Mirrors
	// the CLI grouped sort so the two views read the same; we no
	// longer have a single category to tie-break on (it's an
	// aggregated list now), so we fall straight through to product
	// which is the operator-meaningful identity anyway.
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := stateWeight(out[i].State), stateWeight(out[j].State)
		if ri != rj {
			return ri < rj
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Product < out[j].Product
	})

	p.rows = out
	p.applyFilter()
}

// stateWeight orders signal states for the table -- new things go
// to the top so an operator scanning the Visibility tab spots fresh
// detections first. Mirrors `_AI_USAGE_STATE_ORDER` in the Python
// CLI so both renderers agree.
func stateWeight(state string) int {
	switch strings.ToLower(state) {
	case "new":
		return 0
	case "changed":
		return 1
	case "active":
		return 2
	case "seen":
		return 3
	case "gone":
		return 4
	}
	return 9
}

// applyFilter rebuilds p.filtered from p.rows by case-insensitive
// substring match against every column we render. Cursor is clamped
// so a search that drops the current row keeps the highlight inside
// the visible set.
func (p *AIVisibilityPanel) applyFilter() {
	if p.filter == "" {
		p.filtered = p.rows
	} else {
		q := strings.ToLower(p.filter)
		p.filtered = nil
		for _, r := range p.rows {
			parts := []string{
				r.State, r.Product, r.Vendor,
				r.Ecosystem, r.Component, r.Version,
				r.IdentityBand, r.PresenceBand,
			}
			// Search EVERY constituent category / detector so a
			// query for "binary" still matches Claude Code even
			// after the dedup pass collapsed the per-detector
			// rows. We use the full list, not just a joined
			// truncated cell, so the "+N" suffix never hides a
			// legitimate match.
			parts = append(parts, r.Categories...)
			parts = append(parts, r.Detectors...)
			hay := strings.ToLower(strings.Join(parts, " "))
			if strings.Contains(hay, q) {
				p.filtered = append(p.filtered, r)
			}
		}
	}
	if p.cursor >= len(p.filtered) {
		if len(p.filtered) > 0 {
			p.cursor = len(p.filtered) - 1
		} else {
			p.cursor = 0
		}
	}
}

// View renders the panel. Layout, top to bottom:
//   * Header with summary counts + "(updated Ns ago)" freshness
//   * Filter line, present only when /-search is active
//   * Table of rows (state, product, component(eco), version,
//     vendor, detector, count, identity, presence, last active)
//   * Footer hint with key bindings
// When the detail overlay is open we replace the table with the
// per-signal drill-down -- handleAIVisibilityKey sends Esc to
// ToggleDetail, restoring the table.
func (p *AIVisibilityPanel) View(width, height int) string {
	// Always honor SetSize over the inline arg if it was called;
	// width/height fall back to whatever the caller passed when
	// the panel hasn't been sized yet (e.g. tests).
	w, h := width, height
	if p.width > 0 {
		w = p.width
	}
	if p.height > 0 {
		h = p.height
	}
	if w < 40 {
		w = 40
	}
	if h < 6 {
		h = 6
	}

	border := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(w - 2)

	if p.snapshot == nil {
		hint := lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render(
			"AI discovery snapshot not yet available.\n" +
				"Waiting for the first poll of /api/v1/ai-usage…\n" +
				"If this stays blank: ensure the gateway is running and that\n" +
				"DEFENSECLAW_GATEWAY_TOKEN matches the configured token.")
		return border.Render("AI Visibility\n\n" + hint)
	}

	if p.detailOpen && p.detailRow != nil {
		return border.Render(p.renderDetail(w))
	}

	var b strings.Builder
	b.WriteString(p.renderHeader())
	b.WriteString("\n")

	if p.filtering || p.filter != "" {
		fStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
		marker := "/"
		if !p.filtering {
			marker = "/(applied)"
		}
		fmt.Fprintf(&b, "%s %s\n", fStyle.Render(marker), p.filter)
	}

	if len(p.filtered) == 0 {
		empty := lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render(
			"No matching signals.")
		b.WriteString(empty)
		b.WriteString("\n\n")
		b.WriteString(p.renderFooter())
		return border.Render(b.String())
	}

	b.WriteString(p.renderTable(w))
	b.WriteString("\n")
	b.WriteString(p.renderFooter())
	return border.Render(b.String())
}

func (p *AIVisibilityPanel) renderHeader() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("87")).
		Render("AI VISIBILITY")
	s := p.snapshot.Summary
	// Collapse zero-valued counts so a steady-state inventory
	// reads as `active=755  files=2103` rather than the noisy
	// `active=755  new=0  changed=0  gone=0  files=2103`. Always
	// keep `active` and `files` so an operator can confirm the
	// scan ran even when no churn happened. Use color to make
	// non-zero churn (new / changed / gone) visually pop.
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("84"))   // new
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("220")) // changed
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("203"))    // gone
	parts := []string{dim.Render(fmt.Sprintf("active=%d", s.ActiveSignals))}
	if s.NewSignals > 0 {
		parts = append(parts, green.Render(fmt.Sprintf("new=%d", s.NewSignals)))
	}
	if s.ChangedSignals > 0 {
		parts = append(parts, yellow.Render(fmt.Sprintf("changed=%d", s.ChangedSignals)))
	}
	if s.GoneSignals > 0 {
		parts = append(parts, red.Render(fmt.Sprintf("gone=%d", s.GoneSignals)))
	}
	parts = append(parts, dim.Render(fmt.Sprintf("files=%d", s.FilesScanned)))
	if !p.snapshot.FetchedAt.IsZero() {
		parts = append(parts, dim.Render(fmt.Sprintf(
			"(updated %s ago)", humanizeAge(time.Since(p.snapshot.FetchedAt)))))
	}
	return title + "  " + strings.Join(parts, "  ")
}

func (p *AIVisibilityPanel) renderFooter() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	if p.detailOpen {
		return dim.Render("Esc close detail · j/k scroll signals")
	}
	return dim.Render(
		"j/k navigate · Enter detail · / search · r refresh · Esc clear filter",
	)
}

// renderTable emits a fixed-column table similar in style to the
// Overview AI box. We don't pull in bubbles/table because (a) it's
// not used elsewhere in this package and (b) we need a custom
// "blank confidence cell after first row of group" treatment that
// the bubbles helper does not support out of the box.
//
// Layout invariant: EVERY cell is rendered through padTrunc so
// values that would otherwise overflow (a 27-char Categories
// aggregate, a 23-char component name) are clipped with "…"
// instead of pushing all subsequent cells off the right edge.
// The previous renderer used padRight only -- which silently
// expanded the column when content overflowed and left adjacent
// rows visibly drifting against the header.
func (p *AIVisibilityPanel) renderTable(width int) string {
	// Column widths sized to the 95th-percentile of observed
	// values across Anthropic / OpenAI / DefenseClaw / Vercel /
	// Anysphere catalogs (sum 184 + 10 separators = 194 chars).
	// On terminals narrower than ~200 chars the panel border
	// will wrap, but cells will STILL line up with the header
	// because every cell is padTrunc'd to its declared width.
	//
	// Confidence cell width is sized to fit "very_high (100%)"
	// (16 chars) so the bands never wrap.
	const (
		wState = 7
		wCat   = 28
		wProd  = 22
		wComp  = 26
		wVer   = 8
		wVend  = 14
		wDet   = 26
		wCnt   = 6
		wConf  = 16
		wAge   = 11
	)
	hdrStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("250"))
	rowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	selStyle := lipgloss.NewStyle().
		Bold(true).
		Background(lipgloss.Color("237")).
		Foreground(lipgloss.Color("231"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	// Plural headers reflect the normalization choice -- each cell
	// in the Categories / Detectors columns lists every detector
	// that surfaced this product, joined with ", " and "+N"-truncated
	// (see formatCSV) so the row width stays bounded.
	header := hdrStyle.Render(strings.Join([]string{
		padTrunc("State", wState),
		padTrunc("Categories", wCat),
		padTrunc("Product", wProd),
		padTrunc("Component", wComp),
		padTrunc("Version", wVer),
		padTrunc("Vendor", wVend),
		padTrunc("Detectors", wDet),
		padLeftTrunc("Count", wCnt),
		padTrunc("Identity", wConf),
		padTrunc("Presence", wConf),
		padTrunc("Active", wAge),
	}, " "))

	// Visible window: leave 6 lines of chrome (header + filter +
	// border + footer + spacing). Floor at 5 so a tiny terminal
	// still shows something instead of an empty table.
	visible := p.height - 6
	if visible < 5 {
		visible = 5
	}
	if visible > len(p.filtered) {
		visible = len(p.filtered)
	}
	// Scroll so cursor stays in view: simple anchor-on-cursor.
	top := 0
	if p.cursor >= visible {
		top = p.cursor - visible + 1
	}
	if top+visible > len(p.filtered) {
		top = len(p.filtered) - visible
	}
	if top < 0 {
		top = 0
	}

	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n")

	// Per-component dedup of confidence: blank Identity / Presence
	// after the first row of a (ecosystem, name) group so a noisy
	// product like @anthropic-ai/sdk × N versions doesn't paint
	// the same band on every line. Tracks the previous key in the
	// VISIBLE slice -- detail mode shows everything regardless.
	type confKey struct{ eco, name, prod, vendor string }
	var prev confKey
	var hasPrev bool

	for i := top; i < top+visible && i < len(p.filtered); i++ {
		r := p.filtered[i]
		ck := confKey{
			eco:    strings.ToLower(r.Ecosystem),
			name:   strings.ToLower(r.Component),
			prod:   strings.ToLower(r.Product),
			vendor: strings.ToLower(r.Vendor),
		}
		identityCell := formatConf(r.IdentityScore, r.IdentityBand)
		presenceCell := formatConf(r.PresenceScore, r.PresenceBand)
		if hasPrev && ck == prev {
			identityCell = ""
			presenceCell = ""
		}
		prev = ck
		hasPrev = true

		comp := r.Component
		if r.Ecosystem != "" && comp != "" {
			comp = comp + " (" + r.Ecosystem + ")"
		}
		age := ""
		if !r.LastActiveAt.IsZero() {
			age = humanizeAge(time.Since(r.LastActiveAt)) + " ago"
		}

		line := strings.Join([]string{
			padTrunc(r.State, wState),
			padTrunc(formatCSV(r.Categories, 2), wCat),
			padTrunc(r.Product, wProd),
			padTrunc(comp, wComp),
			padTrunc(r.Version, wVer),
			padTrunc(r.Vendor, wVend),
			padTrunc(formatCSV(r.Detectors, 2), wDet),
			padLeftTrunc(fmt.Sprintf("%d", r.Count), wCnt),
			padTrunc(identityCell, wConf),
			padTrunc(presenceCell, wConf),
			padTrunc(age, wAge),
		}, " ")

		if i == p.cursor {
			b.WriteString(selStyle.Render(line))
		} else {
			b.WriteString(rowStyle.Render(line))
		}
		b.WriteString("\n")
	}

	if len(p.filtered) > visible {
		b.WriteString(dim.Render(fmt.Sprintf(
			"(%d of %d shown — j/k or PgUp/PgDn)",
			visible, len(p.filtered))))
		b.WriteString("\n")
	}
	_ = width
	return b.String()
}

// renderDetail shows the per-signal drill-down for the currently
// highlighted row. For each underlying signal we surface the
// fields that uniquely identify the install (signature ID,
// detector, source, last seen / first seen, runtime PID/uptime).
// The CLI's `agent usage --detail` is the analogue; this view
// keeps to the most operator-relevant fields so the box fits
// without horizontal scroll.
func (p *AIVisibilityPanel) renderDetail(width int) string {
	r := *p.detailRow
	hdrStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("87"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	var b strings.Builder
	b.WriteString(hdrStyle.Render("AI VISIBILITY — detail"))
	b.WriteString("\n")
	// Build the header segment-by-segment so a CLI product
	// without a component (Cursor, Claude Code, Codex, ...)
	// doesn't render the awkward "seen · Cursor ·  × 7
	// signal(s)" with a trailing dot+space sandwiching empty
	// text. We also include the ecosystem in parens when the
	// component is present, mirroring the table column.
	segs := []string{r.State, r.Product}
	if comp := strings.TrimSpace(r.Component); comp != "" {
		if eco := strings.TrimSpace(r.Ecosystem); eco != "" {
			segs = append(segs, comp+" ("+eco+")")
		} else {
			segs = append(segs, comp)
		}
	}
	b.WriteString(dim.Render(fmt.Sprintf(
		"%s × %d signal(s)",
		strings.Join(segs, " · "), r.Count)))
	b.WriteString("\n\n")

	if r.IdentityBand != "" || r.PresenceBand != "" {
		b.WriteString(fmt.Sprintf(
			"  Identity: %s    Presence: %s\n\n",
			formatConf(r.IdentityScore, r.IdentityBand),
			formatConf(r.PresenceScore, r.PresenceBand)))
	}

	for i, sig := range r.Signals {
		if i >= 50 {
			b.WriteString(dim.Render(fmt.Sprintf(
				"  …and %d more (use `defenseclaw agent usage --detail --json` for the full list)",
				len(r.Signals)-i)))
			b.WriteString("\n")
			break
		}
		fmt.Fprintf(&b, "  • %s\n", sigID(sig))
		if sig.Detector != "" {
			fmt.Fprintf(&b, "      detector=%s", sig.Detector)
			if sig.Source != "" {
				fmt.Fprintf(&b, "  source=%s", sig.Source)
			}
			b.WriteString("\n")
		}
		if sig.Runtime != nil && sig.Runtime.PID > 0 {
			fmt.Fprintf(&b, "      runtime: pid=%d", sig.Runtime.PID)
			if sig.Runtime.User != "" {
				fmt.Fprintf(&b, " user=%s", sig.Runtime.User)
			}
			if sig.Runtime.UptimeSec > 0 {
				fmt.Fprintf(&b, " up=%s",
					humanizeAge(time.Duration(sig.Runtime.UptimeSec)*time.Second))
			}
			if sig.Runtime.Comm != "" {
				fmt.Fprintf(&b, " comm=%s", sig.Runtime.Comm)
			}
			b.WriteString("\n")
		}
		if sig.LastActiveAt != nil {
			fmt.Fprintf(&b, "      last active: %s ago\n",
				humanizeAge(time.Since(*sig.LastActiveAt)))
		} else if !sig.LastSeen.IsZero() {
			fmt.Fprintf(&b, "      last seen:   %s ago\n",
				humanizeAge(time.Since(sig.LastSeen)))
		}
	}

	b.WriteString("\n")
	b.WriteString(p.renderFooter())
	_ = width
	return b.String()
}

// sigID picks the most informative identifier on a signal: the
// signature_id when present (catalog entries), then the explicit
// name, then the signal_id. Falls back to "(unknown)" so a row
// without any of those still renders something parseable.
func sigID(s AIUsageSignal) string {
	for _, c := range []string{s.SignatureID, s.Name, s.SignalID} {
		if v := strings.TrimSpace(c); v != "" {
			return v
		}
	}
	return "(unknown)"
}

// formatConf renders "<band> (XX%)" and gracefully handles either
// half being missing -- mirrors the CLI _format_confidence so the
// two surfaces present the same string.
func formatConf(score float64, band string) string {
	band = strings.TrimSpace(band)
	if band == "" && score == 0 {
		return ""
	}
	pct := int(score*100 + 0.5)
	if band == "" {
		return fmt.Sprintf("%d%%", pct)
	}
	return fmt.Sprintf("%s (%d%%)", band, pct)
}

// humanizeAge is a compact 2-unit duration printer used by the
// "(updated Ns ago)" header and the per-signal "last active". We
// do NOT pull in time.Format because we want operator-friendly
// output (`3m`, `2h`, `1d4h`) rather than RFC timestamps.
func humanizeAge(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	if d < time.Second {
		return "0s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if hours == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd%dh", days, hours)
}

// padLeft is the right-aligned counterpart of the package-scope
// padRight (defined in inventory.go and reused here for the
// left-aligned columns). Pads only -- callers wanting hard
// truncation should reach for padLeftTrunc instead.
func padLeft(s string, w int) string {
	vw := lipgloss.Width(s)
	if vw >= w {
		return s
	}
	return strings.Repeat(" ", w-vw) + s
}

// padTrunc enforces EXACT column width: clips overflow with "…"
// (via the package-scope `truncate`) and then pads the result so
// every cell is `w` runes wide. This is the layout invariant the
// table renderer relies on -- without it, a single 27-char
// Categories aggregate quietly pushes Product, Component, Vendor,
// Detectors, Count, Identity, Presence, and Active off the right
// edge and the visual alignment with the header collapses.
//
// Edge cases:
//
//   - empty string → w spaces (a clean blank cell)
//   - w <= 0       → empty string (defensive: never panic on a
//     pathological column width)
//   - exact-fit s  → s unchanged (no spurious "…")
func padTrunc(s string, w int) string {
	if w <= 0 {
		return ""
	}
	t := truncate(s, w)
	vw := lipgloss.Width(t)
	if vw >= w {
		return t
	}
	return t + strings.Repeat(" ", w-vw)
}

// padLeftTrunc is the right-aligned variant of padTrunc. Used for
// the Count column so multi-digit values stay flush to the right
// regardless of magnitude (1, 11, 685, etc.).
func padLeftTrunc(s string, w int) string {
	if w <= 0 {
		return ""
	}
	t := truncate(s, w)
	vw := lipgloss.Width(t)
	if vw >= w {
		return t
	}
	return strings.Repeat(" ", w-vw) + t
}

// containsString is the linear membership check we use during
// rebuild() to dedupe small Categories / Detectors slices. The
// per-row slice is typically 1..7 long, so a map allocation per
// signal would dominate this hot path. Lives in this file (not a
// shared util) because the package already has plenty of inlined
// utility helpers (humanizeAge, formatConf, padLeft) and we want
// the cross-references obvious from one place.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// formatCSV renders up to `limit` items joined with ", " plus a
// "+N" suffix for the rest. Mirrors `_format_csv_truncated` in
// cli/cmd_agent.py so the two surfaces emit the same compact
// "<a>, <b> (+N)" cell shape for the rolled-up Categories /
// Detectors columns.
func formatCSV(items []string, limit int) string {
	if len(items) == 0 {
		return ""
	}
	if limit <= 0 || limit > len(items) {
		return strings.Join(items, ", ")
	}
	head := strings.Join(items[:limit], ", ")
	if extra := len(items) - limit; extra > 0 {
		return fmt.Sprintf("%s (+%d)", head, extra)
	}
	return head
}

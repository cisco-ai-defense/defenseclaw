// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Registries panel sub-tabs. The numbering matches the in-panel
// 1/2/3 keybindings so the constants double as positional indices in
// the View() rendering.
const (
	registriesTabSources = iota
	registriesTabEntries
	registriesTabApproved
	registriesTabCount
)

var registriesTabNames = [registriesTabCount]string{
	"Sources", "Entries", "Approved",
}

// registryEntryRow is one verdict row read from
// ~/.defenseclaw/registries/<id>/index.json. The struct is intentionally
// loose-typed strings so we can render it without a hard dependency on
// the cli/defenseclaw/registries Python types — the JSON file is the
// contract between the two sides.
type registryEntryRow struct {
	SourceID  string `json:"source_id"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Severity  string `json:"severity"`
	Findings  int    `json:"findings"`
	Approved  bool   `json:"approved"`
	Rejected  bool   `json:"rejected"`
	Transport string `json:"transport"`
	Command   string `json:"command"`
	URL       string `json:"url"`
	SourceURL string `json:"source_url"`
}

// indexFile mirrors the cache.SourceIndex JSON shape — only the
// fields the TUI actually renders. New fields can land in the JSON
// without forcing a TUI release; we ignore unknown keys.
type indexFile struct {
	SourceID     string           `json:"source_id"`
	FetchedAt    string           `json:"fetched_at"`
	Publisher    string           `json:"publisher"`
	EntryCount   int              `json:"entry_count"`
	CleanCount   int              `json:"clean_count"`
	WarningCount int              `json:"warning_count"`
	BlockedCount int              `json:"blocked_count"`
	ErrorCount   int              `json:"error_count"`
	Verdicts     []map[string]any `json:"verdicts"`
}

// RegistriesPanel surfaces external skill / MCP catalog sources to
// operators. It mirrors the SkillsPanel/ToolsPanel surface (Refresh,
// CursorUp/Down, Selected, ScrollBy, View) so the same router code in
// app.go can drive it. Sub-tabs are switched with 1/2/3.
//
// The panel is read-only by design: every mutation (sync, approve,
// reject, edit, remove) is a shell-out to `defenseclaw registry ...`
// dispatched via the shared CommandExecutor. That keeps the
// CLI/TUI behaviour identical and means tests for the underlying
// behaviour live in cli/tests/test_cmd_registry.py.
type RegistriesPanel struct {
	cfg      *config.Config
	executor *CommandExecutor
	dataDir  string

	tab     int
	cursor  int
	width   int
	height  int
	message string

	// filterEntryName is set when an external caller (Skills /
	// MCPs panel cross-link) wants the Entries tab to focus on a
	// single named entry. Cleared on tab change so it doesn't
	// silently filter unrelated views.
	filterEntryName string

	// Loaded data — recomputed on each Refresh().
	sources []config.RegistrySource
	indexes map[string]indexFile
}

// NewRegistriesPanel constructs the panel bound to a live config (for
// the source list) and the data dir (for the on-disk index files).
func NewRegistriesPanel(cfg *config.Config, executor *CommandExecutor) RegistriesPanel {
	dataDir := ""
	if cfg != nil {
		dataDir = cfg.DataDir
	}
	p := RegistriesPanel{
		cfg:      cfg,
		executor: executor,
		dataDir:  dataDir,
		indexes:  map[string]indexFile{},
	}
	p.Refresh()
	return p
}

// SetSize is the standard panel-API hook so the resize router can
// keep the list viewport aligned with the terminal.
func (p *RegistriesPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

// SetTab jumps directly to a sub-tab; used by external callers
// (Skills / MCPs panels) that want to land on Entries with a filter
// already applied.
func (p *RegistriesPanel) SetTab(tab int) {
	if tab < 0 || tab >= registriesTabCount {
		return
	}
	if tab != p.tab {
		p.cursor = 0
		p.filterEntryName = ""
	}
	p.tab = tab
}

// FocusEntry pre-loads the Entries tab and pins the cursor on the
// requested (type, name). Used by the Skills / MCPs panels' 'R'
// keybind so muscle memory carries over.
//
// On a hit: the filter is set so the operator only sees rows for
// that name (useful when a skill is approved by multiple sources).
// On a miss: the filter is cleared so the operator lands on the
// full Entries table instead of an empty filtered view — naming
// conventions differ between local installs and registry manifests
// (e.g. smithery normalises “@scope/name“ to “scope-name“), and
// we'd rather show the operator something useful than nothing.
func (p *RegistriesPanel) FocusEntry(entryType, name string) {
	p.tab = registriesTabEntries

	// Try the filtered view first. Build rows directly so the
	// match check doesn't see a stale filterEntryName.
	p.filterEntryName = ""
	rows := p.entryRows()
	for i, r := range rows {
		if r.Type == entryType && r.Name == name {
			p.cursor = i
			p.filterEntryName = entryType + ":" + name
			// Re-fetch with the filter in place so cursor maps
			// onto the post-filter index — entryRows() returns a
			// stable order so the existing match still wins.
			filtered := p.entryRows()
			for j, fr := range filtered {
				if fr.Type == entryType && fr.Name == name {
					p.cursor = j
					return
				}
			}
			return
		}
	}
	// No match — leave the filter cleared so the operator sees the
	// full table and can pick the correct row themselves.
	p.cursor = 0
}

// Refresh re-reads the source list from cfg and the on-disk indexes.
// Cheap (one file per source) so we call it on tab changes too.
func (p *RegistriesPanel) Refresh() {
	if p.cfg == nil {
		return
	}
	p.sources = append(p.sources[:0], p.cfg.Registries.Sources...)
	sort.SliceStable(p.sources, func(i, j int) bool {
		return p.sources[i].ID < p.sources[j].ID
	})

	p.indexes = map[string]indexFile{}
	for _, s := range p.sources {
		idx, err := loadRegistryIndex(p.dataDir, s.ID)
		if err == nil {
			p.indexes[s.ID] = idx
		}
	}
	p.message = ""
	if p.cursor < 0 {
		p.cursor = 0
	}
	max := p.rowCount() - 1
	if p.cursor > max && max >= 0 {
		p.cursor = max
	}
}

// CursorUp / CursorDown / ScrollBy keep the panel responsive to the
// shared list-navigation keys handled in app.go.
func (p *RegistriesPanel) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}

func (p *RegistriesPanel) CursorDown() {
	if p.cursor < p.rowCount()-1 {
		p.cursor++
	}
}

func (p *RegistriesPanel) ScrollBy(delta int) {
	p.cursor += delta
	if p.cursor < 0 {
		p.cursor = 0
	}
	if p.cursor >= p.rowCount() {
		p.cursor = p.rowCount() - 1
		if p.cursor < 0 {
			p.cursor = 0
		}
	}
}

// CurrentTab returns the active sub-tab index (used by tests).
func (p *RegistriesPanel) CurrentTab() int { return p.tab }

// Cursor / RowCount accessors for tests.
func (p *RegistriesPanel) Cursor() int   { return p.cursor }
func (p *RegistriesPanel) RowCount() int { return p.rowCount() }

func (p *RegistriesPanel) SetCursor(i int) {
	if i < 0 {
		i = 0
	}
	max := p.rowCount() - 1
	if i > max {
		i = max
	}
	if i < 0 {
		i = 0
	}
	p.cursor = i
}

func (p *RegistriesPanel) TabHitTest(x int) int {
	cursor := 0
	for i := 0; i < registriesTabCount; i++ {
		label := fmt.Sprintf("[%d] %s", i+1, registriesTabNames[i])
		w := lipgloss.Width(label)
		if x >= cursor && x < cursor+w {
			return i
		}
		cursor += w + 2
	}
	return -1
}

// SelectedSource returns the highlighted source on the Sources tab,
// or nil if the tab/cursor combination doesn't address a source.
func (p *RegistriesPanel) SelectedSource() *config.RegistrySource {
	if p.tab != registriesTabSources {
		return nil
	}
	if p.cursor < 0 || p.cursor >= len(p.sources) {
		return nil
	}
	return &p.sources[p.cursor]
}

// SelectedEntry returns the highlighted entry on the Entries / Approved
// tabs. Nil when the tab is Sources or the row count is zero.
func (p *RegistriesPanel) SelectedEntry() *registryEntryRow {
	rows := p.entryRows()
	if p.cursor < 0 || p.cursor >= len(rows) {
		return nil
	}
	return &rows[p.cursor]
}

// HandleKey processes a panel-local keystroke. Returns (handled, label,
// argv, hint). When `handled` is false the global router falls
// through to its standard handlers.
func (p *RegistriesPanel) HandleKey(key string) (bool, string, []string, string) {
	switch key {
	case "1":
		p.SetTab(registriesTabSources)
		return true, "", nil, ""
	case "2":
		p.SetTab(registriesTabEntries)
		return true, "", nil, ""
	case "3":
		p.SetTab(registriesTabApproved)
		return true, "", nil, ""
	case "r":
		p.Refresh()
		return true, "", nil, "Refreshed."
	case "s":
		// 's' on the Sources tab triggers `registry sync <id>`. On
		// Entries / Approved, it syncs the source the cursor is on.
		sid := p.cursorSourceID()
		if sid == "" {
			return true, "", nil, "(no source selected)"
		}
		return true, "registry sync " + sid,
			[]string{"registry", "sync", sid, "--json"},
			fmt.Sprintf("Syncing %s ...", sid)
	case "S":
		return true, "registry sync --all",
			[]string{"registry", "sync", "--all", "--json"},
			"Syncing all enabled sources ..."
	case "a":
		// approve highlighted entry
		row := p.SelectedEntry()
		if row == nil {
			return true, "", nil, "(no entry selected)"
		}
		return true, fmt.Sprintf("registry approve %s %s", row.SourceID, row.Name),
			[]string{
				"registry", "approve", row.SourceID, row.Name,
				"--type", row.Type, "--json",
			},
			"Approving " + row.Name
	case "x":
		row := p.SelectedEntry()
		if row == nil {
			return true, "", nil, "(no entry selected)"
		}
		return true, fmt.Sprintf("registry reject %s %s", row.SourceID, row.Name),
			[]string{
				"registry", "reject", row.SourceID, row.Name,
				"--type", row.Type, "--json",
			},
			"Rejecting " + row.Name
	case "d":
		// `d` removes the highlighted source — mirrors the Skills /
		// MCPs unblock convention. Only fires on Sources tab to
		// avoid accidental deletes from Entries.
		if p.tab != registriesTabSources {
			return false, "", nil, ""
		}
		src := p.SelectedSource()
		if src == nil {
			return true, "", nil, "(no source selected)"
		}
		return true, "registry remove " + src.ID,
			[]string{
				"registry", "remove", src.ID,
				"--non-interactive", "--json",
			},
			"Removing " + src.ID
	}
	return false, "", nil, ""
}

// View renders the panel. Layout: header (tab bar + filter hint) →
// table → footer (per-tab keybind cheatsheet).
func (p *RegistriesPanel) View(width, height int) string {
	if width > 0 {
		p.width = width
	}
	if height > 0 {
		p.height = height
	}
	if p.message != "" {
		return p.message
	}

	var b strings.Builder
	b.WriteString(p.renderTabBar())
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", maxInt(20, p.width-2)))
	b.WriteString("\n")

	switch p.tab {
	case registriesTabSources:
		b.WriteString(p.renderSourcesTable())
	case registriesTabEntries:
		b.WriteString(p.renderEntriesTable(false))
	case registriesTabApproved:
		b.WriteString(p.renderEntriesTable(true))
	}

	b.WriteString("\n")
	b.WriteString(p.renderFooter())
	return b.String()
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

func (p *RegistriesPanel) renderTabBar() string {
	parts := make([]string, 0, registriesTabCount)
	for i := 0; i < registriesTabCount; i++ {
		label := fmt.Sprintf("[%d] %s", i+1, registriesTabNames[i])
		if i == p.tab {
			label = lipgloss.NewStyle().
				Foreground(lipgloss.Color("213")).
				Bold(true).
				Render(label)
		} else {
			label = lipgloss.NewStyle().
				Foreground(lipgloss.Color("242")).
				Render(label)
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, "  ")
}

func (p *RegistriesPanel) renderFooter() string {
	hints := []string{}
	switch p.tab {
	case registriesTabSources:
		hints = []string{
			"[s]ync", "[S]ync all", "[d]elete", "[r]efresh",
			"[1-3] tabs",
		}
	case registriesTabEntries:
		hints = []string{
			"[a]pprove", "[x] reject", "[s]ync source",
			"[r]efresh", "[1-3] tabs",
		}
	case registriesTabApproved:
		hints = []string{
			"[x] reject", "[s]ync source", "[r]efresh", "[1-3] tabs",
		}
	}
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("242")).
		Render(strings.Join(hints, "  "))
}

func (p *RegistriesPanel) renderSourcesTable() string {
	if len(p.sources) == 0 {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("242")).
			Render("No registry sources configured. Run `defenseclaw registry add` or use the Setup wizard.")
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf(
		"  %-22s %-10s %-7s %-3s %-22s %s\n",
		"ID", "KIND", "CONTENT", "ON", "LAST SYNC", "STATUS",
	))
	for i, s := range p.sources {
		marker := "  "
		if i == p.cursor {
			marker = "» "
		}
		on := "no"
		if s.Enabled {
			on = "yes"
		}
		last := s.LastSync
		if last == "" {
			last = "(never)"
		}
		status := s.LastStatus
		if status == "" {
			status = "-"
		}
		row := fmt.Sprintf(
			"%s%-22s %-10s %-7s %-3s %-22s %s",
			marker, truncate(s.ID, 22), s.Kind, s.Content, on, last,
			truncate(status, maxInt(8, p.width-72)),
		)
		if i == p.cursor {
			row = lipgloss.NewStyle().Bold(true).Render(row)
		}
		b.WriteString(row + "\n")
	}
	return b.String()
}

func (p *RegistriesPanel) renderEntriesTable(approvedOnly bool) string {
	rows := p.entryRowsFiltered(approvedOnly)
	if len(rows) == 0 {
		hint := "Sync a source to populate this view."
		if approvedOnly {
			hint = "No entries approved yet. Press 'a' on the Entries tab to approve one."
		}
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("242")).
			Render(hint)
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf(
		"  %-20s %-22s %-6s %-9s %-7s %-3s %s\n",
		"SOURCE", "NAME", "TYPE", "STATUS", "SEV", "A/R", "LOCATION",
	))
	for i, r := range rows {
		marker := "  "
		if i == p.cursor {
			marker = "» "
		}
		ar := "--"
		switch {
		case r.Approved:
			ar = "A-"
		case r.Rejected:
			ar = "-R"
		}
		loc := r.URL
		if loc == "" {
			loc = r.Command
			if loc == "" {
				loc = r.SourceURL
			}
		}
		row := fmt.Sprintf(
			"%s%-20s %-22s %-6s %-9s %-7s %-3s %s",
			marker,
			truncate(r.SourceID, 20),
			truncate(r.Name, 22),
			r.Type, statusLabel(r.Status), defaultStr(r.Severity, "-"),
			ar, truncate(loc, maxInt(16, p.width-90)),
		)
		if i == p.cursor {
			row = lipgloss.NewStyle().Bold(true).Render(row)
		}
		b.WriteString(row + "\n")
	}
	return b.String()
}

// statusLabel colourises the status string. Hot colours for blocked /
// error so an operator scanning the table sees them at a glance.
func statusLabel(status string) string {
	switch status {
	case "clean":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("34")).Render("clean")
	case "warning":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("warning")
	case "blocked":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("blocked")
	case "error":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("160")).Render("error")
	case "":
		return "-"
	default:
		return status
	}
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// registryBadge formats a small "registry:<id>" pill for use on
// Skills / MCPs panel rows. Returns the empty string when *sourceID*
// is empty so the caller can append it unconditionally without an
// extra guard. Truncates long ids so a verbose source name doesn't
// blow out the row width budget; the detail view shows the untrimmed
// value when the operator opens it.
func registryBadge(sourceID string) string {
	id := strings.TrimSpace(sourceID)
	if id == "" {
		return ""
	}
	if len(id) > 18 {
		id = id[:15] + "…"
	}
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("117")).
		Render("registry:" + id)
}

// ---------------------------------------------------------------------------
// Cursor / row helpers
// ---------------------------------------------------------------------------

func (p *RegistriesPanel) rowCount() int {
	switch p.tab {
	case registriesTabSources:
		return len(p.sources)
	case registriesTabEntries:
		return len(p.entryRowsFiltered(false))
	case registriesTabApproved:
		return len(p.entryRowsFiltered(true))
	}
	return 0
}

// entryRows returns the union of every cached source's verdicts so
// the Entries tab is a single table the operator can scroll. Sources
// are interleaved by id so all rows for one source stay together.
func (p *RegistriesPanel) entryRows() []registryEntryRow {
	var out []registryEntryRow
	for _, s := range p.sources {
		idx, ok := p.indexes[s.ID]
		if !ok {
			continue
		}
		for _, raw := range idx.Verdicts {
			row := verdictToRow(s.ID, raw)
			out = append(out, row)
		}
	}
	if p.filterEntryName != "" {
		want := p.filterEntryName
		filtered := out[:0]
		for _, r := range out {
			if r.Type+":"+r.Name == want {
				filtered = append(filtered, r)
			}
		}
		out = filtered
	}
	return out
}

func (p *RegistriesPanel) entryRowsFiltered(approvedOnly bool) []registryEntryRow {
	rows := p.entryRows()
	if !approvedOnly {
		return rows
	}
	out := rows[:0]
	for _, r := range rows {
		if r.Approved {
			out = append(out, r)
		}
	}
	return out
}

func (p *RegistriesPanel) cursorSourceID() string {
	switch p.tab {
	case registriesTabSources:
		if src := p.SelectedSource(); src != nil {
			return src.ID
		}
	case registriesTabEntries, registriesTabApproved:
		if row := p.SelectedEntry(); row != nil {
			return row.SourceID
		}
	}
	return ""
}

func verdictToRow(sourceID string, raw map[string]any) registryEntryRow {
	getStr := func(k string) string {
		if v, ok := raw[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	getBool := func(k string) bool {
		if v, ok := raw[k]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
		return false
	}
	getInt := func(k string) int {
		if v, ok := raw[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
		return 0
	}
	return registryEntryRow{
		SourceID:  sourceID,
		Type:      getStr("type"),
		Name:      getStr("name"),
		Status:    getStr("status"),
		Severity:  getStr("severity"),
		Findings:  getInt("findings"),
		Approved:  getBool("approved"),
		Rejected:  getBool("rejected"),
		Transport: getStr("transport"),
		Command:   getStr("command"),
		URL:       getStr("url"),
		SourceURL: getStr("source_url"),
	}
}

// ---------------------------------------------------------------------------
// Disk I/O
// ---------------------------------------------------------------------------

// loadRegistryIndex reads the on-disk index.json for *sourceID* under
// *dataDir*. Returns an empty :class:`indexFile` and a non-nil error
// when the file is missing or corrupt — both are non-fatal: the
// Sources table renders fine without an index, the Entries tab just
// shows a "sync to populate" hint.
func loadRegistryIndex(dataDir, sourceID string) (indexFile, error) {
	if dataDir == "" || sourceID == "" {
		return indexFile{}, fmt.Errorf("missing dataDir or sourceID")
	}
	if strings.ContainsAny(sourceID, "/\\.") {
		// Defence-in-depth: cli/defenseclaw/registries/cache.py
		// also rejects these. Block paths that would escape the
		// cache root regardless of how they got into config.
		return indexFile{}, fmt.Errorf("unsafe source id: %q", sourceID)
	}
	path := filepath.Join(dataDir, "registries", sourceID, "index.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return indexFile{}, err
	}
	var out indexFile
	if err := json.Unmarshal(raw, &out); err != nil {
		return indexFile{}, err
	}
	if out.SourceID == "" {
		out.SourceID = sourceID
	}
	return out, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

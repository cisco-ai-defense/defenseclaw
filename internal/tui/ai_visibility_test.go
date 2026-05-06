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
	"strings"
	"testing"
	"time"
)

// AI Visibility panel tests. These pin behavior the CLI tests
// (cli/tests/test_cmd_agent_discover.py) also assert on, because
// the two surfaces MUST agree -- an operator switching between
// `defenseclaw agent usage` and the TUI panel should see the same
// dedup'd row count and the same per-component confidence.

// helper to build a snapshot with the smallest payload that exercises
// the dedup (3 manifest hits for one component) and the offline /
// disabled paths.
func aiSnapshotWithComponent(numHits int, identity float64, presence float64) *AIUsageSnapshot {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	la := now.Add(-2 * time.Minute)
	signals := make([]AIUsageSignal, 0, numHits)
	for i := 0; i < numHits; i++ {
		signals = append(signals, AIUsageSignal{
			SignalID:      "sig-" + itoaPad(i),
			SignatureID:   "anthropic-sdk-npm",
			Name:          "Anthropic Claude SDK",
			Vendor:        "Anthropic",
			Product:       "Anthropic Claude",
			Category:      "package_dependency",
			State:         "new",
			Detector:      "package_manifest",
			Source:        "scan",
			IdentityScore: identity,
			IdentityBand:  "high",
			PresenceScore: presence,
			PresenceBand:  "medium",
			FirstSeen:     now,
			LastSeen:      now,
			LastActiveAt:  &la,
			Component: &AIUsageComponent{
				Ecosystem: "npm",
				Name:      "@anthropic-ai/sdk",
				Version:   "0.20.0",
			},
		})
	}
	return &AIUsageSnapshot{
		Enabled: true,
		Summary: AIUsageSummary{
			ScanID:        "scan-1",
			ScannedAt:     now,
			ActiveSignals: numHits,
			NewSignals:    numHits,
			TotalSignals:  numHits,
		},
		Signals:   signals,
		FetchedAt: now,
	}
}

// itoaPad is a tiny zero-padded itoa so signal IDs sort
// lexicographically. Avoids strconv import in test helpers.
func itoaPad(i int) string {
	if i < 10 {
		return "0" + string(rune('0'+i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

func TestAIVisibility_NoSnapshot_ShowsOfflinePlaceholder(t *testing.T) {
	p := NewAIVisibilityPanel()
	p.SetSize(120, 30)
	out := p.View(120, 30)
	// The placeholder should be self-explanatory and tell the
	// operator what they need to do (start gateway / set token).
	mustContain(t, out, "AI Visibility")
	mustContain(t, out, "snapshot not yet available")
	mustContain(t, out, "DEFENSECLAW_GATEWAY_TOKEN")
}

func TestAIVisibility_DedupsSignalsByComponent(t *testing.T) {
	p := NewAIVisibilityPanel()
	p.SetSize(160, 30)
	p.SetSnapshot(aiSnapshotWithComponent(3, 0.91, 0.78))

	rows := p.Rows()
	if len(rows) != 1 {
		t.Fatalf("expected 1 deduped row from 3 identical signals, got %d", len(rows))
	}
	if rows[0].Count != 3 {
		t.Fatalf("expected Count=3, got %d", rows[0].Count)
	}
	if rows[0].IdentityBand != "high" || rows[0].PresenceBand != "medium" {
		t.Fatalf("expected confidence pulled from signals, got identity=%q presence=%q",
			rows[0].IdentityBand, rows[0].PresenceBand)
	}
}

func TestAIVisibility_RenderShowsConfidenceColumns(t *testing.T) {
	p := NewAIVisibilityPanel()
	p.SetSize(200, 40)
	p.SetSnapshot(aiSnapshotWithComponent(3, 0.91, 0.78))
	out := p.View(200, 40)

	// Header + dedup'd row + percentages must all render.
	mustContain(t, out, "AI VISIBILITY")
	mustContain(t, out, "Identity")
	mustContain(t, out, "Presence")
	mustContain(t, out, "91%")
	mustContain(t, out, "78%")
	// One Count cell with 3 (the dedup count).
	mustContain(t, out, " 3 ")
}

func TestAIVisibility_FilterFiltersAndPersistsAcrossRefresh(t *testing.T) {
	p := NewAIVisibilityPanel()
	p.SetSize(160, 30)

	now := time.Now()
	snap := &AIUsageSnapshot{
		Enabled: true,
		Summary: AIUsageSummary{ActiveSignals: 2},
		Signals: []AIUsageSignal{
			{
				SignalID: "s1", State: "new", Category: "ai_cli",
				Product: "Codex", Vendor: "OpenAI", Detector: "binary",
				FirstSeen: now, LastSeen: now,
			},
			{
				SignalID: "s2", State: "new", Category: "ai_cli",
				Product: "Cursor", Vendor: "Anysphere", Detector: "process",
				FirstSeen: now, LastSeen: now,
			},
		},
		FetchedAt: now,
	}
	p.SetSnapshot(snap)

	if got := len(p.FilteredRows()); got != 2 {
		t.Fatalf("expected 2 unfiltered rows, got %d", got)
	}

	// Apply filter -- should drop the non-matching row.
	p.SetFilter("codex")
	if got := len(p.FilteredRows()); got != 1 {
		t.Fatalf("expected 1 filtered row, got %d", got)
	}
	if p.FilteredRows()[0].Product != "Codex" {
		t.Fatalf("expected Codex row, got %q", p.FilteredRows()[0].Product)
	}

	// Re-set the SAME snapshot -- the filter must persist so a
	// background poll doesn't wipe the operator's search.
	p.SetSnapshot(snap)
	if got := p.FilterText(); got != "codex" {
		t.Fatalf("filter text lost across refresh: got %q", got)
	}
	if got := len(p.FilteredRows()); got != 1 {
		t.Fatalf("filter not re-applied across refresh: got %d", got)
	}
}

func TestAIVisibility_FilterMatchesVendorAndDetector(t *testing.T) {
	p := NewAIVisibilityPanel()
	p.SetSize(160, 30)

	now := time.Now()
	snap := &AIUsageSnapshot{
		Enabled: true,
		Signals: []AIUsageSignal{
			{
				SignalID: "s1", State: "new", Category: "ai_cli",
				Product: "Codex", Vendor: "OpenAI", Detector: "binary",
				FirstSeen: now, LastSeen: now,
			},
			{
				SignalID: "s2", State: "new", Category: "active_process",
				Product: "Cursor", Vendor: "Anysphere", Detector: "process",
				FirstSeen: now, LastSeen: now,
			},
		},
		FetchedAt: now,
	}
	p.SetSnapshot(snap)

	// Vendor substring match.
	p.SetFilter("Anysphere")
	if got := len(p.FilteredRows()); got != 1 {
		t.Fatalf("expected 1 vendor-filtered row, got %d", got)
	}
	if p.FilteredRows()[0].Product != "Cursor" {
		t.Fatalf("vendor filter mismatched: got %q", p.FilteredRows()[0].Product)
	}

	// Detector substring match (case-insensitive). Detectors are
	// now an aggregated list; assert the filter still matches via
	// the search haystack and the matching row's Detectors slice
	// contains "process".
	p.SetFilter("PROCESS")
	if got := len(p.FilteredRows()); got != 1 {
		t.Fatalf("expected 1 detector-filtered row, got %d", got)
	}
	got := p.FilteredRows()[0]
	if !containsString(got.Detectors, "process") {
		t.Fatalf("expected detectors to contain \"process\", got %v", got.Detectors)
	}
}

func TestAIVisibility_DetailToggle_OpensAndClosesOverlay(t *testing.T) {
	p := NewAIVisibilityPanel()
	p.SetSize(160, 30)
	p.SetSnapshot(aiSnapshotWithComponent(2, 0.91, 0.78))

	if p.IsDetailOpen() {
		t.Fatal("detail must start closed")
	}
	p.ToggleDetail()
	if !p.IsDetailOpen() {
		t.Fatal("ToggleDetail did not open the overlay")
	}
	out := p.View(160, 30)
	// Detail mode shows per-signal IDs and the runtime block hint.
	mustContain(t, out, "AI VISIBILITY — detail")
	mustContain(t, out, "anthropic-sdk-npm")

	p.ToggleDetail()
	if p.IsDetailOpen() {
		t.Fatal("ToggleDetail did not close the overlay")
	}
}

func TestAIVisibility_DetailHeader_OmitsEmptyComponent(t *testing.T) {
	// Regression for the "seen · Cursor ·  × 7 signal(s)" bug:
	// CLI-style products (Cursor, Claude Code, Codex, ...) have
	// no Component block, so the detail header used to render an
	// awkward dangling "·" between Product and the count. The
	// fixed header builds segments and joins with " · " so the
	// empty Component is dropped cleanly.
	p := NewAIVisibilityPanel()
	p.SetSize(160, 30)
	now := time.Now()
	la := now.Add(-4 * time.Minute)
	snap := &AIUsageSnapshot{
		Enabled: true,
		Summary: AIUsageSummary{ActiveSignals: 1},
		Signals: []AIUsageSignal{{
			SignalID: "s1", State: "seen", Category: "ai_cli",
			Product: "Cursor", Vendor: "Anysphere", Detector: "process",
			FirstSeen: now, LastSeen: now, LastActiveAt: &la,
			// No Component field on purpose -- this is the
			// shape every CLI / desktop / process product
			// gets back from /api/v1/ai-usage today.
		}},
		FetchedAt: now,
	}
	p.SetSnapshot(snap)
	p.ToggleDetail()
	out := p.View(160, 30)
	// The header MUST NOT contain the dangling "Cursor ·  ×"
	// (component cell empty between two separators). The
	// fixed format is "seen · Cursor × 1 signal(s)".
	if strings.Contains(out, "Cursor ·  ×") || strings.Contains(out, "Cursor · ×") {
		t.Fatalf("detail header still has dangling separator for empty Component:\n%s", out)
	}
	mustContain(t, out, "Cursor")
	mustContain(t, out, "× 1 signal(s)")
}

func TestAIVisibility_Header_CollapsesZeroChurn(t *testing.T) {
	// In the steady state (no churn since the last scan) the
	// header used to read `active=755  new=0  changed=0  gone=0
	// files=2103` -- four zeros for one signal. The fixed
	// renderer drops the zero-valued churn segments and keeps
	// active + files so the operator can still confirm a scan
	// ran.
	p := NewAIVisibilityPanel()
	p.SetSize(160, 30)
	now := time.Now()
	p.SetSnapshot(&AIUsageSnapshot{
		Enabled: true,
		Summary: AIUsageSummary{
			ActiveSignals: 755,
			NewSignals:    0,
			ChangedSignals: 0,
			GoneSignals:   0,
			FilesScanned:  2103,
		},
		FetchedAt: now,
	})
	out := p.View(160, 30)
	mustContain(t, out, "active=755")
	mustContain(t, out, "files=2103")
	// Zero-valued churn segments MUST be hidden so the header
	// reads cleanly.
	if strings.Contains(out, "new=0") {
		t.Fatalf("zero-valued new= segment must be hidden:\n%s", out)
	}
	if strings.Contains(out, "changed=0") {
		t.Fatalf("zero-valued changed= segment must be hidden:\n%s", out)
	}
	if strings.Contains(out, "gone=0") {
		t.Fatalf("zero-valued gone= segment must be hidden:\n%s", out)
	}
}

func TestAIVisibility_Table_RowsAlignedWithHeader(t *testing.T) {
	// Regression for the column drift bug: a 27-char Categories
	// aggregate (e.g. "active_process, ai_cli (+5)") used to
	// overflow its 14-char column and push Product, Component,
	// Vendor, Detectors, Count, Identity, Presence, and Active
	// rightward, breaking visual alignment with the header.
	// The fix routes every cell through padTrunc which BOTH
	// truncates overflow with "…" AND pads to the declared
	// width, so the column right-edges never move.
	//
	// We assert the invariant directly: in the rendered table,
	// every body line MUST have the same printable width as the
	// header line. We strip ANSI before measuring because the
	// renderer wraps cells in lipgloss styles for color.
	p := NewAIVisibilityPanel()
	p.SetSize(220, 30)
	now := time.Now()
	la := now.Add(-1 * time.Minute)
	mk := func(state, cat, prod, vendor, det string, eco, comp string) AIUsageSignal {
		s := AIUsageSignal{
			State: state, Category: cat, Product: prod, Vendor: vendor,
			Detector: det, FirstSeen: now, LastSeen: now, LastActiveAt: &la,
			Confidence: 0.9,
		}
		if comp != "" {
			s.Component = &AIUsageComponent{Ecosystem: eco, Name: comp, Version: "1.2.3"}
		}
		return s
	}
	signals := []AIUsageSignal{
		// Long Categories AND long Detectors — the original bug.
		mk("seen", "active_process", "Claude Code", "Anthropic", "process", "", ""),
		mk("seen", "ai_cli", "Claude Code", "Anthropic", "binary", "", ""),
		mk("seen", "shell_history_match", "Claude Code", "Anthropic", "shell_history", "", ""),
		mk("seen", "supported_app", "Claude Code", "Anthropic", "config", "", ""),
		mk("seen", "mcp_server", "Claude Code", "Anthropic", "mcp", "", ""),
		mk("seen", "provider_history", "Claude Code", "Anthropic", "provider_history", "", ""),
		// Long product + component (the SDK shape).
		mk("seen", "package_dependency", "Anthropic Python SDK extra long",
			"Anthropic", "package_manifest", "pypi", "anthropic-genuinely-long-name"),
		// Catch-all: short values everywhere — must STILL pad to
		// the same total width (no shrink).
		mk("new", "ai_cli", "X", "Y", "binary", "", ""),
	}
	p.SetSnapshot(&AIUsageSnapshot{
		Enabled: true,
		Summary: AIUsageSummary{ActiveSignals: len(signals)},
		Signals: signals,
		FetchedAt: now,
	})

	out := p.View(220, 30)
	lines := splitLinesNoANSI(out)
	headerIdx := -1
	for i, ln := range lines {
		if strings.Contains(ln, "State") && strings.Contains(ln, "Categories") &&
			strings.Contains(ln, "Identity") && strings.Contains(ln, "Active") {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 {
		t.Fatalf("could not locate header line in:\n%s", out)
	}
	headerWidth := visibleWidth(lines[headerIdx])
	if headerWidth == 0 {
		t.Fatalf("header line measured zero width: %q", lines[headerIdx])
	}

	// Walk subsequent body lines until we hit a footer / hint /
	// border line. Each body line MUST match the header width
	// EXACTLY -- one mismatch means a cell overflowed and pushed
	// the right edge, which is exactly the bug we're guarding.
	body := 0
	for j := headerIdx + 1; j < len(lines); j++ {
		ln := lines[j]
		// Stop at the footer hint / border / blank.
		if strings.Contains(ln, "navigate") ||
			strings.Contains(ln, "shown") ||
			strings.TrimSpace(ln) == "" {
			break
		}
		got := visibleWidth(ln)
		if got != headerWidth {
			t.Fatalf("row %d width=%d != header width=%d (cell overflowed!)\n"+
				"header: %q\nrow:    %q",
				j-headerIdx, got, headerWidth, lines[headerIdx], ln)
		}
		body++
	}
	if body == 0 {
		t.Fatalf("no body rows found after header in:\n%s", out)
	}
}

func TestAIVisibility_Header_KeepsNonZeroChurn(t *testing.T) {
	// When there IS churn, the header MUST still surface it --
	// dropping non-zero values would hide the operator-relevant
	// "you have 5 NEW agents since last scan" signal.
	p := NewAIVisibilityPanel()
	p.SetSize(160, 30)
	p.SetSnapshot(&AIUsageSnapshot{
		Enabled: true,
		Summary: AIUsageSummary{
			ActiveSignals:  755,
			NewSignals:     5,
			ChangedSignals: 2,
			GoneSignals:    0, // mixed: keep new+changed, drop gone
			FilesScanned:   2103,
		},
		FetchedAt: time.Now(),
	})
	out := p.View(160, 30)
	mustContain(t, out, "new=5")
	mustContain(t, out, "changed=2")
	if strings.Contains(out, "gone=0") {
		t.Fatalf("zero-valued gone= must STILL be hidden when others are non-zero:\n%s", out)
	}
}

func TestAIVisibility_DetailToggle_NoOpOnEmptyTable(t *testing.T) {
	p := NewAIVisibilityPanel()
	p.SetSize(160, 30)
	p.SetSnapshot(&AIUsageSnapshot{Enabled: true})

	// Empty filtered list -- ToggleDetail must NOT open an overlay
	// pointing at a non-existent row (that would render an empty
	// detail box and panic-prone for any future field that
	// assumes detailRow is non-nil + populated).
	p.ToggleDetail()
	if p.IsDetailOpen() {
		t.Fatal("ToggleDetail must be a no-op when the table is empty")
	}
}

func TestAIVisibility_NormalizesAcrossDetectors(t *testing.T) {
	// Real-world bug: "Claude Code" was independently discovered
	// by 7 detectors (binary, process, mcp, config, shell_history,
	// provider_history, desktop_app) and the panel showed it as
	// 7 near-identical rows. Operators wanted "where is Claude
	// Code?" -- ONE row per product -- with the constituent
	// categories / detectors aggregated as Categories[] /
	// Detectors[]. This test pins the new behavior and asserts
	// the renderer surfaces both detectors in the cell.
	p := NewAIVisibilityPanel()
	p.SetSize(200, 30)
	now := time.Now()
	mk := func(id, cat, det string) AIUsageSignal {
		return AIUsageSignal{
			SignalID: id, State: "seen",
			Category: cat, Product: "Claude Code",
			Vendor: "Anthropic", Detector: det,
			FirstSeen: now, LastSeen: now,
		}
	}
	snap := &AIUsageSnapshot{
		Enabled: true,
		Signals: []AIUsageSignal{
			mk("s1", "ai_cli", "binary"),
			mk("s2", "active_process", "process"),
			mk("s3", "mcp_server", "mcp"),
			mk("s4", "supported_app", "config"),
			mk("s5", "shell_history", "shell_history"),
			mk("s6", "provider_history", "shell_history"),
			mk("s7", "desktop_app", "application"),
			// Different vendor/product MUST stay distinct.
			{
				SignalID: "s8", State: "seen", Category: "ai_cli",
				Product: "Cursor", Vendor: "Anysphere", Detector: "binary",
				FirstSeen: now, LastSeen: now,
			},
		},
		FetchedAt: now,
	}
	p.SetSnapshot(snap)

	rows := p.FilteredRows()
	if got := len(rows); got != 2 {
		t.Fatalf("expected 7 Claude Code signals to collapse to 1 row + 1 Cursor row (=2 total), got %d rows: %#v", got, rows)
	}
	var claude *aiVisibilityRow
	for i := range rows {
		if rows[i].Product == "Claude Code" {
			claude = &rows[i]
			break
		}
	}
	if claude == nil {
		t.Fatalf("missing Claude Code row in %#v", rows)
	}
	if claude.Count != 7 {
		t.Fatalf("expected count=7 across all detectors, got %d", claude.Count)
	}
	// Aggregated lists carry every constituent category/detector.
	wantCats := []string{
		"ai_cli", "active_process", "mcp_server", "supported_app",
		"shell_history", "provider_history", "desktop_app",
	}
	for _, c := range wantCats {
		if !containsString(claude.Categories, c) {
			t.Fatalf("Categories missing %q: %v", c, claude.Categories)
		}
	}
	wantDets := []string{
		"binary", "process", "mcp", "config",
		"shell_history", "application",
	}
	for _, d := range wantDets {
		if !containsString(claude.Detectors, d) {
			t.Fatalf("Detectors missing %q: %v", d, claude.Detectors)
		}
	}

	// Header column must read "Categories" / "Detectors" plural.
	out := stripANSIVisib(p.View(200, 30))
	mustContain(t, out, "Categories")
	mustContain(t, out, "Detectors")
	// Cell shows the first two + "+N" suffix; assert on the
	// suffix rather than full content because the truncation
	// rule may evolve and the test should fail loudly when it
	// does instead of silently accepting a longer cell.
	mustContain(t, out, "(+5)")
	// Filter still finds rows by their constituent detectors
	// even after the dedup pass collapsed the per-detector rows.
	p.SetFilter("application")
	if len(p.FilteredRows()) != 1 {
		t.Fatalf("filter \"application\" must still match Claude Code via aggregated detectors; got %d rows", len(p.FilteredRows()))
	}
}

func TestAIVisibility_CursorClampsOnFilter(t *testing.T) {
	p := NewAIVisibilityPanel()
	p.SetSize(160, 30)

	now := time.Now()
	signals := make([]AIUsageSignal, 0, 5)
	for i, v := range []string{"alpha", "beta", "gamma", "delta", "epsilon"} {
		signals = append(signals, AIUsageSignal{
			SignalID: "s" + itoaPad(i), State: "new",
			Product: v, Detector: "binary",
			FirstSeen: now, LastSeen: now,
		})
	}
	p.SetSnapshot(&AIUsageSnapshot{
		Enabled: true, Signals: signals, FetchedAt: now,
	})

	// Move cursor to the bottom row, then apply a filter that
	// drops it -- cursor must clamp into the remaining set
	// instead of pointing past the slice end.
	p.CursorDown()
	p.CursorDown()
	p.CursorDown()
	p.CursorDown()
	p.SetFilter("alpha")
	if got := len(p.FilteredRows()); got != 1 {
		t.Fatalf("expected 1 filtered row, got %d", got)
	}
	// ToggleDetail should now safely open on the remaining row;
	// before the clamp this was an out-of-range read.
	p.ToggleDetail()
	if !p.IsDetailOpen() {
		t.Fatal("ToggleDetail must succeed after filter clamp")
	}
}

func TestFormatConf_HandlesMissingHalves(t *testing.T) {
	cases := []struct {
		score float64
		band  string
		want  string
	}{
		{0.91, "high", "high (91%)"},
		{0.5, "", "50%"},
		{0, "medium", "medium (0%)"},
		{0, "", ""},
		{0.123, "low", "low (12%)"},
	}
	for _, c := range cases {
		got := formatConf(c.score, c.band)
		if got != c.want {
			t.Errorf("formatConf(%v,%q) = %q want %q",
				c.score, c.band, got, c.want)
		}
	}
}

func TestHumanizeAge_Compact(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Millisecond, "0s"},
		{30 * time.Second, "30s"},
		{2 * time.Minute, "2m"},
		{3 * time.Hour, "3h"},
		{3*time.Hour + 12*time.Minute, "3h12m"},
		{36 * time.Hour, "1d12h"},
		{72 * time.Hour, "3d"},
	}
	for _, c := range cases {
		got := humanizeAge(c.d)
		if got != c.want {
			t.Errorf("humanizeAge(%v) = %q want %q", c.d, got, c.want)
		}
	}
}

// mustContain is a tiny helper used by the View() snapshot tests.
// Strips ANSI escape codes (lipgloss adds color codes even when we
// build the panel in a no-color test env on some terminals) before
// asserting the substring. Mirrors the helper in
// overview_ai_discovery_test.go.
func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(stripANSIVisib(haystack), needle) {
		t.Fatalf("expected %q in:\n%s", needle, haystack)
	}
}

// stripANSIVisib removes simple ANSI CSI sequences so View()
// substring assertions don't depend on whether lipgloss emitted
// color codes for the test env. We intentionally avoid pulling in
// regexp for a tiny state machine (regex compile cost is ~50us
// which would dominate every test).
func stripANSIVisib(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !in && c == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			in = true
			i++
			continue
		}
		if in {
			if c >= 0x40 && c <= 0x7e {
				in = false
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// splitLinesNoANSI is the convenience used by the alignment test:
// strip ANSI styling first (so the lipgloss color wrappers don't
// throw off width math), then split on \n. Empty trailing line
// from a final newline is preserved -- callers ignore it via
// strings.TrimSpace if they care.
func splitLinesNoANSI(s string) []string {
	return strings.Split(stripANSIVisib(s), "\n")
}

// visibleWidth returns the printable rune width of `s` after ANSI
// stripping. We count runes (not bytes) so multi-byte UTF-8 in
// the table (e.g. the "…" the truncate helper appends to clipped
// cells) is measured at one column wide -- which is also how
// terminals render it.
func visibleWidth(s string) int {
	clean := stripANSIVisib(s)
	// Count runes, not bytes: "…" is 3 bytes but 1 column.
	n := 0
	for range clean {
		n++
	}
	return n
}

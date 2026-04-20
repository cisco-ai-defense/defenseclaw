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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// jsonUnmarshal is a thin alias that keeps the verdict parser site
// readable and lets us swap in a streaming decoder later without
// touching the call site.
var jsonUnmarshal = json.Unmarshal

const (
	logSourceGateway = iota
	logSourceVerdicts
	logSourceWatchdog
	logSourceCount
)

var logSourceNames = [logSourceCount]string{"Gateway", "Verdicts", "Watchdog"}

// verdictActionFilters cycle the Verdicts source through structured
// action filters. Matches the action field of gatewaylog.VerdictPayload.
// Empty string means "show all actions".
var verdictActionFilters = []string{"", "block", "alert", "allow"}
var verdictActionLabels = map[string]string{
	"":      "All actions",
	"block": "Block",
	"alert": "Alert",
	"allow": "Allow",
}

// verdictEventTypeFilters cycle the Verdicts source through
// event-type chips. Phase 4: operators wanted to see "just judge
// responses" or "just lifecycle" separately from the action chip,
// which only keys on block/alert/allow. Empty string means "show
// all event types".
//
// Kept in lockstep with the discriminants on gatewaylog.EventType —
// every schema-level type gets its own chip so "diagnostic" noise
// is filterable just like "error" is. Renaming or adding an event
// type in the schema must also update this list;
// TestVerdictEventTypeFiltersMatchSchema catches drift at test time.
var verdictEventTypeFilters = []string{"", "verdict", "judge", "lifecycle", "error", "diagnostic"}
var verdictEventTypeLabels = map[string]string{
	"":           "All events",
	"verdict":    "Verdict",
	"judge":      "Judge",
	"lifecycle":  "Lifecycle",
	"error":      "Error",
	"diagnostic": "Diagnostic",
}

// verdictSeverityFilters cycles the Verdicts source through
// severity chips. Incident-response playbooks almost always lead
// with "show me every HIGH and CRITICAL since $timestamp", so the
// chip sits on its own row rather than being crammed into the
// event-type chip. Empty string means "all severities".
//
// The vocabulary mirrors gatewaylog.Severity exactly — HIGH+ is a
// common ask ("just show me the stuff worth paging on") so we
// expose it as a meta-chip that matches HIGH or CRITICAL.
var verdictSeverityFilters = []string{"", "CRITICAL", "HIGH", "HIGH+", "MEDIUM", "LOW", "INFO"}
var verdictSeverityLabels = map[string]string{
	"":         "All severities",
	"CRITICAL": "Critical",
	"HIGH":     "High",
	"HIGH+":    "High+",
	"MEDIUM":   "Medium",
	"LOW":      "Low",
	"INFO":     "Info",
}

// Pre-built noise filter patterns — lines containing any of these are hidden
// when the corresponding filter is active.
var noisePatterns = []string{
	"event tick seq=",
	"event health seq=",
	"payload_len=20",
	"MallocStackLogging",
	"event sessions.changed seq=nil",
	"content-length=0",
}

// Interesting-event patterns used by the "important" filter
var importantPatterns = []string{
	"error", "fatal", "panic", "warn",
	"block", "allow", "reject", "quarantine",
	"scan", "drift", "verdict", "guardrail",
	"connected", "disconnected", "started", "stopped",
}

// Named filter presets — cycling through these with keyboard shortcuts
const (
	filterNone      = ""
	filterNoNoise   = "no-noise"
	filterImportant = "important"
	filterErrors    = "errors"
	filterWarnings  = "warnings+"
	filterScan      = "scan"
	filterDrift     = "drift"
	filterGuardrail = "guardrail"
)

var filterPresets = []string{
	filterNone,
	filterNoNoise,
	filterImportant,
	filterErrors,
	filterWarnings,
	filterScan,
	filterDrift,
	filterGuardrail,
}

var filterLabels = map[string]string{
	filterNone:      "All",
	filterNoNoise:   "No Noise",
	filterImportant: "Important",
	filterErrors:    "Errors",
	filterWarnings:  "Warnings+",
	filterScan:      "Scan",
	filterDrift:     "Drift",
	filterGuardrail: "Guardrail",
}

type logPollMsg struct{}

// LogsPanel provides live log tailing for gateway.log, gateway.jsonl
// (Verdicts tab), and watchdog.log.
type LogsPanel struct {
	theme      *Theme
	dataDir    string
	source     int
	lines      [logSourceCount][]string
	errMsgs    [logSourceCount]string
	scroll     int
	width      int
	height     int
	paused     bool
	filterMode string
	searching  bool
	searchText string

	// B4b: per-line cursor into the *currently filtered* view of
	// the active source. Kept per-source so switching tabs doesn't
	// silently jump the selection to a line the operator didn't
	// scroll to. When a source is tailing (paused=false) and the
	// cursor has never been moved, we clamp it to the bottom so
	// "live tail + press Enter" opens the most recent line
	// (matching the pre-B4b behaviour of SelectedVerdict).
	cursor      [logSourceCount]int
	cursorMoved [logSourceCount]bool

	// Verdicts-only state: cached structured events and a chip-
	// filter for action (block/alert/allow). Cardinalities other
	// than action (category, model) are still queryable via the
	// existing text-search field to keep the chip bar short. The
	// three chips we surface as first-class (action, event type,
	// severity) are the ones operators name when describing an
	// incident — "show me HIGH judge blocks" — so putting them
	// one keystroke away materially speeds up triage.
	verdicts         []verdictRow
	verdictAction    string // one of verdictActionFilters
	verdictEventType string // one of verdictEventTypeFilters
	verdictSeverity  string // one of verdictSeverityFilters
}

// verdictRow is a pre-rendered Verdicts-tab entry. We keep the
// structured fields alongside the rendered line so typed filters
// run in O(n) over in-memory rows rather than re-parsing JSON per
// keystroke.
//
// Every field on the gatewaylog.Event schema that's useful for
// operator triage lands here. The extra cost is a handful of
// unused strings per record; the win is that the detail modal
// can surface request_id / run_id / categories / findings without
// a second JSON parse pass and the search filter can key on any
// of them via the existing text-search field.
type verdictRow struct {
	raw       string
	timestamp time.Time
	action    string
	severity  string
	stage     string
	direction string
	model     string
	reason    string
	kind      string // for Judge events: injection/pii
	eventType string

	// Envelope correlation identifiers — surfaced in the detail
	// modal so operators can pivot from a TUI event into the
	// SQLite audit store or a Splunk search without hand-copying
	// IDs out of the raw JSON blob.
	requestID string
	runID     string
	sessionID string
	provider  string

	// Verdict-payload extras.
	categories []string
	latencyMs  int64

	// Judge-payload extras. judgeRaw is the (possibly truncated)
	// model response, populated only when guardrail.retain_judge_bodies
	// is true. judgeParseError flags bodies we could not decode.
	judgeInputBytes int
	judgeSeverity   string
	judgeRaw        string
	judgeParseError string
	judgeFindings   []judgeFinding

	// Lifecycle-payload extras.
	lifecycleSubsystem  string
	lifecycleTransition string
	lifecycleDetails    map[string]string

	// Error-payload extras.
	errorSubsystem string
	errorCode      string
	errorMessage   string
	errorCause     string

	// Diagnostic-payload extras.
	diagnosticComponent string
	diagnosticMessage   string
}

// judgeFinding mirrors gatewaylog.Finding on the TUI side. We keep
// only the fields the detail modal renders — evidence is already
// redacted by the writer, but we don't expose it here because the
// modal is a compact kv list, not a structured table.
type judgeFinding struct {
	Category string  `json:"category"`
	Severity string  `json:"severity"`
	Rule     string  `json:"rule,omitempty"`
	Source   string  `json:"source,omitempty"`
	Conf     float64 `json:"confidence,omitempty"`
}

// NewLogsPanel creates the logs panel.
func NewLogsPanel(theme *Theme, cfg *config.Config) LogsPanel {
	dataDir := config.DefaultDataPath()
	if cfg != nil {
		dataDir = cfg.DataDir
	}
	return LogsPanel{theme: theme, dataDir: dataDir, filterMode: filterNoNoise}
}

// Init returns a command to start polling logs.
func (p LogsPanel) Init() tea.Cmd {
	return p.pollLogs()
}

func (p LogsPanel) pollLogs() tea.Cmd {
	return tea.Tick(2*time.Second, func(_ time.Time) tea.Msg {
		return logPollMsg{}
	})
}

// Update handles messages for the logs panel.
func (p LogsPanel) Update(msg tea.Msg) (LogsPanel, tea.Cmd) {
	switch msg := msg.(type) {
	case logPollMsg:
		p.loadFile(logSourceGateway, filepath.Join(p.dataDir, "gateway.log"))
		p.loadVerdicts(filepath.Join(p.dataDir, "gateway.jsonl"))
		p.loadFile(logSourceWatchdog, filepath.Join(p.dataDir, "watchdog.log"))
		if !p.paused {
			totalLines := len(p.filteredLines())
			visible := p.visibleLines()
			if totalLines > visible {
				p.scroll = totalLines - visible
			}
		}
		return p, p.pollLogs()
	case tea.KeyPressMsg:
		return p.handleKey(msg)
	}
	return p, nil
}

func (p LogsPanel) handleKey(msg tea.KeyPressMsg) (LogsPanel, tea.Cmd) {
	switch msg.String() {
	case "space":
		p.paused = !p.paused
	case "left", "h":
		if p.searching {
			break
		}
		if p.source > 0 {
			p.source--
			p.scroll = 0
		}
	case "right", "l":
		if p.searching {
			break
		}
		if p.source < logSourceCount-1 {
			p.source++
			p.scroll = 0
		}
	case "up", "k":
		// B4b: up/down now move the per-line cursor and pin the
		// view so the cursor stays on-screen. This gives Enter
		// something precise to target — previously "scroll then
		// Enter" opened whichever line happened to be last
		// visible, which surprised operators who expected it to
		// open the row they were looking at.
		p.moveCursor(-1)
		p.paused = true
	case "down", "j":
		p.moveCursor(1)
		p.paused = true
	case "pgup":
		p.moveCursor(-p.visibleLines())
		p.paused = true
	case "pgdown":
		p.moveCursor(p.visibleLines())
		p.paused = true
	case "G":
		// Jump cursor + scroll to the newest line and resume live
		// tailing. Matches vim's G but with the extra twist of
		// flipping back into live mode — the operator is asking
		// for "show me what's happening now".
		totalLines := len(p.filteredLines())
		if totalLines > 0 {
			p.cursor[p.source] = totalLines - 1
			p.cursorMoved[p.source] = true
		}
		p.clampScrollToCursor()
		p.paused = false
	case "g":
		p.cursor[p.source] = 0
		p.cursorMoved[p.source] = true
		p.scroll = 0
		p.paused = true

	// Filter cycling: f key cycles through presets, or number keys for direct access
	case "f":
		if !p.searching {
			p.cycleFilter()
			p.scroll = 0
		} else {
			p.searchText += "f"
		}
	// 'a' cycles the action-chip on the Verdicts tab only. Swallowed
	// silently on other tabs (and while searching) so it doesn't
	// shadow the more common "append to search" path.
	case "a":
		if !p.searching && p.source == logSourceVerdicts {
			p.cycleVerdictAction()
			p.scroll = 0
		} else if p.searching {
			p.searchText += "a"
		}
	// 't' cycles the event-type chip on the Verdicts tab only.
	// Same gating logic as 'a': silently pass through while
	// searching so typing "type" into the search field still
	// works.
	case "t":
		if !p.searching && p.source == logSourceVerdicts {
			p.cycleVerdictEventType()
			p.scroll = 0
		} else if p.searching {
			p.searchText += "t"
		}
	// 's' cycles the severity chip on the Verdicts tab only.
	// Lowercase 's' is otherwise unused by the panel (uppercase
	// 'S' is not bound either), and while searching the letter
	// must still append to the search query so grepping for
	// "severity" works.
	case "s":
		if !p.searching && p.source == logSourceVerdicts {
			p.cycleVerdictSeverity()
			p.scroll = 0
		} else if p.searching {
			p.searchText += "s"
		}
	case "1":
		if !p.searching {
			p.filterMode = filterNone
			p.scroll = 0
		}
	case "2":
		if !p.searching {
			p.filterMode = filterNoNoise
			p.scroll = 0
		}
	case "3":
		if !p.searching {
			p.filterMode = filterImportant
			p.scroll = 0
		}
	case "4":
		if !p.searching {
			p.filterMode = filterErrors
			p.scroll = 0
		}
	case "5":
		if !p.searching {
			p.filterMode = filterWarnings
			p.scroll = 0
		}
	case "6":
		if !p.searching {
			p.filterMode = filterScan
			p.scroll = 0
		}
	case "7":
		if !p.searching {
			p.filterMode = filterDrift
			p.scroll = 0
		}
	case "8":
		if !p.searching {
			p.filterMode = filterGuardrail
			p.scroll = 0
		}

	// Legacy shortcuts
	case "e":
		if !p.searching {
			if p.filterMode == filterErrors {
				p.filterMode = filterNone
			} else {
				p.filterMode = filterErrors
			}
			p.scroll = 0
		} else {
			p.searchText += "e"
		}
	case "w":
		if !p.searching {
			if p.filterMode == filterWarnings {
				p.filterMode = filterNone
			} else {
				p.filterMode = filterWarnings
			}
			p.scroll = 0
		} else {
			p.searchText += "w"
		}
	case "/":
		if !p.searching {
			p.searching = true
			p.searchText = ""
		}
	case "enter":
		if p.searching {
			p.searching = false
		}
	case "esc":
		if p.searching {
			p.searching = false
			p.searchText = ""
		}
	case "backspace":
		if p.searching && len(p.searchText) > 0 {
			p.searchText = p.searchText[:len(p.searchText)-1]
		}
	default:
		if p.searching && len(msg.String()) == 1 {
			p.searchText += msg.String()
		}
	}
	return p, nil
}

func filterPresetIndex(f string) int {
	for i, p := range filterPresets {
		if p == f {
			return i
		}
	}
	return 0
}

func (p *LogsPanel) cycleFilter() {
	for i, preset := range filterPresets {
		if preset == p.filterMode {
			next := (i + 1) % len(filterPresets)
			p.filterMode = filterPresets[next]
			return
		}
	}
	p.filterMode = filterNoNoise
}

// cycleVerdictAction advances the action-chip filter for the
// Verdicts source. Not intended to be invoked on other sources —
// handleKey gates that — so the action field on non-verdict rows
// stays unused.
func (p *LogsPanel) cycleVerdictAction() {
	for i, action := range verdictActionFilters {
		if action == p.verdictAction {
			next := (i + 1) % len(verdictActionFilters)
			p.verdictAction = verdictActionFilters[next]
			return
		}
	}
	p.verdictAction = verdictActionFilters[0]
}

// cycleVerdictEventType advances the event-type chip on the
// Verdicts tab. Independent of cycleVerdictAction: both filters
// AND together, so operators can drill into "judge rows that
// blocked" with two chip presses.
func (p *LogsPanel) cycleVerdictEventType() {
	for i, t := range verdictEventTypeFilters {
		if t == p.verdictEventType {
			next := (i + 1) % len(verdictEventTypeFilters)
			p.verdictEventType = verdictEventTypeFilters[next]
			return
		}
	}
	p.verdictEventType = verdictEventTypeFilters[0]
}

// cycleVerdictSeverity advances the severity chip. Orthogonal to
// cycleVerdictAction and cycleVerdictEventType — all three filters
// AND together, so "severity=HIGH+ × type=judge × action=block"
// is three chip presses.
func (p *LogsPanel) cycleVerdictSeverity() {
	for i, s := range verdictSeverityFilters {
		if s == p.verdictSeverity {
			next := (i + 1) % len(verdictSeverityFilters)
			p.verdictSeverity = verdictSeverityFilters[next]
			return
		}
	}
	p.verdictSeverity = verdictSeverityFilters[0]
}

// severityRank assigns a total order to our severity vocabulary so
// the HIGH+ meta-filter can compare "row severity >= HIGH" cheaply.
// Unknown values rank below INFO on purpose: surfacing them with an
// active severity filter would be misleading ("I asked for HIGH+
// and got garbage"), so we drop them.
func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// SelectedVerdict returns the structured event under the current
// per-line cursor in the Verdicts tab, or nil if the tab is not
// active or the cursor is out of range. Used by the detail modal
// (Phase 3.2).
func (p *LogsPanel) SelectedVerdict() *verdictRow {
	if p.source != logSourceVerdicts {
		return nil
	}
	// filteredVerdicts walks p.verdicts in lockstep with the
	// rendered-line filter, so indexing into its output is
	// always safe even with text/preset filters active. Prior
	// implementations keyed off scroll+visible-1 ("last visible
	// line") which surprised operators who scrolled up to a
	// specific row before pressing Enter (B4b).
	filtered := p.filteredVerdicts()
	if len(filtered) == 0 {
		return nil
	}
	idx := p.cursor[logSourceVerdicts]
	if !p.cursorMoved[logSourceVerdicts] {
		idx = len(filtered) - 1
	}
	if idx < 0 {
		idx = 0
	}
	if idx >= len(filtered) {
		idx = len(filtered) - 1
	}
	row := filtered[idx]
	return &row
}

// SelectedRawLine returns the raw line under the cursor for
// non-Verdicts sources. Returned empty when there's nothing to
// open so callers can skip the modal instead of showing a blank.
func (p *LogsPanel) SelectedRawLine() string {
	if p.source == logSourceVerdicts {
		return ""
	}
	filtered := p.filteredLines()
	if len(filtered) == 0 {
		return ""
	}
	idx := p.cursor[p.source]
	if !p.cursorMoved[p.source] {
		idx = len(filtered) - 1
	}
	if idx < 0 {
		idx = 0
	}
	if idx >= len(filtered) {
		idx = len(filtered) - 1
	}
	return filtered[idx]
}

// moveCursor shifts the per-source cursor by delta lines, clamps it
// to the filtered-view bounds, and ensures the scroll window still
// contains it. Callers flip p.paused themselves because some entry
// points (the per-source chip filter buttons) should not pause
// automatically just because the filter shrank the view under the
// cursor.
func (p *LogsPanel) moveCursor(delta int) {
	total := len(p.filteredLines())
	if total == 0 {
		p.cursor[p.source] = 0
		p.cursorMoved[p.source] = true
		return
	}
	// Seed the cursor at the bottom the first time the operator
	// presses a navigation key while live-tailing. Without this
	// seed, a user who has never moved up/down would find the
	// first down-arrow snap them to line 0 instead of the newest
	// row — confusing UX.
	if !p.cursorMoved[p.source] {
		p.cursor[p.source] = total - 1
	}
	c := p.cursor[p.source] + delta
	if c < 0 {
		c = 0
	}
	if c >= total {
		c = total - 1
	}
	p.cursor[p.source] = c
	p.cursorMoved[p.source] = true
	p.clampScrollToCursor()
}

// clampScrollToCursor keeps the scroll window covering p.cursor.
// Used whenever the cursor moves or the filtered view shrinks so
// the selected row never falls off-screen.
func (p *LogsPanel) clampScrollToCursor() {
	total := len(p.filteredLines())
	visible := p.visibleLines()
	if visible < 1 {
		visible = 1
	}
	c := p.cursor[p.source]
	if c < 0 {
		c = 0
	}
	if c >= total {
		c = total - 1
		if c < 0 {
			c = 0
		}
	}
	if c < p.scroll {
		p.scroll = c
	}
	if c >= p.scroll+visible {
		p.scroll = c - visible + 1
	}
	if p.scroll < 0 {
		p.scroll = 0
	}
	maxScroll := total - visible
	if maxScroll < 0 {
		maxScroll = 0
	}
	if p.scroll > maxScroll {
		p.scroll = maxScroll
	}
}

// SetCursor positions the per-source cursor explicitly (used by
// mouse click hit-tests on log rows). Accepts a filtered-view
// index so callers don't need to think about scroll offsets.
func (p *LogsPanel) SetCursor(filteredIdx int) {
	total := len(p.filteredLines())
	if total == 0 {
		return
	}
	if filteredIdx < 0 {
		filteredIdx = 0
	}
	if filteredIdx >= total {
		filteredIdx = total - 1
	}
	p.cursor[p.source] = filteredIdx
	p.cursorMoved[p.source] = true
	p.paused = true
	p.clampScrollToCursor()
}

// SetVerdictAction / SetVerdictEventType / SetVerdictSeverity are
// mouse-friendly setters for the three Verdicts chip filters.
// They accept the string value directly (not an index) so callers
// don't have to re-scan the *Filters slices just to click a chip
// they can see. Unknown values are silently ignored rather than
// panicking — a chip-bar layout drift shouldn't crash the TUI.
func (p *LogsPanel) SetVerdictAction(action string) {
	for _, a := range verdictActionFilters {
		if a == action {
			p.verdictAction = action
			p.scroll = 0
			p.cursorMoved[p.source] = false
			return
		}
	}
}

func (p *LogsPanel) SetVerdictEventType(t string) {
	for _, known := range verdictEventTypeFilters {
		if known == t {
			p.verdictEventType = t
			p.scroll = 0
			p.cursorMoved[p.source] = false
			return
		}
	}
}

func (p *LogsPanel) SetVerdictSeverity(s string) {
	for _, known := range verdictSeverityFilters {
		if known == s {
			p.verdictSeverity = s
			p.scroll = 0
			p.cursorMoved[p.source] = false
			return
		}
	}
}

// TogglePause toggles the pause state (for mouse clicks).
func (p *LogsPanel) TogglePause() {
	p.paused = !p.paused
}

// SetFilter sets a filter preset (for mouse clicks).
func (p *LogsPanel) SetFilter(f string) {
	p.filterMode = f
	p.scroll = 0
}

// FilterBarHeight returns how many lines the filter bar takes.
func (p *LogsPanel) FilterBarHeight() int {
	return 3 // tabs + filters + separator
}

// VerdictChipHitTest maps a click at (x, relY) on the Verdicts
// chip bar to the chip value under the cursor. relY is the
// zero-based row offset into the panel. Returns (kind, value, ok)
// where kind is one of "action", "type", "severity". Using
// lipgloss.Width ensures the hit test stays aligned with the
// rendered badge widths even when labels change.
//
// Layout (Verdicts only):
//
//	row 2 → action chips
//	row 3 → event-type chips
//	row 4 → severity chips
//
// relY outside that window returns ok=false so the caller can fall
// through to its normal log-line click handler.
func (p *LogsPanel) VerdictChipHitTest(x, relY int) (kind, value string, ok bool) {
	if p.source != logSourceVerdicts {
		return "", "", false
	}
	var labelPrefix string
	var values []string
	var labels map[string]string
	switch relY {
	case 2:
		kind = "action"
		labelPrefix = "action:"
		values = verdictActionFilters
		labels = verdictActionLabels
	case 3:
		kind = "type"
		labelPrefix = "type:  "
		values = verdictEventTypeFilters
		labels = verdictEventTypeLabels
	case 4:
		kind = "severity"
		labelPrefix = "sev:   "
		values = verdictSeverityFilters
		labels = verdictSeverityLabels
	default:
		return "", "", false
	}
	// View() renders each chip row as:
	//   "  <labelPrefix>  <badge1> <badge2> … "
	// so the leading two spaces + the prefix width + two spaces
	// before the first chip are fixed. Badges are space-separated
	// (one space).
	cursor := 2 + lipgloss.Width(labelPrefix) + 2
	for _, v := range values {
		text := fmt.Sprintf(" %s ", labels[v])
		w := lipgloss.Width(text)
		if x >= cursor && x < cursor+w {
			return kind, v, true
		}
		cursor += w + 1
	}
	return "", "", false
}

// LogRowHitTest converts a click at (relY) on a log row into a
// filtered-view index. Returns ok=false when the click fell on
// chrome (tabs, chips, separator, hint). Callers use this to set
// the cursor and optionally open the detail modal.
func (p *LogsPanel) LogRowHitTest(relY int) (idx int, ok bool) {
	headerRows := 2 // tabs + filter bar
	if p.source == logSourceVerdicts {
		headerRows += 3 // action / type / severity chip rows
	}
	headerRows++ // separator
	if p.searching {
		headerRows++
	}
	if relY < headerRows {
		return 0, false
	}
	filtered := p.filteredLines()
	rowIdx := p.scroll + (relY - headerRows)
	if rowIdx < 0 || rowIdx >= len(filtered) {
		return 0, false
	}
	return rowIdx, true
}

// ScrollBy adjusts the scroll offset for mouse wheel.
func (p *LogsPanel) ScrollBy(delta int) {
	p.scroll += delta
	if p.scroll < 0 {
		p.scroll = 0
	}
	maxScroll := len(p.filteredLines()) - p.visibleLines()
	if maxScroll < 0 {
		maxScroll = 0
	}
	if p.scroll > maxScroll {
		p.scroll = maxScroll
	}
	if delta != 0 {
		p.paused = true
	}
}

// SetSize sets the panel dimensions.
func (p *LogsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

// View renders the logs panel.
func (p *LogsPanel) View() string {
	var b strings.Builder

	// Row 0: Source tabs + PAUSED/LIVE + line count
	b.WriteString("  ")
	for i, name := range logSourceNames {
		label := fmt.Sprintf("  %s  ", name)
		if i == p.source {
			b.WriteString(p.theme.ActiveTab.Render(label))
		} else {
			b.WriteString(p.theme.InactiveTab.Render(label))
		}
		b.WriteString("  ")
	}

	b.WriteString("   ")
	if p.paused {
		pauseBadge := lipgloss.NewStyle().
			Background(lipgloss.Color("208")).
			Foreground(lipgloss.Color("16")).
			Bold(true).
			Padding(0, 1).
			Render("PAUSED")
		b.WriteString(pauseBadge)
		b.WriteString("  ")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("Space to resume"))
	} else {
		liveBadge := lipgloss.NewStyle().
			Background(lipgloss.Color("46")).
			Foreground(lipgloss.Color("16")).
			Bold(true).
			Padding(0, 1).
			Render("LIVE")
		b.WriteString(liveBadge)
	}

	totalLines := len(p.lines[p.source])
	filteredCount := len(p.filteredLines())
	b.WriteString("   ")
	if filteredCount < totalLines {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			fmt.Sprintf("%d / %d lines", filteredCount, totalLines)))
	} else {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			fmt.Sprintf("%d lines", totalLines)))
	}
	b.WriteString("\n")

	// Row 1: Filter bar — wider buttons with more padding
	b.WriteString("  ")
	for i, preset := range filterPresets {
		label := filterLabels[preset]
		num := fmt.Sprintf("%d", i+1)
		text := fmt.Sprintf(" %s %s ", num, label)

		if preset == p.filterMode {
			badge := lipgloss.NewStyle().
				Background(lipgloss.Color("62")).
				Foreground(lipgloss.Color("230")).
				Bold(true).
				Render(text)
			b.WriteString(badge)
		} else {
			badge := lipgloss.NewStyle().
				Background(lipgloss.Color("237")).
				Foreground(lipgloss.Color("252")).
				Render(text)
			b.WriteString(badge)
		}
		b.WriteString("  ")
	}
	if p.searchText != "" {
		b.WriteString("  " + p.theme.KeyHint.Render("search: "+p.searchText))
	}
	b.WriteString("\n")

	// Row 2: Verdicts-only action-chip bar. The chip bar is only
	// rendered on the Verdicts source — on Gateway/Watchdog the
	// structured action dimension is meaningless and the space is
	// better used for log content.
	if p.source == logSourceVerdicts {
		b.WriteString("  ")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("action:"))
		b.WriteString("  ")
		for _, action := range verdictActionFilters {
			label := verdictActionLabels[action]
			text := fmt.Sprintf(" %s ", label)
			if action == p.verdictAction {
				badge := lipgloss.NewStyle().
					Background(lipgloss.Color("62")).
					Foreground(lipgloss.Color("230")).
					Bold(true).
					Render(text)
				b.WriteString(badge)
			} else {
				badge := lipgloss.NewStyle().
					Background(lipgloss.Color("237")).
					Foreground(lipgloss.Color("252")).
					Render(text)
				b.WriteString(badge)
			}
			b.WriteString(" ")
		}
		b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("(press 'a' to cycle)"))
		b.WriteString("\n")

		// Second chip bar: event type. Renders under the action
		// chip bar so the two filters read like "action × type" in
		// the UI, matching how operators actually think about
		// guardrail decisions.
		b.WriteString("  ")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("type:  "))
		b.WriteString("  ")
		for _, t := range verdictEventTypeFilters {
			label := verdictEventTypeLabels[t]
			text := fmt.Sprintf(" %s ", label)
			if t == p.verdictEventType {
				badge := lipgloss.NewStyle().
					Background(lipgloss.Color("62")).
					Foreground(lipgloss.Color("230")).
					Bold(true).
					Render(text)
				b.WriteString(badge)
			} else {
				badge := lipgloss.NewStyle().
					Background(lipgloss.Color("237")).
					Foreground(lipgloss.Color("252")).
					Render(text)
				b.WriteString(badge)
			}
			b.WriteString(" ")
		}
		b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("(press 't' to cycle, 'J' for SQLite judge)"))
		b.WriteString("\n")

		// Third chip row: severity. Sits under type so the three
		// chips read top-to-bottom as operators naturally describe
		// an incident — "action × type × severity".
		b.WriteString("  ")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("sev:   "))
		b.WriteString("  ")
		for _, s := range verdictSeverityFilters {
			label := verdictSeverityLabels[s]
			text := fmt.Sprintf(" %s ", label)
			if s == p.verdictSeverity {
				badge := lipgloss.NewStyle().
					Background(lipgloss.Color("62")).
					Foreground(lipgloss.Color("230")).
					Bold(true).
					Render(text)
				b.WriteString(badge)
			} else {
				badge := lipgloss.NewStyle().
					Background(lipgloss.Color("237")).
					Foreground(lipgloss.Color("252")).
					Render(text)
				b.WriteString(badge)
			}
			b.WriteString(" ")
		}
		b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("(press 's' to cycle)"))
		b.WriteString("\n")
	}

	// Separator
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", p.width)))
	b.WriteString("\n")

	// Search input
	if p.searching {
		b.WriteString("  / " + p.searchText + "█\n")
	}

	// Log content
	filtered := p.filteredLines()
	visible := p.visibleLines()

	start := p.scroll
	if start < 0 {
		start = 0
	}
	end := start + visible
	if end > len(filtered) {
		end = len(filtered)
	}
	if start >= len(filtered) {
		start = 0
		end = 0
	}

	// Compute cursor position lazily so "live tail + no nav yet"
	// highlights the newest line instead of a stale zero.
	cursorIdx := p.cursor[p.source]
	if !p.cursorMoved[p.source] {
		cursorIdx = len(filtered) - 1
	}
	cursorStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("236")).
		Bold(true)
	for i := start; i < end; i++ {
		line := filtered[i]
		colored := p.colorLine(line)
		if i == cursorIdx {
			// Render a gutter marker so the selection is visible
			// even on terminals where background color is muted
			// by a transparent theme.
			b.WriteString(cursorStyle.Render("▸ " + colored))
			b.WriteString("\n")
			continue
		}
		b.WriteString("  " + colored + "\n")
	}

	if len(filtered) == 0 && len(p.lines[p.source]) > 0 {
		b.WriteString("\n")
		b.WriteString(p.theme.Dimmed.Render("  No lines match the current filter. Press f to cycle or 1 for All."))
	} else if len(p.lines[p.source]) == 0 {
		b.WriteString(p.theme.Dimmed.Render("  Log file is empty or not yet created. Start the gateway with : then start."))
	}

	// Hint bar — on the Verdicts tab we advertise the chip
	// shortcuts ('a' action, 't' type, 's' severity) so operators
	// learning the TUI don't have to skim docs. Gateway/Watchdog
	// keep the shorter hint because the chip bar isn't rendered
	// there.
	b.WriteString("\n")
	hint := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Italic(true)
	if p.source == logSourceVerdicts {
		b.WriteString(hint.Render(fmt.Sprintf(
			"  Streaming %s. ↑/↓ select · Enter detail · Space pause · / search · a/t/s chips · J judge history.",
			logSourceNames[p.source])))
	} else {
		b.WriteString(hint.Render(fmt.Sprintf(
			"  Streaming %s. ↑/↓ select · Enter detail · Space pause · / search · e errors · w warnings.",
			logSourceNames[p.source])))
	}

	return b.String()
}

func (p *LogsPanel) visibleLines() int {
	v := p.height - 7 // tabs + filters + separator + hint + padding
	if p.source == logSourceVerdicts {
		// Verdicts tab renders three extra chip rows (action +
		// type + severity) above the log body. Without accounting
		// for this the cursor math in SelectedVerdict drifts by
		// the same number of lines — historically this bug
		// showed up as "the detail modal doesn't match the row
		// I selected" after a chip was added.
		v -= 3
	}
	if p.searching {
		v--
	}
	if v < 5 {
		v = 5
	}
	return v
}

func (p *LogsPanel) filteredLines() []string {
	all := p.lines[p.source]

	if p.filterMode == filterNone && p.searchText == "" {
		return all
	}

	var result []string
	for _, line := range all {
		if p.lineMatchesCurrentFilter(strings.ToLower(line)) {
			result = append(result, line)
		}
	}
	return result
}

// lineMatchesCurrentFilter returns true when a rendered log line
// (already lowercased by the caller) passes both the free-text
// search and the active preset filter. Factored out so
// filteredLines and filteredVerdicts stay in lockstep — if either
// diverged, the detail-modal selection would quietly pick the wrong
// row (M1 regression). Caller passes `lower` as a small
// optimisation so we do not re-lowercase once per predicate branch.
func (p *LogsPanel) lineMatchesCurrentFilter(lower string) bool {
	if p.searchText != "" {
		if !strings.Contains(lower, strings.ToLower(p.searchText)) {
			return false
		}
	}
	switch p.filterMode {
	case filterNone:
		// No preset — search-only path already handled above.
	case filterNoNoise:
		if p.isNoise(lower) {
			return false
		}
	case filterImportant:
		if !p.isImportant(lower) {
			return false
		}
	case filterErrors:
		if !strings.Contains(lower, "error") && !strings.Contains(lower, "fatal") &&
			!strings.Contains(lower, "panic") {
			return false
		}
	case filterWarnings:
		if !strings.Contains(lower, "error") && !strings.Contains(lower, "fatal") &&
			!strings.Contains(lower, "panic") && !strings.Contains(lower, "warn") {
			return false
		}
	case filterScan:
		if !strings.Contains(lower, "scan") && !strings.Contains(lower, "finding") {
			return false
		}
	case filterDrift:
		if !strings.Contains(lower, "drift") && !strings.Contains(lower, "rescan") {
			return false
		}
	case filterGuardrail:
		if !strings.Contains(lower, "guardrail") && !strings.Contains(lower, "guard") {
			return false
		}
	}
	return true
}

// filteredVerdicts returns the subset of p.verdicts whose rendered
// counterpart in p.lines[logSourceVerdicts] survives the same
// text/preset filter applied by filteredLines. The two slices are
// populated in lockstep by loadVerdicts so index i in p.verdicts
// always corresponds to index i in p.lines[logSourceVerdicts]; this
// helper preserves that invariant under filtering so SelectedVerdict
// can cross-reference the displayed index back to the typed row.
//
// Returns nil when we are not on the Verdicts source or the two
// slices have drifted (defensive: a slice-length mismatch means the
// render path is mid-rebuild and selection must be a no-op rather
// than open the wrong detail modal).
func (p *LogsPanel) filteredVerdicts() []verdictRow {
	if p.source != logSourceVerdicts {
		return nil
	}
	all := p.lines[logSourceVerdicts]
	if len(all) != len(p.verdicts) {
		return nil
	}
	if p.filterMode == filterNone && p.searchText == "" {
		// Copy so callers can safely retain the slice without
		// aliasing our live buffer.
		out := make([]verdictRow, len(p.verdicts))
		copy(out, p.verdicts)
		return out
	}
	out := make([]verdictRow, 0, len(all))
	for i, line := range all {
		if p.lineMatchesCurrentFilter(strings.ToLower(line)) {
			out = append(out, p.verdicts[i])
		}
	}
	return out
}

func (p *LogsPanel) isNoise(lower string) bool {
	for _, pat := range noisePatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func (p *LogsPanel) isImportant(lower string) bool {
	for _, pat := range importantPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func (p *LogsPanel) colorLine(line string) string {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "error") || strings.Contains(lower, "fatal") || strings.Contains(lower, "panic") {
		return p.theme.LogError.Render(line)
	}
	if strings.Contains(lower, "warn") {
		return p.theme.LogWarn.Render(line)
	}
	// Highlight key action keywords in blue
	if strings.Contains(lower, "block") || strings.Contains(lower, "allow") ||
		strings.Contains(lower, "scan") || strings.Contains(lower, "verdict") {
		return p.theme.LogKeyword.Render(line)
	}
	if strings.Contains(lower, "connected") || strings.Contains(lower, "running") || strings.Contains(lower, "healthy") {
		return p.theme.Clean.Render(line)
	}
	// Dim noise even when shown in "All" mode
	if p.isNoise(lower) {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(line)
	}
	return line
}

func (p *LogsPanel) loadFile(source int, path string) {
	const maxBytes = 512 * 1024
	f, err := os.Open(path)
	if err != nil {
		p.errMsgs[source] = fmt.Sprintf("Cannot open: %v", err)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		p.errMsgs[source] = fmt.Sprintf("Cannot stat: %v", err)
		return
	}
	p.errMsgs[source] = ""
	size := info.Size()
	readSize := size
	if readSize > maxBytes {
		readSize = maxBytes
	}
	offset := size - readSize
	buf := make([]byte, readSize)
	n, err := f.ReadAt(buf, offset)
	if err != nil && n == 0 {
		return
	}
	buf = buf[:n]

	if offset > 0 {
		if idx := strings.IndexByte(string(buf), '\n'); idx >= 0 {
			buf = buf[idx+1:]
		}
	}

	lines := strings.Split(string(buf), "\n")
	const maxLines = 5000
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	p.lines[source] = lines
}

// loadVerdicts tails gateway.jsonl and parses each structured
// event into a typed verdictRow. Non-JSON lines (shouldn't happen
// on the JSONL stream, but the writer may roll mid-line during
// rotation) are silently dropped — the errMsgs slot would flap
// for operators otherwise.
//
// Rendered lines go into p.lines[logSourceVerdicts] so the
// existing scroll/search machinery works unchanged; verdictRow
// keeps the parsed shape for the action-chip filter + future
// detail pane.
func (p *LogsPanel) loadVerdicts(path string) {
	const maxBytes = 512 * 1024
	f, err := os.Open(path)
	if err != nil {
		p.errMsgs[logSourceVerdicts] = fmt.Sprintf("Cannot open: %v", err)
		p.lines[logSourceVerdicts] = nil
		p.verdicts = nil
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		p.errMsgs[logSourceVerdicts] = fmt.Sprintf("Cannot stat: %v", err)
		return
	}
	p.errMsgs[logSourceVerdicts] = ""
	size := info.Size()
	readSize := size
	if readSize > maxBytes {
		readSize = maxBytes
	}
	offset := size - readSize
	buf := make([]byte, readSize)
	n, err := f.ReadAt(buf, offset)
	if err != nil && n == 0 {
		return
	}
	buf = buf[:n]

	if offset > 0 {
		if idx := strings.IndexByte(string(buf), '\n'); idx >= 0 {
			buf = buf[idx+1:]
		}
	}

	rawLines := strings.Split(string(buf), "\n")
	const maxLines = 2000
	if len(rawLines) > maxLines {
		rawLines = rawLines[len(rawLines)-maxLines:]
	}

	rows := make([]verdictRow, 0, len(rawLines))
	rendered := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		row, ok := parseVerdictRow(line)
		if !ok {
			continue
		}
		if p.verdictEventType != "" {
			// Event-type chip is case-insensitive; an empty
			// event_type on a malformed row should be hidden while
			// a filter is active — otherwise "Judge only" would
			// include uncategorised noise.
			if !strings.EqualFold(row.eventType, p.verdictEventType) {
				continue
			}
		}
		if p.verdictSeverity != "" {
			// Severity chip supports the HIGH+ meta-filter
			// explicitly; plain names match case-insensitively.
			// Rows whose severity does not clear the bar are
			// dropped — matching operator expectation of "show me
			// HIGH or worse, nothing else".
			if p.verdictSeverity == "HIGH+" {
				if severityRank(row.severity) < severityRank("HIGH") {
					continue
				}
			} else if !strings.EqualFold(row.severity, p.verdictSeverity) {
				continue
			}
		}
		if p.verdictAction != "" {
			// The action-chip applies to anything that advertises an
			// action: verdict rows (stage decisions) and judge rows
			// (which carry the judge's own allow/alert/block).
			// Lifecycle / error / diagnostic rows have no action; we
			// hide them entirely while a specific action filter is
			// active so operators see a clean "only block decisions"
			// stream. The prior gate keyed only on eventType ==
			// "verdict", which left every judge row visible even when
			// the chip was set to "allow" — confusing UX.
			if row.action == "" || !strings.EqualFold(row.action, p.verdictAction) {
				continue
			}
		}
		rows = append(rows, row)
		rendered = append(rendered, renderVerdictLine(row))
	}
	p.verdicts = rows
	p.lines[logSourceVerdicts] = rendered
}

// parseVerdictRow extracts the typed fields we care about from a
// single gateway.jsonl line. Kept permissive — missing fields just
// become empty strings so row rendering degrades gracefully
// instead of dropping the record.
//
// The parse target mirrors gatewaylog.Event end-to-end. We pay the
// extra few dozen unused strings per record in exchange for a
// detail modal that does not need a second JSON pass, and a
// search/filter experience that can key on any documented field.
func parseVerdictRow(line string) (verdictRow, bool) {
	var raw struct {
		Timestamp time.Time `json:"ts"`
		EventType string    `json:"event_type"`
		Severity  string    `json:"severity"`
		Model     string    `json:"model"`
		Direction string    `json:"direction"`
		RequestID string    `json:"request_id"`
		RunID     string    `json:"run_id"`
		SessionID string    `json:"session_id"`
		Provider  string    `json:"provider"`
		Verdict   *struct {
			Stage      string   `json:"stage"`
			Action     string   `json:"action"`
			Reason     string   `json:"reason"`
			Categories []string `json:"categories"`
			Latency    int64    `json:"latency_ms"`
		} `json:"verdict"`
		Judge *struct {
			Kind        string         `json:"kind"`
			Action      string         `json:"action"`
			Severity    string         `json:"severity"`
			Latency     int64          `json:"latency_ms"`
			InputBytes  int            `json:"input_bytes"`
			Findings    []judgeFinding `json:"findings"`
			RawResponse string         `json:"raw_response"`
			ParseError  string         `json:"parse_error"`
		} `json:"judge"`
		Lifecycle *struct {
			Subsystem  string            `json:"subsystem"`
			Transition string            `json:"transition"`
			Details    map[string]string `json:"details"`
		} `json:"lifecycle"`
		Error *struct {
			Subsystem string `json:"subsystem"`
			Code      string `json:"code"`
			Message   string `json:"message"`
			Cause     string `json:"cause"`
		} `json:"error"`
		Diagnostic *struct {
			Component string `json:"component"`
			Message   string `json:"message"`
		} `json:"diagnostic"`
	}
	if err := jsonUnmarshal([]byte(line), &raw); err != nil {
		return verdictRow{}, false
	}
	row := verdictRow{
		raw:       line,
		timestamp: raw.Timestamp,
		severity:  raw.Severity,
		model:     raw.Model,
		direction: raw.Direction,
		eventType: raw.EventType,
		requestID: raw.RequestID,
		runID:     raw.RunID,
		sessionID: raw.SessionID,
		provider:  raw.Provider,
	}
	if raw.Verdict != nil {
		row.stage = raw.Verdict.Stage
		row.action = raw.Verdict.Action
		row.reason = raw.Verdict.Reason
		row.categories = raw.Verdict.Categories
		row.latencyMs = raw.Verdict.Latency
	}
	if raw.Judge != nil {
		row.kind = raw.Judge.Kind
		if row.action == "" {
			row.action = raw.Judge.Action
		}
		// Judge events carry an envelope severity AND a judge-layer
		// severity; the former is what the sink pipeline uses for
		// its own routing, the latter is what the judge itself
		// decided. Envelope wins in the rendered row (row.severity)
		// but we keep the judge-layer value so the detail modal
		// can show both without re-parsing JSON.
		row.judgeSeverity = raw.Judge.Severity
		row.judgeInputBytes = raw.Judge.InputBytes
		row.judgeRaw = raw.Judge.RawResponse
		row.judgeParseError = raw.Judge.ParseError
		row.judgeFindings = raw.Judge.Findings
		if row.latencyMs == 0 {
			row.latencyMs = raw.Judge.Latency
		}
	}
	if raw.Lifecycle != nil {
		row.lifecycleSubsystem = raw.Lifecycle.Subsystem
		row.lifecycleTransition = raw.Lifecycle.Transition
		row.lifecycleDetails = raw.Lifecycle.Details
	}
	if raw.Error != nil {
		row.errorSubsystem = raw.Error.Subsystem
		row.errorCode = raw.Error.Code
		row.errorMessage = raw.Error.Message
		row.errorCause = raw.Error.Cause
	}
	if raw.Diagnostic != nil {
		row.diagnosticComponent = raw.Diagnostic.Component
		row.diagnosticMessage = raw.Diagnostic.Message
	}
	return row, true
}

// renderVerdictLine produces the compact single-line view of a
// structured event. Kept intentionally close to the pretty writer
// format in internal/gatewaylog/pretty.go so operators see the
// same shape whether they're tailing stderr or the TUI.
//
// Every branch has a deterministic column layout so eyeballing
// columns at scroll speed works; operator feedback on the original
// prose rendering was that lifecycle/error rows dumped a whole
// JSON blob and made it hard to see just a transition or a code.
func renderVerdictLine(r verdictRow) string {
	ts := r.timestamp.Format("15:04:05.000")
	switch r.eventType {
	case "verdict":
		// Suffix with categories + latency when present so operators
		// can eyeball "who decided, why, and how fast" without
		// opening the detail modal. Categories are capped at the
		// first two to keep the line from wrapping; the full list
		// stays one Enter away in verdictDetailPairs.
		suffix := truncateVerdictReason(r.reason, 100)
		if len(r.categories) > 0 {
			suffix += " [" + strings.Join(trimCategories(r.categories, 2), ",") + "]"
		}
		if r.latencyMs > 0 {
			suffix += fmt.Sprintf(" (%dms)", r.latencyMs)
		}
		return fmt.Sprintf("%s VERDICT %-7s %-8s %-10s %s %s -- %s",
			ts,
			strings.ToUpper(nonEmpty(r.action, "none")),
			strings.ToUpper(nonEmpty(r.severity, "info")),
			nonEmpty(r.stage, "-"),
			nonEmpty(r.direction, "-"),
			nonEmpty(r.model, "-"),
			suffix,
		)
	case "judge":
		// Include latency + input_bytes so pathological judge calls
		// (slow model, oversized prompt) are visible at a glance.
		suffix := ""
		if r.judgeInputBytes > 0 {
			suffix += fmt.Sprintf(" in=%dB", r.judgeInputBytes)
		}
		if r.latencyMs > 0 {
			suffix += fmt.Sprintf(" %dms", r.latencyMs)
		}
		if r.judgeParseError != "" {
			suffix += " parse=error"
		}
		return fmt.Sprintf("%s JUDGE   %-7s %-8s kind=%-10s dir=%s model=%s%s",
			ts,
			strings.ToUpper(nonEmpty(r.action, "none")),
			strings.ToUpper(nonEmpty(r.severity, "info")),
			nonEmpty(r.kind, "-"),
			nonEmpty(r.direction, "-"),
			nonEmpty(r.model, "-"),
			suffix,
		)
	case "lifecycle":
		// Human-readable shape: "SUBSYSTEM TRANSITION optional=key=value".
		// Falls back to raw JSON when the payload is empty so we
		// never lose information, but the structured case is the
		// 99% path and worth rendering compactly.
		if r.lifecycleSubsystem != "" || r.lifecycleTransition != "" {
			details := renderDetailsInline(r.lifecycleDetails, 3)
			return fmt.Sprintf("%s LIFECYCLE %-10s %-10s %s",
				ts,
				strings.ToUpper(nonEmpty(r.lifecycleSubsystem, "-")),
				strings.ToUpper(nonEmpty(r.lifecycleTransition, "-")),
				details)
		}
		return fmt.Sprintf("%s LIFECYCLE %s", ts, r.raw)
	case "error":
		if r.errorCode != "" || r.errorMessage != "" {
			return fmt.Sprintf("%s ERROR     %-10s code=%s msg=%s",
				ts,
				strings.ToUpper(nonEmpty(r.errorSubsystem, "-")),
				nonEmpty(r.errorCode, "-"),
				truncateVerdictReason(r.errorMessage, 120))
		}
		return fmt.Sprintf("%s ERROR   %s", ts, r.raw)
	case "diagnostic":
		if r.diagnosticComponent != "" || r.diagnosticMessage != "" {
			return fmt.Sprintf("%s DIAG      %-10s %s",
				ts,
				strings.ToUpper(nonEmpty(r.diagnosticComponent, "-")),
				truncateVerdictReason(r.diagnosticMessage, 120))
		}
		return fmt.Sprintf("%s DIAG    %s", ts, r.raw)
	default:
		return fmt.Sprintf("%s %-9s %s", ts, strings.ToUpper(nonEmpty(r.eventType, "event")), r.raw)
	}
}

// trimCategories caps cats at n entries for compact rendering.
// When cats is short enough to fit, it is returned verbatim. On
// overflow the result is n real entries plus a single synthetic
// "+Kmore" marker (so length is n+1) — this is intentional: the
// marker preserves operator signal that more categories exist
// without eating one of the first-n slots.
//
// The overflow branch uses a 3-index slice to cap capacity and
// force append into a fresh backing array, so the caller's slice
// is never mutated.
func trimCategories(cats []string, n int) []string {
	if n <= 0 || len(cats) == 0 {
		return nil
	}
	if len(cats) <= n {
		return cats
	}
	return append(cats[:n:n], "+"+fmt.Sprint(len(cats)-n)+"more")
}

// renderDetailsInline compacts a lifecycle details map into a
// deterministic "k=v k=v" suffix. Ordering is alphabetical so the
// line is stable across runs (map iteration would otherwise shuffle
// keys and hurt eyeballing). n caps how many key/value pairs we
// show inline; the full map stays available in the detail modal.
//
// n <= 0 returns an empty string — matches the trimCategories
// contract and guards against a keys[:n] panic if a caller ever
// threads a dynamic cap through here.
func renderDetailsInline(m map[string]string, n int) string {
	if n <= 0 || len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > n {
		keys = keys[:n]
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, m[k]))
	}
	return strings.Join(parts, " ")
}

// truncateVerdictReason clips s to n runes (not bytes) so multi-byte
// UTF-8 sequences are never sliced mid-codepoint. The prior
// byte-indexed implementation could emit invalid UTF-8 whenever a
// redacted token or user-supplied snippet contained non-ASCII text,
// which shows up as mojibake in the TUI.
func truncateVerdictReason(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string(runes[:n-1]) + "…"
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

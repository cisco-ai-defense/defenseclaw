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

	// Verdicts-only state: cached structured events and a chip-
	// filter for action (block/alert/allow). Cardinalities other
	// than action (severity, category, model) are queryable via
	// the existing text-search field to keep the chip bar short.
	verdicts      []verdictRow
	verdictAction string // one of verdictActionFilters
}

// verdictRow is a pre-rendered Verdicts-tab entry. We keep the
// structured fields alongside the rendered line so typed filters
// run in O(n) over in-memory rows rather than re-parsing JSON per
// keystroke.
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
		if p.scroll > 0 {
			p.scroll--
			p.paused = true
		}
	case "down", "j":
		maxScroll := len(p.filteredLines()) - p.visibleLines()
		if maxScroll < 0 {
			maxScroll = 0
		}
		if p.scroll < maxScroll {
			p.scroll++
		}
	case "G":
		totalLines := len(p.filteredLines())
		visible := p.visibleLines()
		if totalLines > visible {
			p.scroll = totalLines - visible
		}
		p.paused = false
	case "g":
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

// SelectedVerdict returns the structured event under the current
// cursor in the Verdicts tab, or nil if the tab is not active or
// the cursor is out of range. Used by the detail modal (Phase 3.2).
func (p *LogsPanel) SelectedVerdict() *verdictRow {
	if p.source != logSourceVerdicts {
		return nil
	}
	filtered := p.filteredLines()
	if len(filtered) == 0 {
		return nil
	}
	// Convert scroll + visible position to the underlying row.
	// scroll points at the first displayed row; cursor is the
	// last visible line since the user typically "tails" the
	// view — pressing Enter should open that most-recent event.
	idx := p.scroll + p.visibleLines() - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(filtered) {
		idx = len(filtered) - 1
	}
	// Map filtered rendered index back to p.verdicts. Because the
	// filter is pure (same loop produced both), the indices line
	// up as long as p.verdicts was built from the same pass.
	if idx >= len(p.verdicts) {
		return nil
	}
	row := p.verdicts[idx]
	return &row
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

	for i := start; i < end; i++ {
		line := filtered[i]
		colored := p.colorLine(line)
		b.WriteString("  " + colored + "\n")
	}

	if len(filtered) == 0 && len(p.lines[p.source]) > 0 {
		b.WriteString("\n")
		b.WriteString(p.theme.Dimmed.Render("  No lines match the current filter. Press f to cycle or 1 for All."))
	} else if len(p.lines[p.source]) == 0 {
		b.WriteString(p.theme.Dimmed.Render("  Log file is empty or not yet created. Start the gateway with : then start."))
	}

	// Hint bar
	b.WriteString("\n")
	hint := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Italic(true)
	b.WriteString(hint.Render(fmt.Sprintf("  Streaming %s. Space to pause, / to search, e for errors, w for warnings.",
		logSourceNames[p.source])))

	return b.String()
}

func (p *LogsPanel) visibleLines() int {
	v := p.height - 7 // tabs + filters + separator + hint + padding
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
		lower := strings.ToLower(line)

		// Apply search filter
		if p.searchText != "" {
			if !strings.Contains(lower, strings.ToLower(p.searchText)) {
				continue
			}
		}

		// Apply preset filter
		switch p.filterMode {
		case filterNoNoise:
			if p.isNoise(lower) {
				continue
			}
		case filterImportant:
			if !p.isImportant(lower) {
				continue
			}
		case filterErrors:
			if !strings.Contains(lower, "error") && !strings.Contains(lower, "fatal") && !strings.Contains(lower, "panic") {
				continue
			}
		case filterWarnings:
			if !strings.Contains(lower, "error") && !strings.Contains(lower, "fatal") &&
				!strings.Contains(lower, "panic") && !strings.Contains(lower, "warn") {
				continue
			}
		case filterScan:
			if !strings.Contains(lower, "scan") && !strings.Contains(lower, "finding") {
				continue
			}
		case filterDrift:
			if !strings.Contains(lower, "drift") && !strings.Contains(lower, "rescan") {
				continue
			}
		case filterGuardrail:
			if !strings.Contains(lower, "guardrail") && !strings.Contains(lower, "guard") {
				continue
			}
		}

		result = append(result, line)
	}
	return result
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
func parseVerdictRow(line string) (verdictRow, bool) {
	var raw struct {
		Timestamp time.Time `json:"ts"`
		EventType string    `json:"event_type"`
		Severity  string    `json:"severity"`
		Model     string    `json:"model"`
		Direction string    `json:"direction"`
		Verdict   *struct {
			Stage  string `json:"stage"`
			Action string `json:"action"`
			Reason string `json:"reason"`
		} `json:"verdict"`
		Judge *struct {
			Kind    string `json:"kind"`
			Action  string `json:"action"`
			Latency int64  `json:"latency_ms"`
		} `json:"judge"`
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
	}
	if raw.Verdict != nil {
		row.stage = raw.Verdict.Stage
		row.action = raw.Verdict.Action
		row.reason = raw.Verdict.Reason
	}
	if raw.Judge != nil {
		row.kind = raw.Judge.Kind
		if row.action == "" {
			row.action = raw.Judge.Action
		}
	}
	return row, true
}

// renderVerdictLine produces the compact single-line view of a
// structured event. Kept intentionally close to the pretty writer
// format in internal/gatewaylog/pretty.go so operators see the
// same shape whether they're tailing stderr or the TUI.
func renderVerdictLine(r verdictRow) string {
	ts := r.timestamp.Format("15:04:05.000")
	switch r.eventType {
	case "verdict":
		return fmt.Sprintf("%s VERDICT %-7s %-5s %-10s %s %s -- %s",
			ts,
			strings.ToUpper(nonEmpty(r.action, "none")),
			strings.ToUpper(nonEmpty(r.severity, "info")),
			nonEmpty(r.stage, "-"),
			nonEmpty(r.direction, "-"),
			nonEmpty(r.model, "-"),
			truncateVerdictReason(r.reason, 120),
		)
	case "judge":
		return fmt.Sprintf("%s JUDGE   %-7s %-5s kind=%s dir=%s model=%s",
			ts,
			strings.ToUpper(nonEmpty(r.action, "none")),
			strings.ToUpper(nonEmpty(r.severity, "info")),
			nonEmpty(r.kind, "-"),
			nonEmpty(r.direction, "-"),
			nonEmpty(r.model, "-"),
		)
	case "lifecycle":
		return fmt.Sprintf("%s LIFECYCLE %s", ts, r.raw)
	case "error":
		return fmt.Sprintf("%s ERROR   %s", ts, r.raw)
	default:
		return fmt.Sprintf("%s %-9s %s", ts, strings.ToUpper(nonEmpty(r.eventType, "event")), r.raw)
	}
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

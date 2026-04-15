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
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	logSourceGateway = iota
	logSourceWatchdog
	logSourceCount
)

var logSourceNames = [logSourceCount]string{"Gateway", "Watchdog"}

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

type logPollMsg struct {
	lines []string
}

// LogsPanel provides live log tailing for gateway.log and watchdog.log.
type LogsPanel struct {
	theme      *Theme
	dataDir    string
	source     int
	lines      [logSourceCount][]string
	scroll     int
	width      int
	height     int
	paused     bool
	filterMode string
	searching  bool
	searchText string
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
	switch msg.(type) {
	case logPollMsg:
		p.loadFile(logSourceGateway, filepath.Join(p.dataDir, "gateway.log"))
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
		return p.handleKey(msg.(tea.KeyPressMsg))
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
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return
	}
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

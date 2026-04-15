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
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

// activityEntry represents one command execution in the activity log.
type activityEntry struct {
	Command   string
	StartTime time.Time
	Output    []string
	ExitCode  int
	Duration  time.Duration
	Done      bool
	Expanded  bool
}

// ActivityPanel shows command execution output and history.
type ActivityPanel struct {
	theme      *Theme
	entries    []activityEntry
	cursor     int
	width      int
	height     int
	termMode   bool // when true, show raw terminal output for latest command
	termScroll int  // scroll offset in terminal mode (from bottom)
}

// NewActivityPanel creates the activity panel.
func NewActivityPanel(theme *Theme) ActivityPanel {
	return ActivityPanel{theme: theme}
}

// AddEntry adds a new running command entry and enters terminal mode.
func (p *ActivityPanel) AddEntry(command string) {
	p.entries = append(p.entries, activityEntry{
		Command:   command,
		StartTime: time.Now(),
		Expanded:  true,
	})
	p.cursor = len(p.entries) - 1
	p.termMode = true
	p.termScroll = 0
}

// AppendOutput adds a line of output to the current running command.
func (p *ActivityPanel) AppendOutput(line string) {
	if len(p.entries) == 0 {
		return
	}
	idx := len(p.entries) - 1
	p.entries[idx].Output = append(p.entries[idx].Output, line)
}

// FinishEntry marks the current command as done.
func (p *ActivityPanel) FinishEntry(exitCode int, duration time.Duration) {
	if len(p.entries) == 0 {
		return
	}
	idx := len(p.entries) - 1
	p.entries[idx].Done = true
	p.entries[idx].ExitCode = exitCode
	p.entries[idx].Duration = duration
}

// SetSize sets the panel dimensions.
func (p *ActivityPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

// LastCommand returns the name of the most recent command, or "".
func (p *ActivityPanel) LastCommand() string {
	if len(p.entries) == 0 {
		return ""
	}
	return p.entries[len(p.entries)-1].Command
}

// Count returns the number of commands run.
func (p *ActivityPanel) Count() int {
	return len(p.entries)
}

// ScrollBy adjusts the cursor position for mouse wheel, or scrolls in terminal mode.
func (p *ActivityPanel) ScrollBy(delta int) {
	if p.termMode {
		p.termScroll -= delta // negative delta = scroll up = increase offset
		if p.termScroll < 0 {
			p.termScroll = 0
		}
		if p.cursor >= 0 && p.cursor < len(p.entries) {
			maxScroll := len(p.entries[p.cursor].Output)
			if p.termScroll > maxScroll {
				p.termScroll = maxScroll
			}
		}
		return
	}
	p.cursor += delta
	if p.cursor < 0 {
		p.cursor = 0
	}
	if p.cursor >= len(p.entries) {
		p.cursor = len(p.entries) - 1
	}
}

// SetCursor sets the cursor for mouse click.
func (p *ActivityPanel) SetCursor(i int) {
	if i < 0 {
		i = 0
	}
	if i >= len(p.entries) {
		i = len(p.entries) - 1
	}
	p.cursor = i
}

// IsRunning returns whether a command is currently executing.
func (p *ActivityPanel) IsRunning() bool {
	if len(p.entries) == 0 {
		return false
	}
	return !p.entries[len(p.entries)-1].Done
}

// Update handles key events.
func (p *ActivityPanel) Update(msg tea.Msg) {
	if keyMsg, ok := msg.(tea.KeyPressMsg); ok {
		if p.termMode {
			switch keyMsg.String() {
			case "esc", "q":
				p.termMode = false
			case "up", "k":
				p.termScroll++
			case "down", "j":
				if p.termScroll > 0 {
					p.termScroll--
				}
			}
			return
		}
		switch keyMsg.String() {
		case "up", "k":
			if p.cursor > 0 {
				p.cursor--
			}
		case "down", "j":
			if p.cursor < len(p.entries)-1 {
				p.cursor++
			}
		case "enter":
			if p.cursor >= 0 && p.cursor < len(p.entries) {
				p.termMode = true
				p.termScroll = 0
				// point to the selected entry
			}
		case "t":
			if len(p.entries) > 0 {
				p.termMode = true
				p.termScroll = 0
				p.cursor = len(p.entries) - 1
			}
		}
	}
}

// View renders the activity panel.
func (p *ActivityPanel) View() string {
	if len(p.entries) == 0 {
		return p.theme.Dimmed.Render("  No commands run yet. Press : or Ctrl+K to open the command palette.\n  Try: \"doctor\", \"status\", or \"scan skill --all\".")
	}

	if p.termMode {
		return p.viewTerminal()
	}
	return p.viewHistory()
}

func (p *ActivityPanel) viewTerminal() string {
	if p.cursor < 0 || p.cursor >= len(p.entries) {
		p.cursor = len(p.entries) - 1
	}
	entry := p.entries[p.cursor]

	var b strings.Builder
	// Minimal header: command name + status
	header := p.theme.CmdName.Render("$ " + entry.Command)
	if entry.Done {
		if entry.ExitCode == 0 {
			header += "  " + p.theme.ExitOK.Render(fmt.Sprintf("exit 0 (%s)", entry.Duration.Round(time.Millisecond)))
		} else {
			header += "  " + p.theme.ExitFail.Render(fmt.Sprintf("exit %d (%s)", entry.ExitCode, entry.Duration.Round(time.Millisecond)))
		}
	} else {
		header += "  " + p.theme.Spinner.Render("running...")
	}
	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", p.width))
	b.WriteString("\n")

	maxVisible := p.height - 4 // header + separator + hint + padding
	if maxVisible < 5 {
		maxVisible = 5
	}

	output := entry.Output
	totalLines := len(output)

	// Auto-scroll to bottom (scroll=0 means bottom), scroll>0 means scrolled up
	endIdx := totalLines - p.termScroll
	if endIdx < 0 {
		endIdx = 0
	}
	if endIdx > totalLines {
		endIdx = totalLines
	}
	startIdx := endIdx - maxVisible
	if startIdx < 0 {
		startIdx = 0
	}

	for i := startIdx; i < endIdx; i++ {
		b.WriteString(output[i])
		b.WriteString("\n")
	}

	// Pad remaining space
	rendered := endIdx - startIdx
	for rendered < maxVisible {
		b.WriteString("\n")
		rendered++
	}

	// Hint bar
	hint := p.theme.Dimmed.Render("  [Esc] history  [Up/Down] scroll  [Ctrl+C] cancel")
	if p.termScroll > 0 {
		hint += p.theme.Dimmed.Render(fmt.Sprintf("  (scrolled up %d lines)", p.termScroll))
	}
	b.WriteString(hint)

	return b.String()
}

func (p *ActivityPanel) viewHistory() string {
	var lines []string

	lines = append(lines, p.theme.Dimmed.Render("  Command History  [Enter] view output  [t] terminal mode"))
	lines = append(lines, "")

	for i, entry := range p.entries {
		header := p.formatEntryHeader(i, entry)
		lines = append(lines, header)

		if entry.Expanded {
			maxPreview := 5
			for j, outLine := range entry.Output {
				if j >= maxPreview {
					lines = append(lines, p.theme.Dimmed.Render(fmt.Sprintf("    ... %d more lines (Enter to view)", len(entry.Output)-maxPreview)))
					break
				}
				lines = append(lines, "    "+outLine)
			}
			if !entry.Done {
				lines = append(lines, "    "+p.theme.Spinner.Render("running..."))
			}
		}
		lines = append(lines, "")
	}

	maxVisible := p.height - 2
	if maxVisible < 5 {
		maxVisible = 5
	}

	totalLines := len(lines)
	if totalLines <= maxVisible {
		return strings.Join(lines, "\n")
	}

	// Scroll to keep cursor visible
	cursorLine := 0
	entryIdx := 0
	for i := range lines {
		if entryIdx == p.cursor {
			cursorLine = i
			break
		}
		if i > 0 && lines[i] == "" {
			entryIdx++
		}
	}

	start := cursorLine - maxVisible/2
	if start < 0 {
		start = 0
	}
	end := start + maxVisible
	if end > totalLines {
		end = totalLines
		start = end - maxVisible
		if start < 0 {
			start = 0
		}
	}

	return strings.Join(lines[start:end], "\n")
}

func (p *ActivityPanel) formatEntryHeader(idx int, entry activityEntry) string {
	ts := p.theme.Timestamp.Render(entry.StartTime.Format("15:04:05"))
	cmd := p.theme.CmdName.Render(entry.Command)

	status := ""
	if entry.Done {
		if entry.ExitCode == 0 {
			status = p.theme.ExitOK.Render(fmt.Sprintf("✓ exit 0 (%s)", entry.Duration.Round(time.Millisecond)))
		} else {
			status = p.theme.ExitFail.Render(fmt.Sprintf("✗ exit %d (%s)", entry.ExitCode, entry.Duration.Round(time.Millisecond)))
		}
	} else {
		status = p.theme.Spinner.Render("⠋ running")
	}

	expandIcon := "+"
	if entry.Expanded {
		expandIcon = "-"
	}
	outputCount := ""
	if len(entry.Output) > 0 {
		outputCount = p.theme.Dimmed.Render(fmt.Sprintf(" (%d lines)", len(entry.Output)))
	}

	sel := ""
	if idx == p.cursor {
		sel = "→ "
	} else {
		sel = "  "
	}

	return fmt.Sprintf("%s%s %s %s  %s %s%s", sel, expandIcon, ts, cmd, status, "", outputCount)
}

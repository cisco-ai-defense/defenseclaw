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

	"charm.land/lipgloss/v2"
)

// mcpSetField enumerates the form fields in tab order. Keeping this
// as a typed index (vs. freeform ints) makes the View() render branch
// exhaustive and keeps fieldLabels / fieldHints in lockstep if we add
// a field later — the compiler will catch any missing switch case.
type mcpSetField int

const (
	mcpFieldName mcpSetField = iota
	mcpFieldCommand
	mcpFieldArgs
	mcpFieldURL
	mcpFieldTransport
	mcpFieldEnv
	mcpFieldSkipScan
	mcpFieldCount // sentinel, not a real field
)

// mcpFieldLabels mirrors the --option names on `defenseclaw mcp set`
// (cli/defenseclaw/commands/cmd_mcp.py). Kept in declaration order
// so View() iterates linearly.
var mcpFieldLabels = [mcpFieldCount]string{
	"Name (required)",
	"Command (e.g. npx, uvx) — at least one of Command/URL",
	"Args (JSON array or comma-separated)",
	"URL (for SSE/HTTP transport)",
	"Transport (stdio, sse; blank = auto)",
	"Env vars (KEY=VAL, comma-separated)",
	"Skip scan? (y/n; default n — scan before adding)",
}

// MCPSetForm is a sequential text form that collects the fields the
// `defenseclaw mcp set` CLI verb needs, then on submit emits the
// argv that MCPsPanel routes through CommandExecutor. The form is
// deliberately flat (one scrollable list of fields, Tab to move,
// Enter on the last field to submit) — re-implementing a full
// multi-column editor in Bubble Tea for a 7-field configuration
// would be a maintenance liability with no UX payoff over just
// falling back to the CLI.
//
// Design notes:
//   - We never build the argv in View(); rendering must be pure.
//     BuildCommand() is called only from HandleKey on submit so the
//     `mcp set` arg list can never drift out of sync with the
//     displayed form state.
//   - Skip-scan is a tristate in intent ("" → false, "y/yes" → true,
//     anything else → false) but we normalise on submit so tests
//     don't have to care about case.
type MCPSetForm struct {
	active bool
	field  mcpSetField
	values [mcpFieldCount]string
	status string
	width  int
	height int
}

func NewMCPSetForm() MCPSetForm {
	return MCPSetForm{}
}

func (f *MCPSetForm) IsActive() bool { return f.active }

// Open makes the form visible. If `initialName` is non-empty the
// Name field is pre-populated (e.g. when editing an existing
// server from the MCP detail view). All other fields start blank —
// we deliberately do NOT pre-load existing server config because
// `mcp set` is an upsert, not a patch: any field we leave blank
// will be cleared on the target, which would surprise the operator.
func (f *MCPSetForm) Open(initialName string) {
	f.active = true
	f.field = mcpFieldName
	f.values = [mcpFieldCount]string{}
	f.values[mcpFieldName] = initialName
	f.status = ""
}

func (f *MCPSetForm) Close() {
	f.active = false
	f.field = mcpFieldName
	f.values = [mcpFieldCount]string{}
	f.status = ""
}

func (f *MCPSetForm) SetSize(w, h int) { f.width, f.height = w, h }

// Value exposes a field value for tests and for snapshot rendering
// outside the form. The field index is clamped so callers can't
// out-of-bounds via a stale enum value.
func (f *MCPSetForm) Value(field mcpSetField) string {
	if field < 0 || field >= mcpFieldCount {
		return ""
	}
	return f.values[field]
}

// CurrentField reports the focused field (1-indexed for logging
// parity with the View() row numbers).
func (f *MCPSetForm) CurrentField() mcpSetField { return f.field }

// SetValue is test-only; in the running TUI fields are mutated
// exclusively through HandleKey. Tests use this to pre-populate
// state and exercise BuildCommand without simulating every
// keystroke.
func (f *MCPSetForm) SetValue(field mcpSetField, v string) {
	if field < 0 || field >= mcpFieldCount {
		return
	}
	f.values[field] = v
}

// HandleKey processes a keypress. Returns (submit, binary, args,
// displayName) — when submit is true the caller should Close() the
// form (or the caller will, once the command returns) and dispatch
// the command through CommandExecutor.
//
// The key handling is intentionally minimal: Tab / Shift+Tab move
// between fields, Enter advances (or submits on the last field),
// Esc cancels, Backspace deletes the last rune of the focused
// field, and any single-character key is appended. We do not
// implement cursor motion or selection — for a 7-field form it's
// not worth the state or the keymap surface.
func (f *MCPSetForm) HandleKey(key string) (submit bool, binary string, args []string, displayName string) {
	if !f.active {
		return false, "", nil, ""
	}

	switch key {
	case "esc":
		f.Close()
		return false, "", nil, ""

	case "tab", "down":
		f.field = (f.field + 1) % mcpFieldCount
		f.status = ""
		return false, "", nil, ""

	case "shift+tab", "up":
		f.field = (f.field - 1 + mcpFieldCount) % mcpFieldCount
		f.status = ""
		return false, "", nil, ""

	case "enter":
		// Enter on any field but the last simply advances. This
		// mirrors the feel of a CLI wizard and keeps a single-key
		// path for operators who type linearly.
		if f.field < mcpFieldCount-1 {
			f.field++
			f.status = ""
			return false, "", nil, ""
		}
		argv, err := f.BuildCommand()
		if err != nil {
			f.status = err.Error()
			return false, "", nil, ""
		}
		name := strings.TrimSpace(f.values[mcpFieldName])
		f.status = fmt.Sprintf("setting %s…", name)
		return true, "defenseclaw", argv, "mcp set " + name

	case "backspace":
		v := f.values[f.field]
		if len(v) > 0 {
			// Trim one rune, not one byte — UTF-8 safety.
			r := []rune(v)
			f.values[f.field] = string(r[:len(r)-1])
		}
		return false, "", nil, ""

	case "ctrl+u":
		// Clear the focused field — handy for re-typing a value.
		f.values[f.field] = ""
		return false, "", nil, ""
	}

	// Any remaining single-character key is treated as input.
	// Bubble Tea reports printable keys as their own string (e.g.
	// "a"), so a length check is the safest filter — it naturally
	// excludes named keys like "f5" or "home" without a giant
	// explicit allow-list.
	if len([]rune(key)) == 1 {
		f.values[f.field] += key
	}
	return false, "", nil, ""
}

// BuildCommand renders the current form state into an argv slice
// suitable for `defenseclaw mcp set`. Returns an error (for the
// View() status line) if the form is missing required fields — we
// do not let the caller dispatch an obviously-broken command
// because the CLI will reject it anyway and the operator has a
// better error path by staying in the form.
func (f *MCPSetForm) BuildCommand() ([]string, error) {
	name := strings.TrimSpace(f.values[mcpFieldName])
	if name == "" {
		return nil, fmt.Errorf("Name is required")
	}
	cmd := strings.TrimSpace(f.values[mcpFieldCommand])
	url := strings.TrimSpace(f.values[mcpFieldURL])
	if cmd == "" && url == "" {
		return nil, fmt.Errorf("one of Command or URL is required")
	}

	argv := []string{"mcp", "set", name}
	if cmd != "" {
		argv = append(argv, "--command", cmd)
	}
	if a := strings.TrimSpace(f.values[mcpFieldArgs]); a != "" {
		argv = append(argv, "--args", a)
	}
	if url != "" {
		argv = append(argv, "--url", url)
	}
	if t := strings.TrimSpace(f.values[mcpFieldTransport]); t != "" {
		argv = append(argv, "--transport", t)
	}
	// Env is collected as "KEY=VAL, KEY=VAL" and split into repeated
	// --env flags. The CLI also accepts repeated --env so this is a
	// direct 1:1 mapping. Empty / whitespace-only pairs are
	// dropped to tolerate stray commas.
	if env := strings.TrimSpace(f.values[mcpFieldEnv]); env != "" {
		for _, pair := range strings.Split(env, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			if !strings.Contains(pair, "=") {
				return nil, fmt.Errorf("env %q is not KEY=VAL", pair)
			}
			argv = append(argv, "--env", pair)
		}
	}
	if skip := strings.TrimSpace(strings.ToLower(f.values[mcpFieldSkipScan])); skip == "y" || skip == "yes" || skip == "true" || skip == "1" {
		argv = append(argv, "--skip-scan")
	}
	return argv, nil
}

// View renders the form. The layout is a label/value pair per line
// with an arrow marker on the focused row plus a status + hint bar
// at the bottom. Very similar in shape to the Sink Editor — we
// deliberately match so the two forms feel part of the same system.
func (f *MCPSetForm) View() string {
	var b strings.Builder
	title := lipgloss.NewStyle().Bold(true).Render("Add/Update MCP Server")
	b.WriteString(title)
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Faint(true).Render(
		"Fill in the fields below. Tab/↓ next · Shift+Tab/↑ prev · Enter submit on last field · Esc cancel",
	))
	b.WriteString("\n\n")

	arrow := "› "
	blank := "  "
	label := lipgloss.NewStyle().Bold(true)
	focused := lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	dim := lipgloss.NewStyle().Faint(true)

	for i := mcpSetField(0); i < mcpFieldCount; i++ {
		prefix := blank
		if i == f.field {
			prefix = arrow
		}
		val := f.values[i]
		if val == "" {
			val = dim.Render("(empty)")
		} else if i == f.field {
			val = focused.Render(val + "▌")
		}
		fmt.Fprintf(&b, "%s%s\n    %s\n", prefix, label.Render(mcpFieldLabels[i]), val)
	}

	if f.status != "" {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render(f.status))
	}
	return b.String()
}

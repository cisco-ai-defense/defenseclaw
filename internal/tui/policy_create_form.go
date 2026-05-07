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

// policyCreateField enumerates the form fields in tab order.
type policyCreateField int

const (
	policyFieldName policyCreateField = iota
	policyFieldDescription
	policyFieldPreset
	policyFieldCritical
	policyFieldHigh
	policyFieldMedium
	policyFieldLow
	policyFieldCount
)

// policyCreateLabels mirrors the option names on
// `defenseclaw policy create` (cli/defenseclaw/commands/cmd_policy.py).
var policyCreateLabels = [policyFieldCount]string{
	"Name (required — alphanumeric, _ or -)",
	"Description (optional)",
	"From preset (default / strict / permissive / blank)",
	"Critical action (block / warn / allow / blank)",
	"High action (block / warn / allow / blank)",
	"Medium action (block / warn / allow / blank)",
	"Low action (block / warn / allow / blank)",
}

// validActions is the finite choice set the CLI accepts. Blank is
// also valid: it means "use the preset's default". We validate at
// BuildCommand time so the operator sees the error inline in the
// form rather than deep inside a click.BadParameter traceback.
var validActions = map[string]bool{
	"":      true,
	"block": true,
	"warn":  true,
	"allow": true,
}

var validPresets = map[string]bool{
	"":           true,
	"default":    true,
	"strict":     true,
	"permissive": true,
}

// PolicyCreateForm collects the fields `defenseclaw policy create`
// needs. Same sequential-wizard shape as MCPSetForm — see that file
// for the rationale. Kept separate rather than parameterised
// because the field list is short and the validation differs (the
// four severity fields all accept the same restricted choice set).
type PolicyCreateForm struct {
	active bool
	field  policyCreateField
	values [policyFieldCount]string
	status string
	width  int
	height int
}

func NewPolicyCreateForm() PolicyCreateForm {
	return PolicyCreateForm{}
}

func (f *PolicyCreateForm) IsActive() bool { return f.active }

func (f *PolicyCreateForm) Open() {
	f.active = true
	f.field = policyFieldName
	f.values = [policyFieldCount]string{}
	f.status = ""
}

func (f *PolicyCreateForm) Close() {
	f.active = false
	f.field = policyFieldName
	f.values = [policyFieldCount]string{}
	f.status = ""
}

func (f *PolicyCreateForm) SetSize(w, h int) { f.width, f.height = w, h }

// Value / SetValue are test helpers — the running TUI mutates
// state only through HandleKey.
func (f *PolicyCreateForm) Value(field policyCreateField) string {
	if field < 0 || field >= policyFieldCount {
		return ""
	}
	return f.values[field]
}

func (f *PolicyCreateForm) SetValue(field policyCreateField, v string) {
	if field < 0 || field >= policyFieldCount {
		return
	}
	f.values[field] = v
}

func (f *PolicyCreateForm) CurrentField() policyCreateField { return f.field }

// HandleKey processes a keypress. Returns (submit, binary, args,
// displayName). On submit the caller should dispatch via
// CommandExecutor; the form stays open on validation errors so the
// operator has a tight feedback loop (the same design choice as
// MCPSetForm).
func (f *PolicyCreateForm) HandleKey(key string) (submit bool, binary string, args []string, displayName string) {
	if !f.active {
		return false, "", nil, ""
	}

	switch key {
	case "esc":
		f.Close()
		return false, "", nil, ""

	case "tab", "down":
		f.field = (f.field + 1) % policyFieldCount
		f.status = ""
		return false, "", nil, ""

	case "shift+tab", "up":
		f.field = (f.field - 1 + policyFieldCount) % policyFieldCount
		f.status = ""
		return false, "", nil, ""

	case "enter":
		if f.field < policyFieldCount-1 {
			f.field++
			f.status = ""
			return false, "", nil, ""
		}
		argv, err := f.BuildCommand()
		if err != nil {
			f.status = err.Error()
			return false, "", nil, ""
		}
		name := strings.TrimSpace(f.values[policyFieldName])
		f.status = fmt.Sprintf("creating %s…", name)
		return true, "defenseclaw", argv, "policy create " + name

	case "backspace":
		v := f.values[f.field]
		if len(v) > 0 {
			r := []rune(v)
			f.values[f.field] = string(r[:len(r)-1])
		}
		return false, "", nil, ""

	case "ctrl+u":
		f.values[f.field] = ""
		return false, "", nil, ""
	}

	if len([]rune(key)) == 1 {
		f.values[f.field] += key
	}
	return false, "", nil, ""
}

// BuildCommand renders the argv for `defenseclaw policy create`.
// Validation is intentionally strict — the CLI will reject bad
// values anyway, but catching them here keeps the operator in the
// form with a useful status line instead of bouncing out to stderr.
func (f *PolicyCreateForm) BuildCommand() ([]string, error) {
	name := strings.TrimSpace(f.values[policyFieldName])
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	// Mirror the CLI's _sanitize_policy_name regex (alnum/_/-) at
	// the form boundary: the CLI uppercases this failure into a
	// SystemExit which the TUI would just swallow, so we surface
	// it earlier with a nicer message.
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-'
		if !ok {
			return nil, fmt.Errorf("name may only contain letters, digits, _ or -")
		}
	}

	preset := strings.ToLower(strings.TrimSpace(f.values[policyFieldPreset]))
	if !validPresets[preset] {
		return nil, fmt.Errorf("preset must be default, strict, permissive, or blank")
	}

	sevFields := [...]struct {
		idx   policyCreateField
		label string
		flag  string
	}{
		{policyFieldCritical, "critical", "--critical-action"},
		{policyFieldHigh, "high", "--high-action"},
		{policyFieldMedium, "medium", "--medium-action"},
		{policyFieldLow, "low", "--low-action"},
	}

	argv := []string{"policy", "create", name}

	if desc := strings.TrimSpace(f.values[policyFieldDescription]); desc != "" {
		argv = append(argv, "--description", desc)
	}
	if preset != "" {
		argv = append(argv, "--from-preset", preset)
	}

	for _, sf := range sevFields {
		v := strings.ToLower(strings.TrimSpace(f.values[sf.idx]))
		if !validActions[v] {
			return nil, fmt.Errorf("%s action must be block, warn, allow, or blank", sf.label)
		}
		if v != "" {
			argv = append(argv, sf.flag, v)
		}
	}
	return argv, nil
}

// View renders the form. Matches MCPSetForm styling so both feel
// like the same wizard subsystem.
func (f *PolicyCreateForm) View() string {
	var b strings.Builder
	title := lipgloss.NewStyle().Bold(true).Render("Create Policy")
	b.WriteString(title)
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Faint(true).Render(
		"Tab/↓ next · Shift+Tab/↑ prev · Enter submit on last field · Esc cancel",
	))
	b.WriteString("\n\n")

	arrow := "› "
	blank := "  "
	label := lipgloss.NewStyle().Bold(true)
	focused := lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	dim := lipgloss.NewStyle().Faint(true)

	for i := policyCreateField(0); i < policyFieldCount; i++ {
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
		fmt.Fprintf(&b, "%s%s\n    %s\n", prefix, label.Render(policyCreateLabels[i]), val)
	}

	if f.status != "" {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render(f.status))
	}
	return b.String()
}

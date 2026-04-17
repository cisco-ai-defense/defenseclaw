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

type DetailModal struct {
	visible bool
	title   string
	fields  []detailField
	width   int
	height  int
}

type detailField struct {
	label string
	value string
}

func NewDetailModal() DetailModal {
	return DetailModal{}
}

func (d *DetailModal) SetSize(w, h int) {
	d.width = w
	d.height = h
}

func (d *DetailModal) ShowAlert(sev, action, target, details, ts string) {
	d.title = fmt.Sprintf("Alert: %s", action)
	d.fields = []detailField{
		{"Severity", sev},
		{"Action", action},
		{"Target", target},
		{"Details", details},
		{"Timestamp", ts},
	}
	d.visible = true
}

func (d *DetailModal) ShowSkill(name, status, actions, reason, since string) {
	d.title = fmt.Sprintf("Skill: %s", name)
	d.fields = []detailField{
		{"Name", name},
		{"Status", status},
		{"Actions", actions},
		{"Reason", reason},
		{"Since", since},
	}
	d.visible = true
}

func (d *DetailModal) ShowMCP(url, status, actions, reason, since string) {
	d.title = fmt.Sprintf("MCP: %s", url)
	d.fields = []detailField{
		{"URL", url},
		{"Status", status},
		{"Actions", actions},
		{"Reason", reason},
		{"Since", since},
	}
	d.visible = true
}

func (d *DetailModal) Show(title string, pairs [][2]string) {
	d.title = title
	d.fields = nil
	for _, p := range pairs {
		if p[1] == "" {
			continue
		}
		d.fields = append(d.fields, detailField{label: p[0], value: p[1]})
	}
	d.visible = true
}

func (d *DetailModal) Hide() {
	d.visible = false
}

func (d *DetailModal) IsVisible() bool {
	return d.visible
}

func (d *DetailModal) View() string {
	if !d.visible {
		return ""
	}

	modalW := d.width - 10
	if modalW < 40 {
		modalW = 40
	}
	if modalW > 80 {
		modalW = 80
	}

	var b strings.Builder
	b.WriteString(ModalTitleStyle.Render(d.title))
	b.WriteString("\n\n")

	for _, f := range d.fields {
		val := f.value
		if f.label == "Severity" {
			val = SeverityStyle(val).Render(val)
		}
		if f.label == "Status" {
			val = StatusStyle(val).Render(strings.ToUpper(val))
		}
		b.WriteString(ModalLabelStyle.Render(f.label + ":"))
		b.WriteString(" ")
		b.WriteString(val)
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(HelpStyle.Render("press esc or enter to close"))

	content := b.String()
	modal := ModalStyle.Width(modalW).Render(content)

	padTop := (d.height - lipgloss.Height(modal)) / 2
	if padTop < 0 {
		padTop = 0
	}
	padLeft := (d.width - lipgloss.Width(modal)) / 2
	if padLeft < 0 {
		padLeft = 0
	}

	return lipgloss.NewStyle().
		PaddingTop(padTop).
		PaddingLeft(padLeft).
		Render(modal)
}

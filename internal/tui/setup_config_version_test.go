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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ------------------------------------------------------------------
// P2-#14 — config_version read-only surface.
// ------------------------------------------------------------------

func TestFmtConfigVersion(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		got := fmtConfigVersion(&config.Config{})
		if !strings.Contains(got, "unset") {
			t.Errorf("unset should be obvious, got %q", got)
		}
		if !strings.Contains(got, fmt.Sprintf("v%d", config.CurrentConfigVersion)) {
			t.Errorf("should mention binary schema, got %q", got)
		}
	})
	t.Run("current", func(t *testing.T) {
		c := &config.Config{ConfigVersion: config.CurrentConfigVersion}
		got := fmtConfigVersion(c)
		if got != fmt.Sprintf("%d", config.CurrentConfigVersion) {
			t.Errorf("in-sync version should render bare number, got %q", got)
		}
	})
	t.Run("behind", func(t *testing.T) {
		c := &config.Config{ConfigVersion: 1}
		got := fmtConfigVersion(c)
		if !strings.Contains(got, "migration") {
			t.Errorf("drift should surface migration hint, got %q", got)
		}
		if !strings.Contains(got, fmt.Sprintf("v%d", config.CurrentConfigVersion)) {
			t.Errorf("drift summary should mention binary schema version, got %q", got)
		}
	})
	t.Run("nil_config", func(t *testing.T) {
		got := fmtConfigVersion(nil)
		if got == "" || !strings.Contains(got, "unset") {
			t.Errorf("nil config should not panic and should say unset, got %q", got)
		}
	})
}

// TestSetupSections_ConfigVersionIsReadOnly guards that the row
// exists in General and stays Kind=header. Editing this field via
// the TUI would bypass migrateConfig (see P2-#14 rationale).
func TestSetupSections_ConfigVersionIsReadOnly(t *testing.T) {
	c := &config.Config{ConfigVersion: config.CurrentConfigVersion}
	p := NewSetupPanel(nil, c, nil)
	p.loadSections()
	var gen *configSection
	for i := range p.sections {
		if p.sections[i].Name == "General" {
			gen = &p.sections[i]
			break
		}
	}
	if gen == nil {
		t.Fatal("General section missing")
	}
	var found configField
	for _, f := range gen.Fields {
		if f.Key == "config_version" {
			found = f
			break
		}
	}
	if found.Key != "config_version" {
		t.Fatal("config_version row not in General section")
	}
	if found.Kind != "header" {
		t.Errorf("config_version must be Kind=header to stay read-only, got %q", found.Kind)
	}
}

// TestApplyConfigField_ConfigVersionNoOp reinforces that the
// applyConfigField switch never writes to c.ConfigVersion — only
// migrateConfig does.
func TestApplyConfigField_ConfigVersionNoOp(t *testing.T) {
	c := &config.Config{ConfigVersion: 2}
	applyConfigField(c, "config_version", "99")
	if c.ConfigVersion != 2 {
		t.Errorf("applyConfigField must not mutate config_version, got %d", c.ConfigVersion)
	}
}

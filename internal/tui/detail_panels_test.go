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
	"testing"
)

func TestSkillsPanelDetailToggle(t *testing.T) {
	p := NewSkillsPanel(nil)
	if p.IsDetailOpen() {
		t.Fatal("detail should start closed")
	}
	p.ToggleDetail()
	if !p.IsDetailOpen() {
		t.Fatal("detail should be open after toggle")
	}
	p.ToggleDetail()
	if p.IsDetailOpen() {
		t.Fatal("detail should be closed after second toggle")
	}
}

func TestSkillsPanelDetailHeightZeroWhenClosed(t *testing.T) {
	p := NewSkillsPanel(nil)
	p.height = 40
	if h := p.detailHeight(); h != 0 {
		t.Errorf("detailHeight should be 0 when closed, got %d", h)
	}
}

func TestSkillsPanelDetailHeightOpenBounds(t *testing.T) {
	p := NewSkillsPanel(nil)
	p.detailOpen = true

	p.height = 18
	h := p.detailHeight()
	if h < 6 || h > 14 {
		t.Errorf("detailHeight %d out of [6,14] range for height=18", h)
	}

	p.height = 100
	h = p.detailHeight()
	if h > 14 {
		t.Errorf("detailHeight %d exceeds max 14 for height=100", h)
	}
}

func TestSkillsPanelListHeightAccountsForDetail(t *testing.T) {
	p := NewSkillsPanel(nil)
	p.height = 40

	closedH := p.listHeight()
	p.detailOpen = true
	openH := p.listHeight()

	if openH >= closedH {
		t.Errorf("list height with detail open (%d) should be less than closed (%d)", openH, closedH)
	}
}

func TestSkillsPanelGetDetailInfoNilWithNoItems(t *testing.T) {
	p := NewSkillsPanel(nil)
	if info := p.GetDetailInfo(); info != nil {
		t.Fatal("expected nil with no items")
	}
}

func TestSkillsPanelDetailCacheInvalidation(t *testing.T) {
	p := NewSkillsPanel(nil)
	p.items = []skillItem{{Name: "s1"}, {Name: "s2"}}
	p.filtered = p.items
	p.detailOpen = true
	p.height = 40
	p.width = 80

	info1 := p.GetDetailInfo()
	p.detailCache = info1
	p.detailCacheIdx = 0

	if p.detailCache == nil {
		t.Fatal("cache should be set")
	}
	p.cursor = 1
	p.renderDetail()
	if p.detailCacheIdx != 1 {
		t.Error("cache should have been refreshed for new cursor")
	}
}

func TestMCPsPanelDetailToggle(t *testing.T) {
	p := NewMCPsPanel(nil)
	if p.IsDetailOpen() {
		t.Fatal("detail should start closed")
	}
	p.ToggleDetail()
	if !p.IsDetailOpen() {
		t.Fatal("detail should be open after toggle")
	}
	if p.detailCache != nil {
		t.Fatal("cache should be nil after toggle")
	}
}

func TestMCPsPanelDetailHeightZeroWhenClosed(t *testing.T) {
	p := NewMCPsPanel(nil)
	p.height = 40
	if h := p.detailHeight(); h != 0 {
		t.Errorf("detailHeight should be 0 when closed, got %d", h)
	}
}

func TestMCPsPanelGetDetailInfoNilWithNoItems(t *testing.T) {
	p := NewMCPsPanel(nil)
	if info := p.GetDetailInfo(); info != nil {
		t.Fatal("expected nil with no items")
	}
}

func TestPluginsPanelDetailToggle(t *testing.T) {
	theme := testTheme()
	p := NewPluginsPanel(theme, nil)
	if p.IsDetailOpen() {
		t.Fatal("detail should start closed")
	}
	p.ToggleDetail()
	if !p.IsDetailOpen() {
		t.Fatal("detail should be open after toggle")
	}
	if p.detailCache != nil {
		t.Fatal("cache should be nil after toggle")
	}
}

func TestPluginsPanelScrollOffsetUsesListHeight(t *testing.T) {
	theme := testTheme()
	p := NewPluginsPanel(theme, nil)
	p.height = 30
	p.width = 80
	p.detailOpen = true
	for i := 0; i < 50; i++ {
		p.items = append(p.items, pluginItem{Name: "p", ID: "p"})
	}
	p.cursor = 25
	off := p.ScrollOffset()
	if off == 0 {
		t.Error("scroll offset should be non-zero when cursor > listHeight")
	}
}

func TestPluginsPanelGetDetailInfoNilWithNoItems(t *testing.T) {
	theme := testTheme()
	p := NewPluginsPanel(theme, nil)
	if info := p.GetDetailInfo(); info != nil {
		t.Fatal("expected nil with no items")
	}
}

func TestAuditPanelDetailToggle(t *testing.T) {
	theme := testTheme()
	p := NewAuditPanel(theme, nil)
	if p.IsDetailOpen() {
		t.Fatal("detail should start closed")
	}
	p.ToggleDetail()
	if !p.IsDetailOpen() {
		t.Fatal("detail should be open after toggle")
	}
	if p.detailCache != nil {
		t.Fatal("cache should be nil after toggle")
	}
}

func TestAuditPanelListHeightFormula(t *testing.T) {
	theme := testTheme()
	p := NewAuditPanel(theme, nil)
	p.height = 40

	h := p.listHeight()
	// overhead = filterBarHeight(0) + 3 (summary+sep+header) + detailHeight(0) = 3
	expected := 40 - 3
	if h != expected {
		t.Errorf("listHeight()=%d, expected %d", h, expected)
	}
}

func TestAuditPanelScrollOffsetUsesListHeight(t *testing.T) {
	theme := testTheme()
	p := NewAuditPanel(theme, nil)
	p.height = 20
	p.cursor = 30
	off := p.ScrollOffset()
	if off == 0 {
		t.Error("scroll offset should be non-zero when cursor > listHeight")
	}
}

func TestAuditPanelGetDetailInfoNilWithNoItems(t *testing.T) {
	theme := testTheme()
	p := NewAuditPanel(theme, nil)
	if info := p.GetDetailInfo(); info != nil {
		t.Fatal("expected nil with no items")
	}
}

func TestInventoryPanelDetailToggle(t *testing.T) {
	theme := testTheme()
	p := NewInventoryPanel(theme, nil, nil)
	if p.IsDetailOpen() {
		t.Fatal("detail should start closed")
	}
	p.ToggleDetail()
	if !p.IsDetailOpen() {
		t.Fatal("detail should be open after toggle")
	}
	if p.detailCache != nil {
		t.Fatal("cache should be nil after toggle")
	}
}

func TestInventoryPanelGetDetailInfoNilWithNoData(t *testing.T) {
	theme := testTheme()
	p := NewInventoryPanel(theme, nil, nil)
	if info := p.GetDetailInfo(); info != nil {
		t.Fatal("expected nil with no inventory data")
	}
}

func TestInventoryPanelDetailCacheInvalidatesOnSubTab(t *testing.T) {
	theme := testTheme()
	p := NewInventoryPanel(theme, nil, nil)
	p.detailOpen = true
	p.detailCacheSub = 0
	p.detailCacheIdx = 0
	p.detailCache = &InventoryDetailInfo{Title: "stale"}
	p.activeSub = 1
	p.height = 40
	p.width = 80
	p.renderDetail()
	if p.detailCacheSub != 1 {
		t.Error("cache sub should have been updated to 1")
	}
}

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

func TestActivityPanelEmpty(t *testing.T) {
	panel := NewActivityPanel(testTheme(), "")

	if panel.Count() != 0 {
		t.Errorf("expected Count()=0, got %d", panel.Count())
	}
	if panel.IsRunning() {
		t.Error("expected IsRunning()=false for empty panel")
	}
	if panel.LastCommand() != "" {
		t.Errorf("expected empty LastCommand, got %q", panel.LastCommand())
	}

	panel.SetSize(80, 40)
	view := panel.View()
	if !strings.Contains(view, "No commands") {
		t.Errorf("empty panel view should show empty state, got: %s", view)
	}
}

func TestActivityPanelAddEntry(t *testing.T) {
	panel := NewActivityPanel(testTheme(), "")

	panel.AddEntry("scan skill my-agent")

	if panel.Count() != 1 {
		t.Errorf("expected Count()=1, got %d", panel.Count())
	}
	if !panel.IsRunning() {
		t.Error("entry should be running before FinishEntry")
	}
	if panel.LastCommand() != "scan skill my-agent" {
		t.Errorf("LastCommand() = %q, want %q", panel.LastCommand(), "scan skill my-agent")
	}
}

func TestActivityPanelAppendOutput(t *testing.T) {
	panel := NewActivityPanel(testTheme(), "")
	panel.SetSize(80, 40)

	panel.AppendOutput("stray line")

	panel.AddEntry("doctor")
	panel.AppendOutput("Checking gateway...")
	panel.AppendOutput("Gateway: running")
	panel.AppendOutput("All checks passed")

	view := panel.View()
	if !strings.Contains(view, "Checking gateway...") {
		t.Error("expected output lines in view")
	}
}

func TestActivityPanelFinishEntry(t *testing.T) {
	panel := NewActivityPanel(testTheme(), "")

	panel.AddEntry("status")
	panel.AppendOutput("All systems go")
	panel.FinishEntry(0, 150*time.Millisecond)

	if panel.IsRunning() {
		t.Error("expected IsRunning()=false after FinishEntry")
	}
}

func TestActivityPanelMultipleEntries(t *testing.T) {
	panel := NewActivityPanel(testTheme(), "")

	panel.AddEntry("doctor")
	panel.FinishEntry(0, 100*time.Millisecond)

	panel.AddEntry("scan skill --all")
	panel.FinishEntry(1, 2*time.Second)

	panel.AddEntry("status")
	panel.FinishEntry(0, 50*time.Millisecond)

	if panel.Count() != 3 {
		t.Errorf("expected Count()=3, got %d", panel.Count())
	}
	if panel.LastCommand() != "status" {
		t.Errorf("LastCommand() = %q, want %q", panel.LastCommand(), "status")
	}
	if panel.IsRunning() {
		t.Error("last entry is finished, IsRunning should be false")
	}
}

func TestActivityPanelFinishEmptyNoOp(t *testing.T) {
	panel := NewActivityPanel(testTheme(), "")
	panel.FinishEntry(0, 0)
	panel.AppendOutput("nothing")

	if panel.Count() != 0 {
		t.Error("operations on empty panel should be no-ops")
	}
}

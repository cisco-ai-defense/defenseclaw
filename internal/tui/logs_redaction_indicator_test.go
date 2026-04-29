// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// TestLogsPanel_RedactionBadge_VisibleWhenDisabled pins the
// behavior that operators must see a loud, foreground "RAW"
// indicator in the Logs panel header whenever the redaction
// kill-switch is on. This is the only easy place an operator can
// see the state at a glance without rummaging in config.yaml or
// `defenseclaw setup redaction status`. A regression here makes
// the disabled state silent — the exact failure mode that lets
// a multi-tenant install accidentally inherit a redaction-off
// config from a snapshot.
func TestLogsPanel_RedactionBadge_VisibleWhenDisabled(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	panel := &LogsPanel{
		theme:  DefaultTheme(),
		source: logSourceGateway,
		lines:  [logSourceCount][]string{{"line one"}, {}, {}, {}},
		width:  120,
		height: 24,
	}

	// Default state: redaction on, badge hidden.
	view := panel.View()
	if strings.Contains(view, "RAW") {
		t.Fatalf("RAW badge must be hidden by default, got view containing RAW:\n%s", view)
	}

	// Flip the kill-switch on; badge must now appear in the header.
	redaction.SetDisableAll(true)
	view = panel.View()
	if !strings.Contains(view, "RAW") {
		t.Fatalf("RAW badge missing when DisableAll=true, got:\n%s", view)
	}
	if !strings.Contains(view, "defenseclaw setup redaction on") {
		t.Fatalf("RAW badge must include the re-enable hint, got:\n%s", view)
	}

	// Toggle off and confirm the badge disappears again. (Catches
	// a stale-cache regression where the badge state would be
	// memoized across renders.)
	redaction.SetDisableAll(false)
	view = panel.View()
	if strings.Contains(view, "RAW") {
		t.Fatalf("RAW badge must disappear after DisableAll=false, got:\n%s", view)
	}
}

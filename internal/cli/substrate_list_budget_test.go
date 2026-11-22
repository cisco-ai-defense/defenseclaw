// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// TestSubstrateListBudgetColumn: the list table has a BUDGET column that
// shows the share used or "over", and a dash when no budget counts the agent.
func TestSubstrateListBudgetColumn(t *testing.T) {
	var buf bytes.Buffer
	rows := []api.Actor{{Atespace: "eng-web", Name: "a", Budget: "80 %"}, {Atespace: "eng-web", Name: "b", Budget: "over"}, {Atespace: "eng-web", Name: "c"}}
	printSubstrateActors(&buf, rows, false, time.Now())
	out := buf.String()
	if !strings.Contains(out, "BUDGET") || !strings.Contains(out, "80 %") || !strings.Contains(out, "over") {
		t.Fatalf("list output has no BUDGET column:\n%s", out)
	}
}

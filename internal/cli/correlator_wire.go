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

package cli

import (
	"fmt"
	"io"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// auditReaderAdapter bridges *audit.Store's native CorrelationFindingRow
// to guardrail's SessionFindingRow. Lives in the wiring layer so
// neither package has to import the other's types directly.
type auditReaderAdapter struct {
	store *audit.Store
}

func (a *auditReaderAdapter) ListRecentFindingsInSession(
	sessionID, agentInstanceID string, limit int,
) ([]guardrail.SessionFindingRow, error) {
	rows, err := a.store.ListRecentFindingsInSession(sessionID, agentInstanceID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]guardrail.SessionFindingRow, len(rows))
	for i, r := range rows {
		out[i] = guardrail.SessionFindingRow{
			ID:                  r.ID,
			RuleID:              r.RuleID,
			Category:            r.Category,
			Severity:            r.Severity,
			DataAxis:            r.DataAxis,
			ToolCapabilityClass: r.ToolCapabilityClass,
			ContentFingerprint:  r.ContentFingerprint,
			ExternalEndpoint:    r.ExternalEndpoint,
			TurnID:              r.TurnID,
			Timestamp:           r.Timestamp,
		}
	}
	return out, nil
}

var _ guardrail.SessionFindingReader = (*auditReaderAdapter)(nil)

// installCorrelator registers a SessionCorrelator with the scanner
// package so EmitScanResult will invoke it after every persisted
// scan. It also installs the finding-enricher so every persisted
// finding gets its data_axis labels populated automatically from
// the rule_id / tags — otherwise the correlator sees blank axes and
// never matches.
//
// Non-fatal: a pattern-load error logs to stderrWriter and leaves
// the correlator disabled (the rest of the guardrail stack still
// works).
func installCorrelator(store *audit.Store, stderrWriter io.Writer) {
	scanner.SetFindingEnricher(func(f *scanner.Finding) []string {
		axes := guardrail.AxesForRuleID(f.RuleID)
		if len(axes) == 0 {
			return nil
		}
		return guardrail.AxesToStrings(axes)
	})

	if store == nil {
		return
	}
	set, err := guardrail.DefaultCorrelationPatterns()
	if err != nil {
		if stderrWriter != nil {
			fmt.Fprintf(stderrWriter, "correlator: failed to load patterns: %v\n", err)
		}
		return
	}
	reader := &auditReaderAdapter{store: store}
	corr := guardrail.NewSessionCorrelator(reader, set.Patterns)
	scanner.SetCorrelator(corr)
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

var (
	auditFindingsScanner         string
	auditFindingsTarget          string
	auditFindingsSince           string
	auditFindingsNewOnly         bool
	auditFindingsIncludeResolved bool
	auditFindingsLimit           int
)

type auditFindingsReport struct {
	SchemaVersion    int                     `json:"schema_version"`
	CurrentOnly      bool                    `json:"current_only"`
	Since            string                  `json:"since,omitempty"`
	NewOnly          bool                    `json:"new_only"`
	Count            int64                   `json:"count"`
	Returned         int                     `json:"returned"`
	DistinctFindings []audit.FindingStateRow `json:"findings"`
}

var auditFindingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Report distinct current scan findings",
	Long: `Report the deduplicated scan-finding lifecycle as JSON. Active current
state is the default. --since selects findings observed at/after an RFC3339
timestamp and, with --include-resolved, resolutions in that interval. Combine
--new-only with --since to select only fingerprints first observed then.`,
	RunE: runAuditFindings,
}

func init() {
	auditFindingsCmd.Flags().StringVar(&auditFindingsScanner, "scanner", "", "Only findings from this scanner")
	auditFindingsCmd.Flags().StringVar(&auditFindingsTarget, "target", "", "Only findings for this exact normalized scan target")
	auditFindingsCmd.Flags().StringVar(&auditFindingsSince, "since", "", "Only lifecycle changes at/after this RFC3339 timestamp")
	auditFindingsCmd.Flags().BoolVar(&auditFindingsNewOnly, "new-only", false, "Only fingerprints first observed since --since")
	auditFindingsCmd.Flags().BoolVar(&auditFindingsIncludeResolved, "include-resolved", false, "Include resolved findings (active current state is the default)")
	auditFindingsCmd.Flags().IntVar(&auditFindingsLimit, "limit", 100, "Maximum distinct findings to return (1-10000)")
	auditCmd.AddCommand(auditFindingsCmd)
}

func runAuditFindings(cmd *cobra.Command, _ []string) error {
	if auditStore == nil {
		return fmt.Errorf("audit findings: audit store not loaded")
	}
	if auditFindingsLimit < 1 || auditFindingsLimit > 10_000 {
		return fmt.Errorf("audit findings: --limit must be between 1 and 10000")
	}
	since, err := parseAuditFindingsSince(auditFindingsSince)
	if err != nil {
		return err
	}
	if auditFindingsNewOnly && since == nil {
		return fmt.Errorf("audit findings: --new-only requires --since")
	}
	if auditFindingsTarget != "" && scanner.NormalizeFindingStateTarget(auditFindingsTarget) == "" {
		return fmt.Errorf("audit findings: --target must identify a usable scan target")
	}
	query := audit.FindingStateQuery{
		Scanner:         auditFindingsScanner,
		Target:          auditFindingsTarget,
		IncludeResolved: auditFindingsIncludeResolved,
		Since:           since,
		NewOnly:         auditFindingsNewOnly,
		Limit:           auditFindingsLimit,
	}
	queryContext := cmd.Context()
	if queryContext == nil {
		queryContext = context.Background()
	}
	rows, count, err := auditStore.QueryFindingStatesWithCount(queryContext, query)
	if err != nil {
		return fmt.Errorf("audit findings: %w", err)
	}
	report := auditFindingsReport{
		SchemaVersion:    1,
		CurrentOnly:      !auditFindingsIncludeResolved,
		NewOnly:          auditFindingsNewOnly,
		Count:            count,
		Returned:         len(rows),
		DistinctFindings: rows,
	}
	if since != nil {
		report.Since = since.UTC().Format(time.RFC3339Nano)
	}
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("audit findings: encode report: %w", err)
	}
	return nil
}

func parseAuditFindingsSince(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, fmt.Errorf("audit findings: invalid --since %q (expected RFC3339): %w", value, err)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

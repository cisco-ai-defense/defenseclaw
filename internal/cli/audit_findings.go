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
state is the default. --since selects findings observed at/after a time
(RFC3339, or a duration ago such as 30m or 2h) and, with --include-resolved,
resolutions in that interval. Combine --new-only with --since to select only
fingerprints first observed then.

This covers asset scans (skill, MCP, plugin, code, AIBOM and inventory
scans). Guardrail decisions on prompts and tool calls (hook rules, the LLM
guardrail) are not tracked here; see 'defenseclaw alerts' or
'defenseclaw-gateway audit export' for those.`,
	// A bad flag value fails before the audit store opens, so it never
	// creates or migrates audit.db (GAP-2126), like audit export.
	PersistentPreRunE: auditFindingsPersistentPreRunE,
	RunE:              runAuditFindings,
}

func init() {
	auditFindingsCmd.Flags().StringVar(&auditFindingsScanner, "scanner", "", "Only findings from this scanner")
	auditFindingsCmd.Flags().StringVar(&auditFindingsTarget, "target", "", "Only findings for this exact normalized scan target")
	auditFindingsCmd.Flags().StringVar(&auditFindingsSince, "since", "", "Only lifecycle changes at or after this time: RFC3339 (2026-09-27T18:30:00Z) or a duration ago (30m, 2h)")
	auditFindingsCmd.Flags().BoolVar(&auditFindingsNewOnly, "new-only", false, "Only fingerprints first observed since --since")
	auditFindingsCmd.Flags().BoolVar(&auditFindingsIncludeResolved, "include-resolved", false, "Include resolved findings (active current state is the default)")
	auditFindingsCmd.Flags().IntVar(&auditFindingsLimit, "limit", 100, "Maximum distinct findings to return (1-10000)")
	auditCmd.AddCommand(auditFindingsCmd)
}

// auditFindingsPersistentPreRunE checks the flag values, then opens the
// audit store the same way as the other audit commands.
func auditFindingsPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if _, err := checkAuditFindingsFlags(cmd); err != nil {
		return err
	}
	return auditPersistentPreRunE(cmd, args)
}

// checkAuditFindingsFlags validates --limit, --since, --new-only and
// --target as usage errors (exit 2) and returns the parsed --since.
func checkAuditFindingsFlags(cmd *cobra.Command) (*time.Time, error) {
	if auditFindingsLimit < 1 || auditFindingsLimit > 10_000 {
		return nil, auditUsageError(cmd, fmt.Errorf("audit findings: --limit must be between 1 and 10000"))
	}
	since, err := parseAuditFindingsSince(auditFindingsSince)
	if err != nil {
		return nil, auditUsageError(cmd, err)
	}
	if auditFindingsNewOnly && since == nil {
		return nil, auditUsageError(cmd, fmt.Errorf("audit findings: --new-only requires --since"))
	}
	if auditFindingsTarget != "" && scanner.NormalizeFindingStateTarget(auditFindingsTarget) == "" {
		return nil, auditUsageError(cmd, fmt.Errorf("audit findings: --target must identify a usable scan target"))
	}
	return since, nil
}

func runAuditFindings(cmd *cobra.Command, _ []string) error {
	since, err := checkAuditFindingsFlags(cmd)
	if err != nil {
		return err
	}
	if auditStore == nil {
		return fmt.Errorf("audit findings: audit store not loaded")
	}
	if audit.FindingLifecycleExcludesScanner(auditFindingsScanner) {
		// GAP-1301: a guardrail scanner always reports count 0 here; say why
		// on stderr so the JSON on stdout stays machine-readable.
		fmt.Fprintf(cmd.ErrOrStderr(), "note: --scanner %s records guardrail decisions, which audit findings does not track; "+
			"see 'defenseclaw alerts' or 'defenseclaw-gateway audit export' for them.\n", strings.TrimSpace(auditFindingsScanner))
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
	// Same forms as audit export --since (GAP-1232).
	parsed, err := parseAuditExportTime("--since", value, time.Now())
	if err != nil {
		return nil, fmt.Errorf("audit findings: invalid --since %q (use an RFC3339 time such as 2026-09-27T18:30:00Z or a duration such as 30m)", value)
	}
	return parsed, nil
}

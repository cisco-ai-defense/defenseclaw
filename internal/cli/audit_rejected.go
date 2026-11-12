// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

var (
	auditRejectedSince string
	auditRejectedLimit int
)

var auditRejectedCmd = &cobra.Command{
	Use:   "rejected",
	Short: "List the records the v8 schema gate refused (JSONL)",
	Long: `List the records the v8 schema gate refused, newest first, one JSON object
per line: when, the signal, family and event name, the reason code, the field
that failed, the validation error and a copy of the record's fields redacted
with the sensitive profile.

Records are kept only while observability.local.keep_rejected_records is
true (off by default; turn it on with 'defenseclaw config set
observability.local.keep_rejected_records true'). retention_days and
max_store_mb prune them with the other local history.

The audit database is opened read-only. On a standalone managed host run it
as root or the gateway service account (Linux, macOS), or from an elevated
Administrator prompt (Windows): it then reads the managed deployment's
store.`,
	// The store is never on there, so a Secure Client computer keeps main's
	// command set (issue #1092).
	Annotations: map[string]string{secureClientAbsentAnnotation: "true"},
	// A bad flag value fails before the audit store opens (GAP-2126).
	PersistentPreRunE: auditRejectedPersistentPreRunE,
	RunE:              runAuditRejected,
}

func init() {
	auditRejectedCmd.Flags().StringVar(&auditRejectedSince, "since", "", "Only records stored at or after this time: RFC3339 (2026-09-27T18:30:00Z) or a duration ago (30m, 2h)")
	auditRejectedCmd.Flags().IntVar(&auditRejectedLimit, "limit", 100, "Maximum records to list, newest first (1-10000)")
	auditCmd.AddCommand(auditRejectedCmd)
}

// auditRejectedPersistentPreRunE checks the flags, then resolves the audit
// database the way audit export does: a standard account on a managed
// Windows computer is refused (elevation_required, exit 5), an administrator
// gets the managed deployment's environment, a unix standalone administrator
// gets the managed config and the trust check of the service-owned store.
// Only the configuration is loaded; the store is opened read-only in RunE, so
// this command never migrates or writes audit.db.
func auditRejectedPersistentPreRunE(cmd *cobra.Command, _ []string) error {
	if _, err := checkAuditRejectedFlags(cmd, time.Now()); err != nil {
		return err
	}
	if err := pinManagedAdministratorEnvironment("audit rejected", func() string {
		return windowsManagedStandardUserViewAnswer("the rejected-record store", "audit", "rejected")
	}); err != nil {
		return err
	}
	applyManagedStandaloneAdminEnv(cmd.ErrOrStderr())
	if err := loadGatewayCommandConfigFor(cmd); err != nil {
		return err
	}
	return checkManagedAuditExportDatabase()
}

func checkAuditRejectedFlags(cmd *cobra.Command, now time.Time) (*time.Time, error) {
	if auditRejectedLimit < 1 || auditRejectedLimit > audit.RejectedRecordsMaxListLimit {
		return nil, auditUsageError(cmd, fmt.Errorf("audit rejected: --limit must be between 1 and %d", audit.RejectedRecordsMaxListLimit))
	}
	value := strings.TrimSpace(auditRejectedSince)
	if value == "" {
		return nil, nil
	}
	since, err := parseAuditExportTime("--since", value, now)
	if err != nil {
		return nil, auditUsageError(cmd, fmt.Errorf("audit rejected: invalid --since %q (use an RFC3339 time such as 2026-09-27T18:30:00Z or a duration such as 30m)", value))
	}
	return since, nil
}

func runAuditRejected(cmd *cobra.Command, _ []string) (err error) {
	since, err := checkAuditRejectedFlags(cmd, time.Now())
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("audit rejected: config not loaded")
	}
	stderr := auditExportStderr(cmd)
	if note := auditRejectedOffNote(); note != "" {
		fmt.Fprintln(stderr, note)
	}
	path := cfg.AuditDB
	if _, statErr := os.Stat(path); errors.Is(statErr, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "note: no audit database at %s yet; no refused records are stored\n", path)
		return nil
	}
	store, err := audit.OpenReadOnlyStore(path)
	if err != nil {
		return fmt.Errorf("audit rejected: %w", err)
	}
	defer store.Close() //nolint:errcheck -- read-only handle.
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := store.ListRejectedRecords(ctx, audit.RejectedRecordQuery{Since: since, Limit: auditRejectedLimit})
	if errors.Is(err, audit.ErrRejectedRecordsUnavailable) {
		// The gateway adds the table when it next starts on this release.
		fmt.Fprintf(stderr, "note: %s has no rejected-record table yet; start the gateway of this release once\n", path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("audit rejected: %w", err)
	}
	// A reader that stops early (| head -1) is not a failure (GAP-1694).
	defer func() { err = quietClosedOutputPipe(err) }()
	return writeAuditRejectedLines(cmd.OutOrStdout(), rows)
}

func writeAuditRejectedLines(out io.Writer, rows []audit.RejectedRecordRow) error {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			return fmt.Errorf("audit rejected: write: %w", err)
		}
	}
	return nil
}

// auditRejectedOffNote says, on stderr, that the store is off in the
// effective configuration, so an empty listing is not mistaken for "nothing
// was refused". "" when it is on or the plan cannot be read.
func auditRejectedOffNote() string {
	keep, ok := auditRejectedKeepEnabled()
	if !ok || keep {
		return ""
	}
	return "note: observability.local.keep_rejected_records is off, so refused records are counted but not kept; " +
		"turn it on with 'defenseclaw config set observability.local.keep_rejected_records true'"
}

// auditRejectedKeepEnabled reads the effective key from the loaded config. A
// seam for tests.
var auditRejectedKeepEnabled = func() (bool, bool) {
	if cfg == nil {
		return false, false
	}
	loaded, err := loadConfigV8Source(config.ConfigPath(), config.DefaultDataPath(), "", true)
	if err != nil || loaded == nil || loaded.compiled == nil || loaded.compiled.Plan == nil {
		return false, false
	}
	return loaded.compiled.Plan.Snapshot().Local.KeepRejectedRecords, true
}

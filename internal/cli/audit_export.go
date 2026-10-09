// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"container/heap"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // SQLite driver for export (same as audit.Store)

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

var (
	auditExportOut             string
	auditExportIncludeActivity bool
	auditExportLimit           int
	auditExportConnector       string
	auditExportSince           string
	auditExportUntil           string
	auditExportNewest          bool
	auditExportForce           bool
	auditExportDB              string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect and export the local audit database",
	Long: `Inspect and export the local audit database.

On a standalone managed host an administrator (or the gateway service
account) reads the managed deployment's audit store without extra
environment variables. That store belongs to the gateway service, so it is
opened read-only: the review never migrates it or becomes a second writer.`,
	PersistentPreRunE: auditPersistentPreRunE,
}

// auditPersistentPreRunE opens the audit store for the audit commands other
// than export, which has its own config-only initializer. A per-user install
// keeps the root initializer. On a unix standalone host an administrator or
// the service account gets the managed config and the service-owned store,
// validated as a managed runtime file (owned by root or the service account,
// no group/other writers) and opened read-only; the writer path's owner
// check would refuse the service-owned file, and its migrations must never
// run beside the managed gateway.
func auditPersistentPreRunE(cmd *cobra.Command, args []string) error {
	applyManagedStandaloneAdminEnv(cmd.ErrOrStderr())
	if _, admin := managedStandaloneAdminCaller(nil); !admin {
		return rootPersistentPreRunE(cmd, args)
	}
	if err := loadGatewayCommandConfigOnly(); err != nil {
		return err
	}
	if !cfg.StandaloneEnterprise() {
		cfg = nil
		return rootPersistentPreRunE(cmd, args)
	}
	store, err := openManagedAuditStoreReadOnly(cfg.AuditDB)
	if err != nil {
		return err
	}
	auditStore = store
	return nil
}

// managedAuditStoreTrustCheck validates the managed audit database as a
// service runtime file. A seam for tests.
var managedAuditStoreTrustCheck = func(path string) error {
	return managed.ValidateTrustedServiceRuntimeFilePath(path, "managed audit database", "")
}

// openManagedAuditStoreReadOnly opens the managed gateway's audit store
// for review after its ownership check.
func openManagedAuditStoreReadOnly(path string) (*audit.Store, error) {
	if err := managedAuditStoreTrustCheck(path); err != nil {
		return nil, fmt.Errorf("failed to open the managed audit store: %w", err)
	}
	store, err := audit.OpenReadOnlyStore(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open the managed audit store: %w", err)
	}
	return store, nil
}

const auditExportSecureClientLong = `Write one JSON object per line. Each audit row is validated against
schemas/audit-event.json before it is written. Configuration changes and
operator actions are audit rows too (action config-update and others).
--include-activity appends the rows of the activity_events table, which
holds only history from releases before 1.0, validated against
activity-event.json.

Rows are written oldest first. --limit N keeps the first (oldest) N
matching rows; add --newest to keep the N most recent rows instead (they
are still written oldest first). --since and --until select a time window
(--since inclusive, --until exclusive) as an RFC3339 time such as
2026-09-27T18:30:00Z or a duration ago such as 30m or 2h. Activity rows
follow the same window.

The export reads the audit database read-only beside the running gateway.
On a Windows host with a standalone managed deployment, run it from an
elevated Administrator prompt (or as LocalSystem): it then reads the managed
deployment's configuration and audit log.

Examples:
  defenseclaw-gateway audit export --since 30m
  defenseclaw-gateway audit export --connector claudecode --limit 50 --newest`

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit_events as JSONL (v7 schema)",
	Long: `Write one JSON object per line. Each audit row is validated against
schemas/audit-event.json before it is written. Configuration changes and
operator actions are audit rows too (action config-update and others).
--include-activity appends the rows of the activity_events table, which
holds only history from releases before 1.0, validated against
activity-event.json.

Rows are written oldest first. --limit N keeps the first (oldest) N
matching rows; add --newest to keep the N most recent rows instead (they
are still written oldest first). --since and --until select a time window
(--since inclusive, --until exclusive) as an RFC3339 time such as
2026-09-27T18:30:00Z or a duration ago such as 30m or 2h. Activity rows
follow the same window.

The export reads the audit database read-only beside the running gateway.
On a Windows host with a standalone managed deployment, run it from an
elevated Administrator prompt (or as LocalSystem): it then reads the managed
deployment's configuration and audit log.

--db reads another audit database instead of the configured one, with no
configuration needed. After defenseclaw rollback, the install you left keeps
its audit log in ~/.defenseclaw/previous/data/audit.db (previous\data\audit.db
on Windows), and this reads it; each install shows only its own window.

Examples:
  defenseclaw-gateway audit export --since 30m
  defenseclaw-gateway audit export --connector claudecode --limit 50 --newest
  defenseclaw-gateway audit export --db ~/.defenseclaw/previous/data/audit.db`,
	// Export only reads audit.db. It loads the configuration without opening
	// the audit store: the store opens read-write and, on a managed host,
	// only as the gateway service, so an administrator could never export.
	PersistentPreRunE: auditExportPersistentPreRunE,
	RunE:              runAuditExport,
	Annotations:       map[string]string{secureClientLongAnnotation: auditExportSecureClientLong},
}

// auditExportPersistentPreRunE replaces the audit initializer for export:
// resolve a managed deployment for an administrator, then load the
// configuration only. On a Windows standalone host an elevated
// administrator or LocalSystem gets the managed layout and service pins; on
// a unix standalone host an administrator or the service account gets the
// managed config, and the service-owned database must pass the same
// managed runtime file check the other audit commands apply before the
// export reads it.
func auditExportPersistentPreRunE(cmd *cobra.Command, _ []string) error {
	if auditExportDB != "" {
		// A database named by path needs no configuration: the other
		// install after a rollback may have written one this build does not
		// load (GAP-0126). A managed deployment's administrator reads the
		// managed store through the checks below, never a path of their
		// choosing.
		if auditExportManagedHost() {
			if !auditExportCallerIsAdministrator() {
				return withExitCode(&managedViewRefusal{
					code:    "elevation_required",
					message: windowsManagedStandardUserViewAnswer("the audit log", "audit export -o <file>"),
				}, enterprisestatus.WindowsExitAccessDenied)
			}
			return errors.New("audit export --db is not available on a managed deployment; run it without --db to export the managed audit log")
		}
		_, _, deploymentErr := managedStandaloneAdminDeployment()
		if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) || deploymentErr == nil {
			return errors.New("audit export --db is not available on a managed deployment; run it without --db to export the managed audit log")
		}
		return nil
	}
	if err := prepareManagedAuditExportEnvironment(); err != nil {
		return err
	}
	var warn io.Writer
	if cmd != nil {
		warn = cmd.ErrOrStderr()
	}
	applyManagedStandaloneAdminEnv(warn)
	if err := loadGatewayCommandConfigFor(cmd); err != nil {
		return err
	}
	return checkManagedAuditExportDatabase()
}

// checkManagedAuditExportDatabase validates the managed audit database for
// a unix standalone administrator's export. Every other caller reads its
// own database, which the read-only handle leaves untouched.
func checkManagedAuditExportDatabase() error {
	if _, admin := managedStandaloneAdminCaller(nil); !admin || !cfg.StandaloneEnterprise() {
		return nil
	}
	if err := managedAuditStoreTrustCheck(cfg.AuditDB); err != nil {
		return fmt.Errorf("failed to open the managed audit store: %w", err)
	}
	return nil
}

// registerAuditExportDBFlag keeps the pre-1.0 Secure Client command surface.
func registerAuditExportDBFlag(cmd *cobra.Command, secureClient bool) {
	if secureClient {
		return
	}
	cmd.Flags().StringVar(&auditExportDB, "db", "", "Read this audit database instead of the configured one, for example the install a rollback left in ~/.defenseclaw/previous/data/audit.db")
}

func init() {
	auditExportCmd.Flags().StringVarP(&auditExportOut, "output", "o", "-", "Output file path, or '-' for stdout")
	auditExportCmd.Flags().BoolVar(&auditExportIncludeActivity, "include-activity", false, "Append pre-1.0 activity_events rows (activity-event.json) after audit lines; configuration changes are audit rows already")
	auditExportCmd.Flags().IntVar(&auditExportLimit, "limit", 0, "Max audit rows (0 = unlimited); the oldest matching rows unless --newest")
	auditExportCmd.Flags().StringVar(&auditExportSince, "since", "", "Only rows at or after this time: RFC3339 (2026-09-27T18:30:00Z) or a duration ago (30m, 2h)")
	auditExportCmd.Flags().StringVar(&auditExportUntil, "until", "", "Only rows before this time: RFC3339 or a duration ago")
	auditExportCmd.Flags().BoolVar(&auditExportNewest, "newest", false, "With --limit, keep the newest matching rows instead of the oldest (still written oldest first)")
	auditExportCmd.Flags().BoolVar(&auditExportForce, "force", false, "Overwrite the --output file if it already exists")
	auditExportCmd.Flags().StringVar(&auditExportConnector, "connector", "", "Only export rows attributed to this connector (matches the authoritative connector column, then structured.connector, then the details connector= field). Activity rows are omitted when set.")
	registerAuditExportDBFlag(auditExportCmd, secureClientHost())

	auditCmd.AddCommand(auditExportCmd)
	rootCmd.AddCommand(auditCmd)
}

// isKnownAuditAction reports whether s is a registered action recognized by
// the v7 schema. It delegates to internal/audit (the canonical registry) so
// this exporter never drifts from the source of truth again — every action
// added to internal/audit/actions.go is automatically accepted here without a
// second list to maintain.
//
// Historically a hand-maintained `auditActionEnum` map lived here and silently
// fell behind whenever a new action (e.g. connector-hook,
// connector-hook-synthetic, codex.notify.*) was registered. That caused
// `defenseclaw audit export` to remap perfectly valid hook rows to
// `action: "action"` with the original value tucked into
// `legacy_action=…` inside the details blob, breaking SIEM dashboards that
// keyed on the actual action. Routing through audit.IsKnownAction +
// audit.IsKnownActionPrefix permanently closes that drift gap.
func isKnownAuditAction(s string) bool {
	if audit.IsKnownAction(s) {
		return true
	}
	if audit.IsKnownActionPrefix(s) {
		return true
	}
	return false
}

func runAuditExport(cmd *cobra.Command, _ []string) (err error) {
	auditPath := auditExportDB
	if auditPath == "" {
		if cfg == nil {
			return fmt.Errorf("audit export: config not loaded")
		}
		auditPath = cfg.AuditDB
	} else if info, statErr := os.Stat(auditPath); statErr != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("audit export: --db %s is not an audit database file", auditPath)
	}
	// A bad --since/--until is a usage error (exit 2, GAP-2110), checked
	// before the database is opened or an -o file is created.
	window, err := parseAuditExportWindow(time.Now())
	if err != nil {
		return auditUsageError(cmd, err)
	}
	version.SetBinaryVersion(appVersion)
	prov := version.Current()

	db, err := audit.OpenReadOnlyDB(auditPath)
	if err != nil {
		return fmt.Errorf("audit export: open db: %w", err)
	}
	defer db.Close()
	// A reader that stops early (| head -1, | Select-Object -First 1) is
	// not an export failure (GAP-1694).
	defer func() { err = quietClosedOutputPipe(err) }()

	out := io.Writer(os.Stdout)
	if auditExportOut != "" && auditExportOut != "-" {
		// ("Audit export output file is created with
		// default-readable permissions before chmod"): os.Create uses
		// O_CREATE|O_TRUNC with mode 0666 masked by the process umask,
		// so on a 022 umask host the file briefly exists as 0644
		// before the os.Chmod tightens it. A local attacker watching
		// a shared directory (or holding an FD opened during that
		// window) could read sensitive audit content written
		// afterwards. Open with O_CREATE|O_EXCL|0o600 so the file is
		// 0600 from creation and we refuse to clobber an existing
		// file (which could be an attacker-pre-created decoy).
		// --force removes the old file first, so the new one is still
		// created with O_EXCL and 0600 (GAP-1398).
		if auditExportForce {
			if rmErr := os.Remove(auditExportOut); rmErr != nil && !os.IsNotExist(rmErr) {
				return fmt.Errorf("audit export: remove existing output %s: %w", auditExportOut, rmErr)
			}
		}
		f, err := os.OpenFile(
			auditExportOut,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC,
			0o600,
		)
		if err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("audit export: %s already exists; pass --force to overwrite it or choose another -o path", auditExportOut)
			}
			return fmt.Errorf("audit export: create output: %w", err)
		}
		defer f.Close()
		lc := &lineCountWriter{w: f}
		out = lc
		// GAP-1494: say what was written instead of finishing silently.
		defer func() {
			if err != nil {
				return
			}
			msgOut := io.Writer(os.Stderr)
			if cmd != nil {
				msgOut = cmd.ErrOrStderr()
			}
			fmt.Fprintf(msgOut, "Wrote %d line(s) to %s\n", lc.lines, auditExportOut)
		}()
	}

	connFilter := strings.ToLower(strings.TrimSpace(auditExportConnector))

	where, args := window.sqlPredicate()
	// event_name marks a v8 record (GAP-2203); a database from before v8
	// has no such column, and its rows are all legacy rows.
	eventNameCol := "NULL"
	if ok, _ := columnExists(db, "audit_events", "event_name"); ok {
		eventNameCol = "event_name"
	}
	q := `SELECT id, timestamp, action, target, actor, details, structured_json, severity, run_id,
session_id, trace_id, agent_id, agent_name, agent_instance_id, sidecar_instance_id,
schema_version, content_hash, generation, binary_version,
destination_app, tool_name, tool_id, policy_id, connector, ` + eventNameCol + `
FROM audit_events` + where + ` ORDER BY ` + window.orderBy()
	// When a connector or time filter is active the cap must apply to
	// *matching* rows, so we filter in Go and bound the count there.
	// Without one we push LIMIT into SQL (cheaper, unchanged behavior).
	if auditExportLimit > 0 && connFilter == "" && !window.timeFiltered() {
		q += ` LIMIT ?`
		args = append(args, auditExportLimit)
	}

	rows, err := db.Query(q, args...)
	if err != nil {
		// Older DBs may miss v7 columns — fall back to minimal projection.
		if err := exportAuditEventsFallbackWindow(db, out, prov, connFilter, window); err != nil {
			return err
		}
		// Activity rows are operator config mutations, not connector-scoped,
		// so they are omitted whenever a connector filter is requested.
		if auditExportIncludeActivity && connFilter == "" {
			return appendActivityLines(auditExportStderr(cmd), db, out, prov, window)
		}
		return nil
	}
	defer rows.Close()

	sink := window.sink(out)
	seenConnectors := map[string]struct{}{}
	matchedConnectorRows := 0
	for rows.Next() {
		var (
			id, ts, action, actor                           string
			target, details, structuredRaw, severity, runID sql.NullString
			sessionID, traceID                              sql.NullString
			agentID, agentName, agentInst, sidecarInst      sql.NullString
			schemaVer                                       sql.NullInt64
			contentHash, binVer                             sql.NullString
			gen                                             sql.NullInt64
			destApp, toolName, toolID, policyID             sql.NullString
			connectorCol, eventName                         sql.NullString
		)
		if err := rows.Scan(
			&id, &ts, &action, &target, &actor, &details, &structuredRaw, &severity, &runID,
			&sessionID, &traceID,
			&agentID, &agentName, &agentInst, &sidecarInst,
			&schemaVer, &contentHash, &gen, &binVer,
			&destApp, &toolName, &toolID, &policyID, &connectorCol, &eventName,
		); err != nil {
			return fmt.Errorf("audit export: scan: %w", err)
		}

		if !window.contains(ts) {
			continue
		}
		connector := resolveAuditEventConnector(ns(connectorCol), ns(details), ns(structuredRaw))
		if connFilter != "" {
			if connector != "" {
				seenConnectors[connector] = struct{}{}
			}
			if connector != connFilter {
				continue
			}
			matchedConnectorRows++
		}

		line, err := buildAuditEventLine(id, ts, action,
			ns(target), ns(details), ns(severity), ns(runID),
			ns(structuredRaw),
			ns(sessionID), ns(traceID),
			actor,
			ns(agentID), ns(agentName), ns(agentInst), ns(sidecarInst),
			schemaVer, ns(contentHash), gen, ns(binVer),
			ns(destApp), ns(toolName), ns(toolID), ns(policyID),
			connector, ns(eventName),
			prov,
		)
		if err != nil {
			return err
		}
		more, err := sink.add(line, ts)
		if err != nil {
			return err
		}
		if !more {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := sink.flush(); err != nil {
		return err
	}
	if connFilter != "" && matchedConnectorRows == 0 {
		noteUnmatchedAuditConnector(cmd.ErrOrStderr(), connFilter, seenConnectors)
	}

	// Activity rows are operator config mutations, not connector-scoped, so
	// they are omitted whenever a connector filter is requested.
	if auditExportIncludeActivity && connFilter == "" {
		if err := appendActivityLines(auditExportStderr(cmd), db, out, prov, window); err != nil {
			return err
		}
	}
	return nil
}

// activityHistoryNote says why --include-activity added nothing (GAP-1170):
// since 1.0 operator changes are audit rows in the export itself, and
// activity_events holds only history from older databases.
const activityHistoryNote = "note: --include-activity added no rows. Configuration changes and operator " +
	"actions are already audit rows in this export (action config-update and others); " +
	"activity_events holds only history from releases before 1.0."

// appendActivityLines appends the activity_events rows and notes on stderr
// when there were none, so the flag never looks broken. stdout stays JSONL.
func appendActivityLines(stderr io.Writer, db *sql.DB, out io.Writer, prov version.Provenance, window auditExportWindow) error {
	counted := &lineCountWriter{w: out}
	if err := exportActivityLines(db, counted, prov, window); err != nil {
		return err
	}
	if counted.lines == 0 {
		fmt.Fprintln(stderr, activityHistoryNote)
	}
	return nil
}

func auditExportStderr(cmd *cobra.Command) io.Writer {
	if cmd == nil {
		return os.Stderr
	}
	return cmd.ErrOrStderr()
}

// noteUnmatchedAuditConnector says on stderr that --connector matched no row,
// naming the connectors that do have rows in the window, so a typo is not
// mistaken for "no activity" (GAP-1237). stdout stays valid, empty JSONL.
func noteUnmatchedAuditConnector(w io.Writer, filter string, seen map[string]struct{}) {
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		fmt.Fprintf(w, "audit export: no rows from connector %q in this window (no row in it names a connector)\n", filter)
		return
	}
	fmt.Fprintf(w, "audit export: no rows from connector %q in this window; connectors with rows: %s\n", filter, strings.Join(names, ", "))
}

// auditExportWindow is the row selection of one export: an optional time
// window and which end of it a --limit keeps.
type auditExportWindow struct {
	since, until *time.Time
	limit        int
	newest       bool
}

// auditUsageError gives a bad flag value the usage-error shape and exit
// status 2, like unknown flags and unparsable numbers (GAP-2110).
func auditUsageError(cmd *cobra.Command, err error) error {
	if cmd == nil {
		return withExitCode(err, 2)
	}
	return usageError(cmd, err)
}

// parseAuditExportWindow reads --since, --until, --limit and --newest.
func parseAuditExportWindow(now time.Time) (auditExportWindow, error) {
	window := auditExportWindow{limit: auditExportLimit, newest: auditExportNewest}
	var err error
	if window.since, err = parseAuditExportTime("--since", auditExportSince, now); err != nil {
		return window, err
	}
	if window.until, err = parseAuditExportTime("--until", auditExportUntil, now); err != nil {
		return window, err
	}
	if window.since != nil && window.until != nil && !window.until.After(*window.since) {
		return window, fmt.Errorf("audit export: --until must be after --since")
	}
	return window, nil
}

// parseAuditExportTime accepts an RFC3339 time or a non-negative duration
// meaning that long before now.
func parseAuditExportTime(flag, value string, now time.Time) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		parsed = parsed.UTC()
		return &parsed, nil
	}
	if ago, err := time.ParseDuration(value); err == nil && ago >= 0 {
		parsed := now.Add(-ago).UTC()
		return &parsed, nil
	}
	return nil, fmt.Errorf("audit export: invalid %s %q (use an RFC3339 time such as 2026-09-27T18:30:00Z or a duration such as 30m)", flag, value)
}

func (w auditExportWindow) timeFiltered() bool { return w.since != nil || w.until != nil }

// keepsNewest reports a --limit that keeps the most recent rows.
func (w auditExportWindow) keepsNewest() bool { return w.newest && w.limit > 0 }

// orderBy is the SQL order: newest first while collecting the newest rows,
// oldest first otherwise.
func (w auditExportWindow) orderBy() string {
	if w.keepsNewest() {
		return "timestamp DESC, rowid DESC"
	}
	return "timestamp ASC"
}

// sqlPredicate is a coarse, index-friendly prefilter on the timestamp
// column. Stored timestamps are RFC3339 with a variable fraction or
// SQLite's "YYYY-MM-DD HH:MM:SS", possibly with an offset, so string order
// is exact only to the day; the bounds keep a day of slack each side and
// contains applies the exact window.
func (w auditExportWindow) sqlPredicate() (string, []any) {
	var clauses []string
	var args []any
	if w.since != nil {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, w.since.AddDate(0, 0, -1).Format("2006-01-02"))
	}
	if w.until != nil {
		clauses = append(clauses, "timestamp < ?")
		args = append(args, w.until.AddDate(0, 0, 2).Format("2006-01-02"))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// contains applies the exact time window to a stored timestamp. A row
// whose timestamp does not parse is outside any window.
func (w auditExportWindow) contains(stored string) bool {
	if !w.timeFiltered() {
		return true
	}
	at, ok := parseAuditRowTimestamp(stored)
	if !ok {
		return false
	}
	if w.since != nil && at.Before(*w.since) {
		return false
	}
	return w.until == nil || at.Before(*w.until)
}

// parseAuditRowTimestamp parses the formats normalizeTimestamp accepts.
func parseAuditRowTimestamp(stored string) (time.Time, bool) {
	stored = strings.TrimSpace(stored)
	if at, err := time.Parse(time.RFC3339Nano, stored); err == nil {
		return at, true
	}
	if at, err := time.Parse("2006-01-02 15:04:05", stored); err == nil {
		return at.UTC(), true
	}
	return time.Time{}, false
}

func (w auditExportWindow) sink(out io.Writer) *auditExportSink {
	return &auditExportSink{out: out, limit: w.limit, newest: w.keepsNewest()}
}

// auditExportSink writes export lines oldest first and applies --limit.
//
// For --newest the rows arrive in descending string order of their stored
// timestamps, which is chronological only to the day (offsets and variable
// fractions reorder rows within it). The sink therefore keeps the limit
// newest rows by parsed time in a bounded heap, stops once the stored day
// falls more than a day before the oldest kept row (no later row can be
// newer), and writes the kept rows oldest first on flush.
type auditExportSink struct {
	out     io.Writer
	limit   int
	newest  bool
	kept    auditExportHeap
	arrived int
	emitted int
}

// add records one line stored at the given timestamp and reports whether
// more lines are wanted.
func (s *auditExportSink) add(line []byte, stored string) (bool, error) {
	if s.newest {
		at, _ := parseAuditRowTimestamp(stored)
		if len(s.kept) == s.limit && s.limit > 0 && storedDayBefore(stored, s.kept[0].at.AddDate(0, 0, -1)) {
			return false, nil
		}
		s.arrived++
		entry := auditExportEntry{at: at, arrival: s.arrived, line: string(line)}
		if len(s.kept) < s.limit {
			heap.Push(&s.kept, entry)
		} else if s.kept.less(s.kept[0], entry) {
			s.kept[0] = entry
			heap.Fix(&s.kept, 0)
		}
		return true, nil
	}
	if _, err := fmt.Fprintln(s.out, string(line)); err != nil {
		return false, err
	}
	s.emitted++
	return s.limit <= 0 || s.emitted < s.limit, nil
}

func (s *auditExportSink) flush() error {
	entries := append([]auditExportEntry(nil), s.kept...)
	sort.Slice(entries, func(i, j int) bool { return s.kept.less(entries[i], entries[j]) })
	for _, entry := range entries {
		if _, err := fmt.Fprintln(s.out, entry.line); err != nil {
			return err
		}
	}
	s.kept = nil
	return nil
}

// storedDayBefore reports whether a stored timestamp's calendar day is
// before cutoff's day. Every stored format starts with YYYY-MM-DD.
func storedDayBefore(stored string, cutoff time.Time) bool {
	stored = strings.TrimSpace(stored)
	if len(stored) < len("2006-01-02") {
		return false
	}
	return stored[:len("2006-01-02")] < cutoff.UTC().Format("2006-01-02")
}

// auditExportEntry is one row kept for --newest. A later arrival is older
// in stored order, so it sorts first among rows at the same instant.
type auditExportEntry struct {
	at      time.Time
	arrival int
	line    string
}

// auditExportHeap is a min-heap of kept rows: the oldest kept row is on top.
type auditExportHeap []auditExportEntry

func (h auditExportHeap) less(a, b auditExportEntry) bool {
	if !a.at.Equal(b.at) {
		return a.at.Before(b.at)
	}
	return a.arrival > b.arrival
}

func (h auditExportHeap) Len() int           { return len(h) }
func (h auditExportHeap) Less(i, j int) bool { return h.less(h[i], h[j]) }
func (h auditExportHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *auditExportHeap) Push(x any)        { *h = append(*h, x.(auditExportEntry)) }
func (h *auditExportHeap) Pop() any {
	old := *h
	entry := old[len(old)-1]
	*h = old[:len(old)-1]
	return entry
}

// resolveAuditEventConnector returns the lowercased connector an audit row
// is attributed to, or "" if none. The dedicated `connector` column
// (migration 16) is authoritative; when it is blank (older rows, non-hook
// writers that only set the structured payload) it falls back to the
// structured `connector` field and finally the `connector=<name>` details
// token — mirroring the attribution the TUI and `alerts --connector` use.
func resolveAuditEventConnector(connectorCol, details, structuredRaw string) string {
	if c := strings.ToLower(strings.TrimSpace(connectorCol)); c != "" {
		return c
	}
	return auditEventConnector(details, structuredRaw)
}

// auditEventConnector returns the lowercased connector an audit row is
// attributed to, or "" if none. It mirrors the attribution the TUI and
// `alerts --connector` use: the structured payload's "connector" field is
// authoritative; otherwise it falls back to a `connector=<name>` token in
// the free-form details string.
func auditEventConnector(details, structuredRaw string) string {
	if s := strings.TrimSpace(structuredRaw); s != "" {
		var m map[string]any
		if json.Unmarshal([]byte(s), &m) == nil {
			if c, ok := m["connector"].(string); ok {
				if c = strings.TrimSpace(c); c != "" {
					return strings.ToLower(c)
				}
			}
		}
	}
	return strings.ToLower(auditDetailsKV(details, "connector"))
}

// auditDetailsKV extracts a single `key=value` token from a space-separated
// details string. Connector names are single tokens (no spaces), so a simple
// field split is sufficient for best-effort filtering.
func auditDetailsKV(details, key string) string {
	for _, tok := range strings.Fields(details) {
		if eq := strings.IndexByte(tok, '='); eq > 0 && tok[:eq] == key {
			return strings.TrimSpace(tok[eq+1:])
		}
	}
	return ""
}

func exportAuditEventsFallback(db *sql.DB, out io.Writer, prov version.Provenance, connFilter string) error {
	window, err := parseAuditExportWindow(time.Now())
	if err != nil {
		return err
	}
	return exportAuditEventsFallbackWindow(db, out, prov, connFilter, window)
}

func exportAuditEventsFallbackWindow(db *sql.DB, out io.Writer, prov version.Provenance, connFilter string, window auditExportWindow) error {
	where, args := window.sqlPredicate()
	rows, err := db.Query(`SELECT id, timestamp, action, target, actor, details, severity, run_id FROM audit_events`+
		where+` ORDER BY `+window.orderBy(), args...)
	if err != nil {
		return fmt.Errorf("audit export: %w", err)
	}
	defer rows.Close()
	sink := window.sink(out)
	for rows.Next() {
		var id, ts, action, actor string
		var target, details, severity, runID sql.NullString
		if err := rows.Scan(&id, &ts, &action, &target, &actor, &details, &severity, &runID); err != nil {
			return fmt.Errorf("audit export: scan: %w", err)
		}
		if !window.contains(ts) {
			continue
		}
		// Legacy projection has no structured_json column; attribution is
		// best-effort from the details connector= token only.
		conn := auditEventConnector(ns(details), "")
		if connFilter != "" && conn != connFilter {
			continue
		}
		line, err := buildAuditEventLine(id, ts, action,
			ns(target), ns(details), ns(severity), ns(runID),
			"",
			"", "",
			actor,
			"", "", "", "",
			sql.NullInt64{}, "", sql.NullInt64{}, "",
			"", "", "", "",
			conn, "",
			prov,
		)
		if err != nil {
			return err
		}
		more, err := sink.add(line, ts)
		if err != nil {
			return err
		}
		if !more {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return sink.flush()
}

func ns(s sql.NullString) string {
	if !s.Valid {
		return ""
	}
	return s.String
}

func buildAuditEventLine(
	id, ts, action, target, details, severity, runID string,
	structuredRaw string,
	sessionID, traceID string,
	actor string,
	agentID, agentName, agentInst, sidecarInst string,
	schemaVer sql.NullInt64, contentHash string, gen sql.NullInt64, binVer string,
	destApp, toolName, toolID, policyID string,
	connector, eventName string,
	prov version.Provenance,
) ([]byte, error) {
	v8Action := isV8RecordAction(eventName, action)
	actionOut, detailsOut := strings.TrimSpace(action), details
	if !v8Action {
		actionOut, detailsOut = normalizeAuditAction(action, details)
	}
	sev := normalizeSeverity(severity)
	act := strings.TrimSpace(actor)
	if act == "" {
		act = "system:defenseclaw"
	}
	sv := int(version.SchemaVersion)
	if schemaVer.Valid && schemaVer.Int64 >= 7 {
		sv = int(schemaVer.Int64)
	}
	ch := strings.TrimSpace(contentHash)
	if ch == "" {
		ch = prov.ContentHash
	}
	g := prov.Generation
	if gen.Valid && gen.Int64 >= 0 {
		g = uint64(gen.Int64)
	}
	bver := binVer
	if strings.TrimSpace(bver) == "" {
		bver = prov.BinaryVersion
	}
	structured, err := parseStructuredPayload(structuredRaw)
	if err != nil {
		return nil, err
	}

	ev := map[string]any{
		"id":                  id,
		"timestamp":           normalizeTimestamp(ts),
		"action":              actionOut,
		"actor":               act,
		"schema_version":      sv,
		"severity":            sev,
		"content_hash":        nilIfEmptyStr(ch),
		"generation":          g,
		"binary_version":      nilIfEmptyStr(bver),
		"run_id":              strPtr(runID),
		"session_id":          strPtr(sessionID),
		"trace_id":            strPtr(traceID),
		"span_id":             nil,
		"target":              strPtr(target),
		"details":             strPtr(detailsOut),
		"structured":          structured,
		"agent_id":            strPtr(agentID),
		"agent_name":          strPtr(agentName),
		"agent_instance_id":   strPtr(agentInst),
		"sidecar_instance_id": strPtr(sidecarInst),
		"destination_app":     strPtr(destApp),
		"tool_name":           strPtr(toolName),
		"tool_id":             strPtr(toolID),
		"policy_id":           strPtr(policyID),
		"connector":           strPtr(connector),
	}
	if err := validateAuditEventMap(ev, v8Action); err != nil {
		return nil, fmt.Errorf("audit export: %w", err)
	}
	return json.Marshal(ev)
}

func parseStructuredPayload(raw string) (any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, fmt.Errorf("invalid structured_json: %w", err)
	}
	return payload, nil
}

func nilIfEmptyStr(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func strPtr(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func normalizeTimestamp(ts string) string {
	// SQLite may store ISO strings without timezone — ensure RFC3339-like.
	ts = strings.TrimSpace(ts)
	if ts == "" {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	if t, err := time.Parse("2006-01-02 15:04:05", ts); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return ts
}

func normalizeSeverity(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "INFO"
	}
	if s == "ERROR" {
		return "WARN"
	}
	if s == "ACK" {
		return "INFO"
	}
	// schema: CRITICAL, HIGH, MEDIUM, LOW, INFO, WARN
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARN":
		return s
	default:
		return "INFO"
	}
}

// v8RecordActionPattern is the action shape the audit-event schema accepts
// for v8 runtime records.
var v8RecordActionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// isV8RecordAction reports whether a row is a v8 runtime record whose action
// the export keeps as is. A v8 record (event_name set and not a
// legacy.audit.* compatibility identity) carries the action of its telemetry
// family, which the runtime catalog validated: telemetry-destination,
// circuit_breaker_open, config.change.applied and others. Those are not
// audit-logger actions, so rewriting them to "action" with the real value in
// legacy_action=... hid them from SIEM queries on the action (GAP-2203).
func isV8RecordAction(eventName, action string) bool {
	name := strings.TrimSpace(eventName)
	if name == "" || strings.HasPrefix(name, "legacy.audit.") {
		return false
	}
	return v8RecordActionPattern.MatchString(strings.TrimSpace(action))
}

func normalizeAuditAction(action, details string) (string, string) {
	a := strings.TrimSpace(action)
	if isKnownAuditAction(a) {
		return a, details
	}
	prefix := "legacy_action=" + a
	if strings.TrimSpace(details) == "" {
		return "action", prefix
	}
	return "action", prefix + " | " + details
}

var auditSeverityEnum = map[string]struct{}{
	"CRITICAL": {}, "HIGH": {}, "MEDIUM": {}, "LOW": {}, "INFO": {}, "WARN": {},
}

func validateAuditEventMap(ev map[string]any, v8Action bool) error {
	if _, ok := ev["id"]; !ok {
		return fmt.Errorf("invalid audit event: missing id")
	}
	if _, ok := ev["timestamp"]; !ok {
		return fmt.Errorf("invalid audit event: missing timestamp")
	}
	act, _ := ev["action"].(string)
	if v8Action {
		if !v8RecordActionPattern.MatchString(act) {
			return fmt.Errorf("invalid audit event: v8 record action %q", act)
		}
	} else if !isKnownAuditAction(act) {
		return fmt.Errorf("invalid audit event: unknown action %q", act)
	}
	sev, _ := ev["severity"].(string)
	if _, ok := auditSeverityEnum[sev]; !ok {
		return fmt.Errorf("invalid audit event: severity %q", sev)
	}
	sv, ok := ev["schema_version"].(int)
	if !ok || sv < 7 {
		return fmt.Errorf("invalid audit event: schema_version")
	}
	return nil
}

func exportActivityLines(db *sql.DB, out io.Writer, prov version.Provenance, window auditExportWindow) error {
	exists, err := tableExists(db, "activity_events")
	if err != nil || !exists {
		return nil
	}
	where, args := window.sqlPredicate()
	rows, err := db.Query(`
SELECT timestamp, actor, action, target_type, target_id, reason,
       before_json, after_json, diff_json, version_from, version_to
FROM activity_events`+where+` ORDER BY timestamp ASC`, args...)
	if err != nil {
		return fmt.Errorf("audit export: activity query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var timestamp sql.NullString
		var actor, action, tt, tid string
		var reason sql.NullString
		var beforeJ, afterJ, diffJ sql.NullString
		var vf, vt sql.NullString
		if err := rows.Scan(&timestamp, &actor, &action, &tt, &tid, &reason, &beforeJ, &afterJ, &diffJ, &vf, &vt); err != nil {
			return fmt.Errorf("audit export: activity scan: %w", err)
		}
		if !window.contains(ns(timestamp)) {
			continue
		}
		payload, err := buildActivityPayload(actor, action, tt, tid, reason, beforeJ, afterJ, diffJ, vf, vt, prov)
		if err != nil {
			return err
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if err := validateActivityPayloadMap(payload); err != nil {
			return fmt.Errorf("audit export: activity: %w", err)
		}
		if _, err := fmt.Fprintln(out, string(b)); err != nil {
			return err
		}
	}
	return rows.Err()
}

func columnExists(db *sql.DB, table, column string) (bool, error) {
	var n int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, table, column,
	).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func tableExists(db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
	).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func buildActivityPayload(
	actor, action, targetType, targetID string,
	reason sql.NullString,
	beforeJ, afterJ, diffJ sql.NullString,
	vf, vt sql.NullString,
	prov version.Provenance,
) (map[string]any, error) {
	_ = prov // reserved for future envelope fields
	act := normalizeActivityAction(action)
	m := map[string]any{
		"actor":        actor,
		"action":       act,
		"target_type":  targetType,
		"target_id":    targetID,
		"reason":       strPtr(ns(reason)),
		"version_from": strPtr(ns(vf)),
		"version_to":   strPtr(ns(vt)),
	}
	m["before"] = jsonRawToAny(ns(beforeJ))
	m["after"] = jsonRawToAny(ns(afterJ))
	if diffJ.Valid && strings.TrimSpace(diffJ.String) != "" {
		var diff any
		if err := json.Unmarshal([]byte(diffJ.String), &diff); err == nil {
			m["diff"] = diff
		}
	}
	return m, nil
}

func normalizeActivityAction(a string) string {
	a = strings.TrimSpace(a)
	if _, ok := activityActionEnum[a]; ok {
		return a
	}
	return "action"
}

func jsonRawToAny(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return v
}

// activityActionEnum is the action subset from schemas/activity-event.json.
var activityActionEnum = map[string]struct{}{
	"config-update": {}, "policy-update": {}, "policy-reload": {},
	"block": {}, "allow": {}, "quarantine": {}, "restore": {}, "disable": {}, "enable": {},
	"action": {}, "acknowledge-alerts": {}, "dismiss-alerts": {}, "deploy": {}, "stop": {},
}

func validateActivityPayloadMap(m map[string]any) error {
	for _, k := range []string{"actor", "action", "target_type", "target_id"} {
		if v, ok := m[k].(string); !ok || strings.TrimSpace(v) == "" {
			return fmt.Errorf("invalid activity payload: %q", k)
		}
	}
	act := m["action"].(string)
	if _, ok := activityActionEnum[act]; !ok {
		return fmt.Errorf("invalid activity action %q", act)
	}
	return nil
}

// lineCountWriter counts the JSONL lines written through it so a file export
// can report its size.
type lineCountWriter struct {
	w     io.Writer
	lines int
}

func (c *lineCountWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.lines += bytes.Count(p[:n], []byte{'\n'})
	return n, err
}

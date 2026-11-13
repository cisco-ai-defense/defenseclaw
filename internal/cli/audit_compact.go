// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var (
	auditCompactDryRun bool
	auditCompactJSON   bool
)

var auditCompactCmd = &cobra.Command{
	Use:   "compact",
	Short: "Give the disk space of deleted audit history back (stop the gateway first)",
	Long: `Give the disk space of deleted audit history back to the disk.

SQLite keeps audit.db at its largest size after retention deletes old events.
compact rewrites the store with only the rows that are left (VACUUM), switches
it to incremental auto_vacuum so later retention passes give their space back
on their own, and empties the WAL. A store that already uses incremental
auto_vacuum gives its free pages back without a rewrite. No row is changed or
removed, and running it again is safe.

Stop the gateway first: compact refuses while the gateway or any other program
has the audit database open, and a gateway started during the compaction
cannot open the store until it ends. The rewrite needs free disk space next to
audit.db of about twice the live data; compact checks it first and refuses
with the numbers when the disk is short. --dry-run reports what compact would
reclaim and changes nothing; it also works while the gateway runs.

On a managed computer run it as an administrator (root, or an elevated
PowerShell prompt on Windows) after you stop the gateway service.

Examples:
  defenseclaw-gateway audit compact --dry-run
  defenseclaw-gateway stop && defenseclaw-gateway audit compact && defenseclaw-gateway start`,
	Annotations:       map[string]string{secureClientAbsentAnnotation: "true"},
	Args:              cobra.NoArgs,
	PersistentPreRunE: auditCompactPersistentPreRunE,
	RunE:              runAuditCompact,
}

func init() {
	auditCompactCmd.Flags().BoolVar(&auditCompactDryRun, "dry-run", false, "Report what compact would reclaim and change nothing (works while the gateway runs)")
	auditCompactCmd.Flags().BoolVar(&auditCompactJSON, "json", false, "Print the result as JSON")
	auditCmd.AddCommand(auditCompactCmd)
}

// auditCompactPersistentPreRunE loads the configuration without opening the
// audit store (compact opens it alone). On a standalone managed computer
// the managed audit store belongs to the gateway service: an administrator
// gets the managed deployment, as `audit export` does, and the store must
// pass the managed runtime file check; anyone else is refused.
func auditCompactPersistentPreRunE(cmd *cobra.Command, _ []string) error {
	if err := prepareManagedAuditCompactEnvironment(); err != nil {
		return err
	}
	// Windows checked its administrator above; the unix standalone
	// deployment has an administrator (root) and the service account.
	admin := false
	if runtime.GOOS != "windows" {
		applyManagedStandaloneAdminEnv(cmd.ErrOrStderr())
		_, admin = managedStandaloneAdminCaller(nil)
		if !admin {
			_, _, deploymentErr := managedStandaloneAdminDeployment()
			if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) || deploymentErr == nil {
				return errors.New("audit compact on a managed computer needs root (sudo) or the gateway service account; nothing was changed")
			}
		}
	}
	if err := loadGatewayCommandConfigFor(cmd); err != nil {
		return err
	}
	if admin && cfg.StandaloneEnterprise() {
		if err := managedAuditStoreTrustCheck(cfg.AuditDB); err != nil {
			return fmt.Errorf("failed to open the managed audit store: %w", err)
		}
	}
	return nil
}

// prepareManagedAuditCompactEnvironment gives an elevated administrator the
// managed Windows deployment (pinManagedAdministratorEnvironment); a
// standard account is told to ask one. Every other host is left alone.
func prepareManagedAuditCompactEnvironment() error {
	return pinManagedAdministratorEnvironment("audit compact", func() string {
		return "The audit log of a managed computer can be compacted only from an elevated Administrator prompt or by the MDM agent. " +
			"Ask your administrator, who stops the gateway service and runs " + managedWindowsCommand("audit", "compact") +
			" from an elevated PowerShell prompt. Nothing was changed."
	})
}

// auditCompactManaged reports a managed deployment: the configuration a
// unix administrator loaded, or the pinned Windows deployment.
func auditCompactManaged() bool {
	return (cfg != nil && cfg.StandaloneEnterprise()) || managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv))
}

// auditCompactGatewayRunning reports the gateway this data directory
// records; tests replace it.
var auditCompactGatewayRunning = func() (bool, int) {
	return daemon.New(config.DefaultDataPath()).IsRunning()
}

// auditCompactStopStart names the commands that stop and start the gateway
// that owns this store.
func auditCompactStopStart() (string, string) {
	if !auditCompactManaged() {
		return "defenseclaw-gateway stop", "defenseclaw-gateway start"
	}
	switch runtime.GOOS {
	case "windows":
		return "Stop-Service DefenseClawGateway (elevated PowerShell)", "Start-Service DefenseClawGateway"
	case "darwin":
		return "sudo launchctl bootout system/" + managedHostDarwinGatewayLabel,
			"sudo launchctl bootstrap system /Library/LaunchDaemons/" + managedHostDarwinGatewayLabel + ".plist"
	}
	units := "defenseclaw-gateway-hook.socket defenseclaw-gateway-api.socket " + managedHostLinuxGatewayUnit
	return "sudo systemctl stop " + units, "sudo systemctl start " + units
}

// auditCompactInUse is the refusal while the store is open elsewhere.
func auditCompactInUse(db string, pid int) error {
	stop, start := auditCompactStopStart()
	who := "another program (the gateway, a defenseclaw command or a sqlite3 shell) has " + db + " open"
	if pid > 0 {
		who = fmt.Sprintf("the gateway (PID %d) is running and has %s open", pid, db)
	}
	return fmt.Errorf("%s, and compact needs it alone. Stop it with: %s; run defenseclaw audit compact again; then start the gateway with: %s. Nothing was changed",
		who, stop, start)
}

func runAuditCompact(cmd *cobra.Command, _ []string) error {
	if cfg == nil {
		return errors.New("audit compact: config not loaded")
	}
	db := cfg.AuditDB
	if handled, err := auditCompactAsStoreOwner(cmd, db); handled {
		return err
	}
	running, pid := auditCompactGatewayRunning()
	if running && !auditCompactDryRun {
		return auditCompactInUse(db, pid)
	}
	report, err := audit.CompactStore(db, audit.CompactOptions{DryRun: auditCompactDryRun, FreeDiskBytes: dataDirFreeBytes})
	var space *audit.CompactSpaceError
	switch {
	case errors.Is(err, audit.ErrCompactStoreInUse):
		return auditCompactInUse(db, 0)
	case errors.As(err, &space):
		return fmt.Errorf("%w. Free some space on that disk and run defenseclaw audit compact again. Nothing was changed", err)
	case err != nil:
		return fmt.Errorf("audit compact: %w", err)
	}
	out := cmd.OutOrStdout()
	if auditCompactJSON {
		return writeAuditCompactJSON(out, report, running)
	}
	writeAuditCompactText(out, report, running)
	return nil
}

type auditCompactJSONResult struct {
	audit.CompactReport
	ReclaimableBytes int64 `json:"reclaimable_bytes"`
	ReclaimedBytes   int64 `json:"reclaimed_bytes"`
	GatewayRunning   bool  `json:"gateway_running"`
}

func writeAuditCompactJSON(out io.Writer, report audit.CompactReport, running bool) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(auditCompactJSONResult{
		CompactReport:    report,
		ReclaimableBytes: report.ReclaimableBytes(),
		ReclaimedBytes:   report.ReclaimedBytes(),
		GatewayRunning:   running,
	})
}

func writeAuditCompactText(out io.Writer, report audit.CompactReport, running bool) {
	fmt.Fprintf(out, "Audit database: %s\n", report.Path)
	fmt.Fprintf(out, "Size: %s (audit.db %s, WAL %s); %s in free pages; auto_vacuum %s\n",
		auditCompactMiB(report.FileBytesBefore+report.WALBytesBefore), auditCompactMiB(report.FileBytesBefore),
		auditCompactMiB(report.WALBytesBefore), auditCompactMiB(report.FreeBytes), report.AutoVacuumBefore)
	if report.DryRun {
		switch report.Method {
		case audit.CompactVacuum:
			fmt.Fprintf(out, "compact would rewrite it (VACUUM), switch auto_vacuum to incremental and reclaim about %s.\n",
				auditCompactMiB(report.ReclaimableBytes()))
		case audit.CompactIncremental:
			fmt.Fprintf(out, "compact would give the free pages back (incremental_vacuum) and reclaim about %s.\n",
				auditCompactMiB(report.ReclaimableBytes()))
		default:
			fmt.Fprintf(out, "Nothing to reclaim beyond the WAL (%s).\n", auditCompactMiB(report.WALBytesBefore))
		}
		if report.NeedBytes > 0 {
			free := "unknown"
			if report.DiskFreeBytes > 0 {
				free = auditCompactMiB(int64(report.DiskFreeBytes))
			}
			fmt.Fprintf(out, "It needs about %s of free disk space next to audit.db (free now: %s).\n",
				auditCompactMiB(int64(report.NeedBytes)), free)
		}
		if running {
			stop, start := auditCompactStopStart()
			fmt.Fprintf(out, "The gateway is running: stop it first (%s), run defenseclaw audit compact, then start it (%s).\n", stop, start)
		}
		fmt.Fprintln(out, "Dry run: nothing was changed.")
		return
	}
	switch report.Method {
	case audit.CompactVacuum:
		fmt.Fprintf(out, "Rewrote it (VACUUM); auto_vacuum is now %s.\n", report.AutoVacuumAfter)
	case audit.CompactIncremental:
		fmt.Fprintln(out, "Gave the free pages back (incremental_vacuum).")
	default:
		fmt.Fprintln(out, "No free pages to give back; the WAL is empty now.")
	}
	fmt.Fprintf(out, "Now: %s (audit.db %s, WAL %s)\n",
		auditCompactMiB(report.FileBytesAfter+report.WALBytesAfter), auditCompactMiB(report.FileBytesAfter), auditCompactMiB(report.WALBytesAfter))
	fmt.Fprintf(out, "Reclaimed: %s\n", auditCompactMiB(report.ReclaimedBytes()))
	_, start := auditCompactStopStart()
	fmt.Fprintf(out, "Start the gateway again with: %s\n", start)
}

func auditCompactMiB(bytes int64) string {
	value := float64(bytes) / (1 << 20)
	if value >= 10 || value == 0 {
		return fmt.Sprintf("%.0f MiB", value)
	}
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.1f", value), "0"), ".") + " MiB"
}

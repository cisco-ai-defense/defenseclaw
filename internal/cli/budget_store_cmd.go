// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var (
	budgetStoreConfigPath string
	issueSecretFile       string
	issueBundleConfig     string
	issueUsers            []string
	issueGroups           []string
	issueCapUSD           float64
	issueCredentialOut    string
	issueRecordOut        string
	deviceRecordFile      string
	reportSince           string
)

var budgetStoreCmd = &cobra.Command{
	Use:   "budget-store",
	Short: "Run the opt-in fleet budget store (routing.admin.budget_store)",
	Long: `The fleet budget store sums routing.admin budget spend across managed
devices. It is off unless an administrator runs it on a server of their
choice and sets routing.admin.budget_store.url in the device bundle.

Each device has its own credential (device issue, installed by MDM). A
device may add spend and read spend only for its own users and the budgets
they are in; group and connector totals are read on the store host only
(report). No user, group or device name reaches the store.`,
}

var budgetStoreServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the budget store over HTTPS until stopped",
	Long: `Serve reads routing.admin.budget_store.server from the given config.yaml
(listen, tls_cert_file, tls_key_file, db_path, rate_limit_per_minute,
device_daily_cap_usd) and the budget limits from routing.admin.budgets of
the same file (copy the bundle's budgets there).`,
	RunE: runBudgetStoreServe,
}

var budgetStoreDeviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Issue, register, revoke and list device credentials",
}

var budgetStoreIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue one device credential (on an administrator workstation)",
	Long: `Issue makes a device credential and its store record. Run it where the
tenant secret is (--secret-file, base64 of 32 bytes, owner-only), never on a
device. --config is the bundle config.yaml (its routing.admin.budgets);
--user names each of the device's users by UPN or SID, --group each group
the budgets name that they are in.

Install --credential-out on the device as the protected credential
routing-budget-store-device (MDM), and register --record-out on the store
host with: budget-store device add --config <store config> --record <file>.`,
	RunE: runBudgetStoreIssue,
}

var budgetStoreAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Register an issued device on the store host",
	RunE: func(cmd *cobra.Command, _ []string) error {
		store, _, err := openStoreFromConfig()
		if err != nil {
			return err
		}
		defer store.Close()
		raw, err := readOwnerOnlyFile(deviceRecordFile)
		if err != nil {
			return fmt.Errorf("device add: --record %w", err)
		}
		defer clear(raw)
		var rec budgetstore.DeviceRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return errors.New("device add: --record is not a device record")
		}
		if err := store.AddDevice(cmd.Context(), rec); err != nil {
			return fmt.Errorf("device add: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "registered %s (%d keys)\n", rec.ID, len(rec.Keys))
		return nil
	},
}

var budgetStoreRevokeCmd = &cobra.Command{
	Use:   "revoke DEVICE",
	Short: "Refuse a device from now on (its spend stays)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, _, err := openStoreFromConfig()
		if err != nil {
			return err
		}
		defer store.Close()
		if err := store.RevokeDevice(cmd.Context(), args[0]); err != nil {
			return fmt.Errorf("device revoke: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "revoked %s; a running store refuses it within %s\n", args[0], budgetstore.DeviceCacheTTL)
		return nil
	},
}

var budgetStoreListCmd = &cobra.Command{
	Use:   "list",
	Short: "List devices on the store host",
	RunE: func(cmd *cobra.Command, _ []string) error {
		store, _, err := openStoreFromConfig()
		if err != nil {
			return err
		}
		defer store.Close()
		devices, err := store.Devices(cmd.Context())
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "DEVICE\tSTATUS\tKEYS\tCAP USD/DAY\tOVER CAP\tISSUED")
		for _, d := range devices {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%.2f\t%s\t%s\n", d.ID, d.Status, d.Keys, d.CapUSD, d.OverCapDay, d.Created.Format(time.DateOnly))
		}
		return tw.Flush()
	},
}

var budgetStoreReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Fleet totals per charge key (store host only)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		store, _, err := openStoreFromConfig()
		if err != nil {
			return err
		}
		defer store.Close()
		since := reportSince
		if since == "" {
			since = time.Now().UTC().AddDate(0, 0, -30).Format(time.DateOnly)
		}
		rows, err := store.Report(cmd.Context(), since)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "KEY\tUSD\tDEVICES")
		for _, r := range rows {
			fmt.Fprintf(tw, "%s\t%.4f\t%d\n", r.Key, r.USD, r.Devices)
		}
		return tw.Flush()
	},
}

func init() {
	budgetStoreCmd.PersistentFlags().StringVar(&budgetStoreConfigPath, "config", "", "config.yaml (store host: routing.admin.budget_store.server; issue: the bundle config)")
	budgetStoreIssueCmd.Flags().StringVar(&issueSecretFile, "secret-file", "", "tenant secret file (base64 of 32 bytes, owner-only)")
	budgetStoreIssueCmd.Flags().StringArrayVar(&issueUsers, "user", nil, "a user of the device: UPN (name@domain) or SID (repeatable)")
	budgetStoreIssueCmd.Flags().StringArrayVar(&issueGroups, "group", nil, "a group of those users that a budget names (repeatable)")
	budgetStoreIssueCmd.Flags().Float64Var(&issueCapUSD, "cap-usd", 0, "this device's daily spend cap (default: the store's device_daily_cap_usd)")
	budgetStoreIssueCmd.Flags().StringVar(&issueCredentialOut, "credential-out", "", "file for the device credential (for MDM)")
	budgetStoreIssueCmd.Flags().StringVar(&issueRecordOut, "record-out", "", "file for the store record (for device add)")
	for _, name := range []string{"secret-file", "credential-out", "record-out"} {
		_ = budgetStoreIssueCmd.MarkFlagRequired(name)
	}
	budgetStoreAddCmd.Flags().StringVar(&deviceRecordFile, "record", "", "store record from device issue")
	_ = budgetStoreAddCmd.MarkFlagRequired("record")
	budgetStoreReportCmd.Flags().StringVar(&reportSince, "since", "", "first UTC day (YYYY-MM-DD; default 30 days ago)")
	budgetStoreDeviceCmd.AddCommand(budgetStoreIssueCmd, budgetStoreAddCmd, budgetStoreRevokeCmd, budgetStoreListCmd)
	budgetStoreCmd.AddCommand(budgetStoreServeCmd, budgetStoreDeviceCmd, budgetStoreReportCmd)
	rootCmd.AddCommand(budgetStoreCmd)
}

// loadStoreConfig reads the store host's config.yaml.
func loadStoreConfig() (*config.Config, *config.RoutingBudgetStoreServerConfig, error) {
	if strings.TrimSpace(budgetStoreConfigPath) == "" {
		return nil, nil, errors.New("budget-store: --config <config.yaml with routing.admin.budget_store.server> is required")
	}
	cfg, err := config.LoadFromFile(budgetStoreConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("budget-store: %w", err)
	}
	if cfg.Routing.Admin == nil || cfg.Routing.Admin.BudgetStore == nil || cfg.Routing.Admin.BudgetStore.Server == nil {
		return nil, nil, errors.New("budget-store: routing.admin.budget_store.server is not set in " + budgetStoreConfigPath)
	}
	if err := config.ValidateRoutingBudgetStore(cfg.Routing.Admin.BudgetStore, false); err != nil {
		return nil, nil, fmt.Errorf("budget-store: %w", err)
	}
	return cfg, cfg.Routing.Admin.BudgetStore.Server, nil
}

func openStoreFromConfig() (*budgetstore.Store, *config.Config, error) {
	cfg, srv, err := loadStoreConfig()
	if err != nil {
		return nil, nil, err
	}
	store, err := budgetstore.OpenStore(srv.DBPath)
	if err != nil {
		return nil, nil, fmt.Errorf("budget-store: %w", err)
	}
	store.SetDefaultCap(srv.DeviceDailyCapUSD)
	return store, cfg, nil
}

func runBudgetStoreServe(cmd *cobra.Command, _ []string) error {
	cfg, srv, err := loadStoreConfig()
	if err != nil {
		return err
	}
	// The TLS key may be a link (certbot live/); its target must be private,
	// and the bytes checked are the bytes loaded.
	tlsKey, err := filepath.EvalSymlinks(srv.TLSKeyFile)
	if err != nil {
		return errors.New("budget-store serve: tls_key_file cannot be read")
	}
	keyPEM, err := readOwnerOnlyFile(tlsKey)
	if err != nil {
		return fmt.Errorf("budget-store serve: tls_key_file %w", err)
	}
	certPEM, err := os.ReadFile(srv.TLSCertFile)
	if err != nil {
		return errors.New("budget-store serve: tls_cert_file cannot be read")
	}
	tlsConfig, err := budgetstore.ServerTLSConfigPEM(certPEM, keyPEM)
	clear(keyPEM)
	if err != nil {
		return fmt.Errorf("budget-store serve: %w", err)
	}
	store, err := budgetstore.OpenStore(srv.DBPath)
	if err != nil {
		return fmt.Errorf("budget-store serve: %w", err)
	}
	defer store.Close()
	budgets := map[string]budgetstore.Budget{}
	for _, b := range cfg.Routing.Admin.Budgets {
		budgets[b.ID] = budgetstore.Budget{LimitUSD: b.LimitUSD, Period: b.Period}
	}
	store.SetBudgets(budgets)
	store.SetDefaultCap(srv.DeviceDailyCapUSD)
	rate := srv.RateLimitPerMinute
	if rate == 0 {
		rate = config.RoutingBudgetStoreDefaultRate
	}
	server := budgetstore.NewServer(srv.Listen, &budgetstore.Handler{Store: store,
		PreAuth: budgetstore.RateLimiter(rate * 20), PerDevice: budgetstore.RateLimiter(rate)}, tlsConfig)

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			_ = store.Prune(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServeTLS("", "") }()
	fmt.Fprintf(cmd.OutOrStdout(), "budget store serving HTTPS on %s (%d budgets)\n", srv.Listen, len(budgets))
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("budget-store serve: %w", err)
	}
}

func runBudgetStoreIssue(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(budgetStoreConfigPath) == "" {
		return errors.New("device issue: --config <bundle config.yaml> is required (its routing.admin.budgets)")
	}
	if len(issueUsers) == 0 {
		return errors.New("device issue: name at least one --user (UPN or SID)")
	}
	cfg, err := config.LoadFromFile(budgetStoreConfigPath)
	if err != nil {
		return fmt.Errorf("device issue: %w", err)
	}
	if cfg.Routing.Admin == nil || len(cfg.Routing.Admin.Budgets) == 0 {
		return errors.New("device issue: the config has no routing.admin.budgets")
	}
	raw, err := readOwnerOnlyFile(issueSecretFile)
	if err != nil {
		return fmt.Errorf("device issue: --secret-file %w", err)
	}
	secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	clear(raw)
	if err != nil || len(secret) != budgetstore.SecretBytes {
		return errors.New("device issue: --secret-file must hold the tenant secret: base64 of 32 bytes")
	}
	subject, err := budgetstore.NewSubjectKey(secret)
	clear(secret)
	if err != nil {
		return fmt.Errorf("device issue: %w", err)
	}
	cred, rec, err := budgetstore.Issue(subject, budgetstore.IssueInput{
		Budgets: cfg.Routing.Admin.Budgets, Users: issueUsers, Groups: issueGroups, CapUSD: issueCapUSD})
	if err != nil {
		return fmt.Errorf("device issue: %w", err)
	}
	recJSON, _ := json.Marshal(rec)
	for _, out := range []struct {
		path string
		data []byte
	}{{issueCredentialOut, []byte(cred.Encode() + "\n")}, {issueRecordOut, recJSON}} {
		if err := writeNewPrivateFile(out.path, out.data); err != nil {
			return fmt.Errorf("device issue: %w", err)
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "issued %s: %d users, %d keys\n", cred.Device, len(cred.Users), len(rec.Keys))
	return nil
}

// writeNewPrivateFile creates path owner-only and refuses to overwrite.
func writeNewPrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// readOwnerOnlyFile reads a key file that is not a symlink, is owned by the
// user running the command and is readable by that user only (POSIX), or
// that only LocalSystem and Administrators may read (Windows).
func readOwnerOnlyFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("names no file")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("cannot be read")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("must be a regular file, not a link")
	}
	if runtime.GOOS == "windows" {
		if err := managed.RejectUntrustedSecretReaders(path); err != nil {
			return nil, err
		}
		return os.ReadFile(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot be read")
	}
	defer f.Close()
	held, err := f.Stat()
	if err != nil || !os.SameFile(info, held) {
		return nil, errors.New("changed while it was opened")
	}
	if held.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("is readable by others (mode %o); chmod 600 it", held.Mode().Perm())
	}
	if !ownedByCurrentUser(held) {
		return nil, errors.New("must be owned by the account that runs this command")
	}
	return io.ReadAll(io.LimitReader(f, 256<<10))
}

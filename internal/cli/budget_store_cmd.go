// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

var budgetStoreConfigPath string

var budgetStoreCmd = &cobra.Command{
	Use:   "budget-store",
	Short: "Run the opt-in fleet budget store (routing.admin.budget_store)",
	Long: `The fleet budget store sums routing.admin budget spend across managed
devices. It is off unless an administrator runs it on a server of their
choice and sets routing.admin.budget_store.url in the device bundle.

The store keeps only charge keys (a budget id with a keyed hash of a user,
group or connector), UTC days and dollar amounts; no user, group or device
name reaches it. Every request is signed with a key derived from the tenant
secret the store and the devices share, over HTTPS only.`,
}

var budgetStoreServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the budget store over HTTPS until stopped",
	Long: `Serve reads routing.admin.budget_store.server from the given config.yaml:
listen (host:port), tls_cert_file and tls_key_file (PEM), secret_file (the
tenant secret, base64 of 32 bytes, readable by its owner only), db_path
(SQLite) and rate_limit_per_minute (per client address, default 600).`,
	RunE: runBudgetStoreServe,
}

func init() {
	budgetStoreServeCmd.Flags().StringVar(&budgetStoreConfigPath, "config", "", "config.yaml with routing.admin.budget_store.server (required)")
	budgetStoreCmd.AddCommand(budgetStoreServeCmd)
	rootCmd.AddCommand(budgetStoreCmd)
}

func runBudgetStoreServe(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(budgetStoreConfigPath) == "" {
		return errors.New("budget-store serve needs --config <config.yaml with routing.admin.budget_store.server>")
	}
	cfg, err := config.LoadFromFile(budgetStoreConfigPath)
	if err != nil {
		return fmt.Errorf("budget-store serve: %w", err)
	}
	if cfg.Routing.Admin == nil || cfg.Routing.Admin.BudgetStore == nil || cfg.Routing.Admin.BudgetStore.Server == nil {
		return errors.New("budget-store serve: routing.admin.budget_store.server is not set in " + budgetStoreConfigPath)
	}
	srv := cfg.Routing.Admin.BudgetStore.Server
	if err := config.ValidateRoutingBudgetStore(cfg.Routing.Admin.BudgetStore, false); err != nil {
		return fmt.Errorf("budget-store serve: %w", err)
	}
	secret, err := readStoreSecretFile(srv.SecretFile)
	if err != nil {
		return fmt.Errorf("budget-store serve: %w", err)
	}
	keys, err := budgetstore.DeriveKeys(secret)
	clear(secret)
	if err != nil {
		return fmt.Errorf("budget-store serve: %w", err)
	}
	tlsConfig, err := budgetstore.ServerTLSConfig(srv.TLSCertFile, srv.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("budget-store serve: %w", err)
	}
	store, err := budgetstore.OpenStore(srv.DBPath)
	if err != nil {
		return fmt.Errorf("budget-store serve: %w", err)
	}
	defer store.Close()
	rate := srv.RateLimitPerMinute
	if rate == 0 {
		rate = config.RoutingBudgetStoreDefaultRate
	}
	server := budgetstore.NewServer(srv.Listen, &budgetstore.Handler{Store: store, Keys: keys, Limit: budgetstore.RateLimiter(rate)}, tlsConfig)

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Hour)
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
	fmt.Fprintf(cmd.OutOrStdout(), "budget store serving HTTPS on %s\n", srv.Listen)
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

// readStoreSecretFile reads the tenant secret: base64 of 32 bytes, in a
// file only its owner may read (POSIX mode 0600 or tighter).
func readStoreSecretFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("secret_file cannot be read")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secret_file %s is readable by others (mode %o); chmod 600 it", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("secret_file cannot be read")
	}
	secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	clear(raw)
	if err != nil || len(secret) != budgetstore.SecretBytes {
		return nil, errors.New("secret_file must hold the tenant secret: base64 of 32 bytes")
	}
	return secret, nil
}

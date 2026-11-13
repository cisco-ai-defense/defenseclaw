// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

var budgetStoreSecretPath string

var budgetStoreDeriveCmd = &cobra.Command{
	Use:   "derive-auth-key",
	Short: "Print the store's key file content from the tenant secret",
	Long: `Reads the tenant secret (base64 of 32 bytes; the value devices hold as
the protected credential routing-budget-store-key) from --secret-file and
prints the store's key: the request-signing key only. Put the output in the
store host's secret_file. The store never holds the tenant secret itself,
so it cannot compute the keyed hash of a name.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := readOwnerOnlyFile(budgetStoreSecretPath)
		if err != nil {
			return fmt.Errorf("derive-auth-key: %w", err)
		}
		secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		clear(raw)
		if err != nil || len(secret) != budgetstore.SecretBytes {
			return errors.New("derive-auth-key: the secret file must hold base64 of 32 bytes")
		}
		keys, err := budgetstore.DeriveKeys(secret)
		clear(secret)
		if err != nil {
			return fmt.Errorf("derive-auth-key: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), budgetstore.AuthKeyPrefix+base64.StdEncoding.EncodeToString(keys.AuthKey()))
		return nil
	},
}

func init() {
	budgetStoreServeCmd.Flags().StringVar(&budgetStoreConfigPath, "config", "", "config.yaml with routing.admin.budget_store.server (required)")
	budgetStoreDeriveCmd.Flags().StringVar(&budgetStoreSecretPath, "secret-file", "", "file with the tenant secret (owner-only)")
	_ = budgetStoreDeriveCmd.MarkFlagRequired("secret-file")
	budgetStoreCmd.AddCommand(budgetStoreServeCmd, budgetStoreDeriveCmd)
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
	keys, err := readStoreAuthKey(srv.SecretFile)
	if err != nil {
		return fmt.Errorf("budget-store serve: %w", err)
	}
	if _, err := readOwnerOnlyFile(srv.TLSKeyFile); err != nil {
		return fmt.Errorf("budget-store serve: tls_key_file: %w", err)
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
	// A high pre-authentication guard per address (many devices may share one
	// behind NAT or a load balancer) and the configured limit per writer.
	server := budgetstore.NewServer(srv.Listen, &budgetstore.Handler{Store: store, Keys: keys,
		PreAuth: budgetstore.RateLimiter(rate * 20), Writer: budgetstore.RateLimiter(rate)}, tlsConfig)

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

// readStoreAuthKey reads the store's key file: the auth key written by
// derive-auth-key. A raw tenant secret is refused: the store must not hold
// the subject-hash key.
func readStoreAuthKey(path string) (budgetstore.Keys, error) {
	raw, err := readOwnerOnlyFile(path)
	if err != nil {
		return budgetstore.Keys{}, fmt.Errorf("secret_file: %w", err)
	}
	defer clear(raw)
	text := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(text, budgetstore.AuthKeyPrefix) {
		return budgetstore.Keys{}, errors.New("secret_file must hold the output of budget-store derive-auth-key, not the tenant secret")
	}
	auth, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, budgetstore.AuthKeyPrefix))
	if err != nil {
		return budgetstore.Keys{}, errors.New("secret_file holds a damaged auth key; run budget-store derive-auth-key again")
	}
	defer clear(auth)
	return budgetstore.AuthKeys(auth)
}

// readOwnerOnlyFile reads a key file that is not a symlink, is owned by the
// user running the store and is readable by that user only (POSIX), or that
// only LocalSystem and Administrators may read (Windows).
func readOwnerOnlyFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("no file named")
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
		return nil, errors.New("must be owned by the account that runs the store")
	}
	return io.ReadAll(io.LimitReader(f, 64<<10))
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseDiscoveryReadRecord is replaceable in tests (the spool records
// must be root-owned).
var enterpriseDiscoveryReadRecord = inventory.ReadUserScanRecord

// newUnixDiscoveryCommand is `enterprise linux|macos discovery`: a read-only
// view of the AI Discovery inventory (agents, skills, MCP servers, plugins,
// running AI processes) the hook guardian's per-user scans recorded for each
// enrolled account. Before it the data was only in root-only JSON, behind
// the gateway API's token or in exported telemetry (GAP-1144).
func newUnixDiscoveryCommand(platform string) *cobra.Command {
	var user string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "discovery",
		Short: "Show each enrolled account's AI Discovery inventory: agents, skills, MCP servers, processes (read-only)",
		Long: `Show the AI Discovery inventory the hook guardian's per-user scans recorded
for each enrolled account: AI agents and apps, skills, MCP servers, plugins
and running AI processes (runtime discovery). It reads the guardian's spool
(ai-discovery/ in the authorization ledger) and changes nothing. Run as root.

The records exist only while ai_discovery.enabled is true in the deployment
config. Skills and MCP servers are inventoried here; a managed deployment
does not run the skill or MCP scanners.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			goos := platform
			if platform == "macos" {
				goos = "darwin"
			}
			if runtime.GOOS != goos {
				return invalidLifecycleArguments(fmt.Errorf("`enterprise %s discovery` reads %s hosts; this host is %s", platform, goos, runtime.GOOS))
			}
			layout, err := managed.StandaloneLayoutFor(goos)
			if err != nil {
				return withExitCode(err, enterprisestatus.UnixExitFailure)
			}
			dir := filepath.Join(layout.GuardianAuthDir, inventory.UserScanDirName)
			if err := writeEnterpriseDiscovery(cmd.OutOrStdout(), dir, user, asJSON); err != nil {
				return withExitCode(err, enterprisestatus.UnixExitFailure)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "list one account's signals (account name or uid)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print every record as JSON")
	return cmd
}

type enterpriseDiscoveryAccount struct {
	User      string               `json:"user"`
	UID       int                  `json:"uid"`
	UpdatedAt time.Time            `json:"updated_at"`
	Result    string               `json:"result"`
	Signals   []inventory.AISignal `json:"signals"`
}

type enterpriseDiscoveryReport struct {
	Spool    string                       `json:"spool"`
	Accounts []enterpriseDiscoveryAccount `json:"accounts"`
	Errors   []string                     `json:"errors,omitempty"`
}

func writeEnterpriseDiscovery(w io.Writer, dir, user string, asJSON bool) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		entries = nil
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("read %s: permission denied; run as root", dir)
	case err != nil:
		return err
	}
	report := enterpriseDiscoveryReport{Spool: dir, Accounts: []enterpriseDiscoveryAccount{}}
	for _, entry := range entries {
		uid, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || uid == "" || strings.Trim(uid, "0123456789") != "" {
			continue // pass.json and anything else that is not a record
		}
		record, err := enterpriseDiscoveryReadRecord(filepath.Join(dir, entry.Name()))
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("uid %s: %v", uid, err))
			continue
		}
		if user != "" && user != record.User && user != strconv.Itoa(record.UID) {
			continue
		}
		report.Accounts = append(report.Accounts, enterpriseDiscoveryAccount{
			User: record.User, UID: record.UID, UpdatedAt: record.UpdatedAt,
			Result: record.Report.Summary.Result, Signals: record.Report.Signals,
		})
	}
	sort.Slice(report.Accounts, func(i, j int) bool { return report.Accounts[i].UID < report.Accounts[j].UID })
	if user != "" && len(report.Accounts) == 0 && len(report.Errors) == 0 {
		return fmt.Errorf("no AI Discovery record for account %q in %s; the account is not enrolled or has not been scanned yet", user, dir)
	}
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	fmt.Fprintf(w, "AI Discovery inventory from the hook guardian's per-user scans (%s)\n", dir)
	if len(report.Accounts) == 0 && len(report.Errors) == 0 {
		fmt.Fprintln(w, "  no records yet: ai_discovery is off in the deployment config, no account is enrolled, or the first scan has not finished")
	}
	for _, account := range report.Accounts {
		fmt.Fprintf(w, "%s (uid %d): scanned %s, result %s, %d signal(s)\n",
			account.User, account.UID, account.UpdatedAt.UTC().Format(time.RFC3339), account.Result, len(account.Signals))
		if user == "" {
			counts := map[string]int{}
			for _, signal := range account.Signals {
				counts[signal.Category]++
			}
			categories := make([]string, 0, len(counts))
			for category, count := range counts {
				categories = append(categories, fmt.Sprintf("%s %d", category, count))
			}
			sort.Strings(categories)
			if len(categories) > 0 {
				fmt.Fprintf(w, "  %s\n", strings.Join(categories, ", "))
			}
			continue
		}
		table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "  CATEGORY\tNAME\tCONNECTOR\tSTATE\tLAST SEEN\tFILES")
		for _, signal := range account.Signals {
			connector := signal.SupportedConnector
			if connector == "" {
				connector = "-"
			}
			files := strings.Join(signal.Basenames, ",")
			if files == "" {
				files = "-"
			}
			fmt.Fprintf(table, "  %s\t%s\t%s\t%s\t%s\t%s\n", signal.Category, signal.Name, connector, signal.State,
				signal.LastSeen.UTC().Format(time.RFC3339), files)
		}
		_ = table.Flush()
	}
	for _, problem := range report.Errors {
		fmt.Fprintf(w, "unreadable record: %s\n", problem)
	}
	if user == "" && len(report.Accounts) > 0 {
		fmt.Fprintln(w, "Run with --user <account> to list one account's signals, or --json for every field.")
	}
	return nil
}

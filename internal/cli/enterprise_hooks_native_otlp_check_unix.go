//go:build !windows

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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// enterpriseHookNativeOTLPConnectors are the connectors whose own user
// configuration can carry a native OTLP exporter.
var enterpriseHookNativeOTLPConnectors = []string{"codex", "claudecode"}

// enterpriseHookWorkerNativeOTLPReport is one connector's native_otlp_check
// answer: the exporter entries (field names only) that carry a DefenseClaw
// credential, or why the configuration could not be checked.
type enterpriseHookWorkerNativeOTLPReport struct {
	Path    string   `json:"path,omitempty"`
	Entries []string `json:"entries,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// runEnterpriseHookWorkerNativeOTLPCheck runs with the target user's uid.
// It reads the configurations the guardian foreign cleanup would edit
// (removeManagedUserNativeOTLP) the same way and writes nothing.
func runEnterpriseHookWorkerNativeOTLPCheck(request enterpriseHookWorkerRequest) enterpriseHookWorkerResponse {
	if !request.Standalone {
		return enterpriseHookWorkerResponse{Error: "the native OTLP check requires the standalone guardian"}
	}
	home := filepath.Clean(request.Home)
	reports := map[string]enterpriseHookWorkerNativeOTLPReport{}
	for _, name := range request.Connectors {
		if connector.UserNativeOTLPBackupName(name) == "" {
			reports[name] = enterpriseHookWorkerNativeOTLPReport{Error: "connector has no native OTLP exporter"}
			continue
		}
		opts := enterprisehooks.InstallOptions{ConnectorName: name, UserHome: home, OwnerUID: request.UID, OwnerGID: request.GID,
			DataDir: filepath.Join(home, ".defenseclaw")}
		entries, err := managedUserNativeOTLP(opts, request.ProductCredentials, false)
		report := enterpriseHookWorkerNativeOTLPReport{Path: connector.UserNativeOTLPConfigPathFor(name, home), Entries: entries}
		if err != nil {
			report.Error = err.Error()
		}
		reports[name] = report
	}
	return enterpriseHookWorkerResponse{NativeOTLP: reports}
}

// enterpriseHookNativeOTLPFinding is one account's configuration that
// carries a DefenseClaw credential in a native OTLP exporter, or that the
// check could not read.
type enterpriseHookNativeOTLPFinding struct {
	User      string   `json:"user"`
	Connector string   `json:"connector"`
	Path      string   `json:"path"`
	Entries   []string `json:"entries,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// enterpriseHookNativeOTLPCheckReport is the output of
// `enterprise hooks native-otlp-check`.
type enterpriseHookNativeOTLPCheckReport struct {
	OK       bool                              `json:"ok"`
	Accounts int                               `json:"accounts"`
	Findings []enterpriseHookNativeOTLPFinding `json:"findings"`
	// Unchecked names accounts whose home did not answer or changed.
	Unchecked []string `json:"unchecked,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// checkEnterpriseHookStandaloneNativeOTLP reads, as each user, the own
// Codex and Claude Code configuration of every account the guardian foreign
// cleanup covers, and names the native OTLP exporters there that carry the
// product gateway token. Managed Unix verify reports them: the guardian
// removes a removable one on its next pass, and one it cannot edit stays
// (GAP-1360, the check managed Windows verify runs).
func checkEnterpriseHookStandaloneNativeOTLP(ctx context.Context) enterpriseHookNativeOTLPCheckReport {
	report := enterpriseHookNativeOTLPCheckReport{Findings: []enterpriseHookNativeOTLPFinding{}}
	if cfg == nil || !cfg.StandaloneEnterprise() {
		report.Error = "the native OTLP check is available only for managed standalone Unix"
		return report
	}
	accounts, err := enterpriseHookLoadEligibleAccounts(enterprisehooks.UnixEligibleAccountsPath(enterpriseHookManifest))
	if err != nil {
		report.Error = "eligible accounts: " + err.Error()
		return report
	}
	if enterpriseHookManifestEnrollment() {
		manifest, _, err := enterprisehooks.LoadManifestWithSHA256(enterpriseHookManifest)
		if err != nil {
			report.Error = "manifest: " + err.Error()
			return report
		}
		accounts = enterprisehooks.ManifestEnrolledAccounts(accounts, manifest)
	}
	report.Accounts = len(accounts)
	credentials := enterpriseHookStandaloneProductCredentialDigests()
	if len(credentials) == 0 {
		// No product token, so no exporter can carry one.
		report.OK = true
		return report
	}
	jobs := []enterpriseHookWorkerJob{}
	for _, account := range accounts {
		check := enterpriseHookCheckHome(account.Home, account.UID)
		if check.State != enterprisehooks.HomeAvailable ||
			(account.HomeInode != 0 && check.Inode != 0 && account.HomeInode != check.Inode) {
			report.Unchecked = append(report.Unchecked, account.User)
			continue
		}
		var names []string
		for _, name := range enterpriseHookNativeOTLPConnectors {
			if _, err := os.Lstat(connector.UserNativeOTLPConfigPathFor(name, account.Home)); !errors.Is(err, os.ErrNotExist) {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			continue
		}
		jobs = append(jobs, enterpriseHookWorkerJob{
			Account: enterpriseHookWorkerAccount{UID: account.UID, GID: account.GID, User: account.User, Home: account.Home},
			Request: enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpNativeOTLPCheck, Standalone: true,
				Connectors: names, ProductCredentials: credentials},
		})
	}
	for _, outcome := range runEnterpriseHookWorkerPool(ctx, jobs, enterpriseHookWorkerParallelism) {
		user := outcome.Job.Account.User
		for _, name := range outcome.Job.Request.Connectors {
			path := connector.UserNativeOTLPConfigPathFor(name, outcome.Job.Account.Home)
			answer, ok := outcome.Response.NativeOTLP[name]
			reason := ""
			switch {
			case outcome.Err != nil:
				reason = outcome.Err.Error()
			case outcome.Response.Error != "":
				reason = outcome.Response.Error
			case !ok:
				reason = errEnterpriseHookWorkerNoResult.Error()
			case answer.Error != "":
				reason = answer.Error
			}
			if reason != "" {
				report.Findings = append(report.Findings, enterpriseHookNativeOTLPFinding{User: user, Connector: name, Path: path,
					Error: boundedString(reason, 512)})
				continue
			}
			if len(answer.Entries) != 0 {
				report.Findings = append(report.Findings, enterpriseHookNativeOTLPFinding{User: user, Connector: name, Path: path,
					Entries: boundedStrings(answer.Entries, 32)})
			}
		}
	}
	sort.SliceStable(report.Findings, func(i, j int) bool {
		if report.Findings[i].User != report.Findings[j].User {
			return report.Findings[i].User < report.Findings[j].User
		}
		return report.Findings[i].Connector < report.Findings[j].Connector
	})
	report.OK = true
	return report
}

// enterpriseHooksNativeOTLPCheckCmd is the read-only check managed Unix
// verify runs (hidden: not an administrator command).
var enterpriseHooksNativeOTLPCheckCmd = &cobra.Command{
	Use:    "native-otlp-check",
	Short:  "Name user native OTLP exporters that carry a DefenseClaw credential",
	Hidden: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if os.Geteuid() != 0 {
			return errors.New("enterprise hooks native-otlp-check must run as root")
		}
		report := checkEnterpriseHookStandaloneNativeOTLP(cmd.Context())
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
			return err
		}
		if !report.OK {
			return fmt.Errorf("enterprise hooks native-otlp-check: %s", report.Error)
		}
		return nil
	},
}

func init() {
	enterpriseHooksNativeOTLPCheckCmd.Flags().StringVar(&enterpriseHookManifest, "manifest", defaultEnterpriseHookManifest,
		"YAML manifest of per-user hook targets")
	enterpriseHooksNativeOTLPCheckCmd.Flags().BoolVar(&enterpriseHookJSON, "json", true, "Emit machine-readable JSON (always)")
	enterpriseHooksCmd.AddCommand(enterpriseHooksNativeOTLPCheckCmd)
}

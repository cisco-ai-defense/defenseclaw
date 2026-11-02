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
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseHookGatewayPorts lists the loopback ports a managed gateway
// binds: only the API port. In managed_enterprise mode the guardrail proxy
// port is never bound (hooks talk to the API), so checking it would report
// whatever else happens to listen there.
func enterpriseHookGatewayPorts(c *config.Config) []int {
	if c == nil {
		return nil
	}
	return []int{c.Gateway.APIPort}
}

// newEnterpriseHookHostChecks returns the guardian's per-tick host checks
// (prerequisites and advisory code integrity) in managed mode, nil otherwise.
// They run on the reconcile loop itself, never on another goroutine, because
// per-user work changes the process's effective uid.
func newEnterpriseHookHostChecks(c *config.Config) *managed.HostChecks {
	if c == nil || !managed.IsManagedEnterprise(c.DeploymentMode) {
		return nil
	}
	return managed.NewHostChecks(managed.HostCheckOptions{
		InstallRoot: strings.TrimSpace(os.Getenv("DEFENSECLAW_HOME")),
		Ports:       enterpriseHookGatewayPorts(c),
	})
}

var (
	enterprisePrereqInstallRoot string
	enterprisePrereqPorts       string
	enterprisePrereqExecProbe   bool
	enterprisePrereqJSON        bool
)

// enterprisePrereqCheckCmd lets the installer run the same host checks the
// guardian runs each tick. It needs no config and always exits 0: a missing
// prerequisite is logged (`defenseclaw_prereq check=<id> remedy=<text>` and
// code integrity lines on stderr) and never fails install or purge.
var enterprisePrereqCheckCmd = &cobra.Command{
	Use:    "prereq-check",
	Short:  "Report missing host prerequisites and code integrity findings",
	Hidden: true,
	Args:   cobra.NoArgs,
	// The checks must run even when config.yaml is missing or drifted, so the
	// root config initializer is not chained.
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	RunE: func(cmd *cobra.Command, _ []string) error {
		checks := managed.NewHostChecks(managed.HostCheckOptions{
			InstallRoot: strings.TrimSpace(enterprisePrereqInstallRoot),
			Ports:       parseEnterprisePrereqPorts(enterprisePrereqPorts),
			ExecProbe:   enterprisePrereqExecProbe,
		})
		prereqs, integrity := checks.Run()
		if enterprisePrereqJSON {
			type finding struct {
				Check  string `json:"check,omitempty"`
				Reason string `json:"reason,omitempty"`
				Path   string `json:"path,omitempty"`
				Detail string `json:"detail,omitempty"`
				Remedy string `json:"remedy,omitempty"`
			}
			out := struct {
				Prerequisites []finding `json:"prerequisites"`
				CodeIntegrity []finding `json:"code_integrity"`
			}{Prerequisites: []finding{}, CodeIntegrity: []finding{}}
			for _, p := range prereqs {
				out.Prerequisites = append(out.Prerequisites, finding{Check: p.Check, Path: p.Path, Detail: p.Detail, Remedy: p.Remedy})
			}
			for _, f := range integrity {
				out.CodeIntegrity = append(out.CodeIntegrity, finding{Reason: f.Reason, Path: f.Path, Detail: f.Detail})
			}
			_ = json.NewEncoder(cmd.OutOrStdout()).Encode(out)
		}
		return nil
	},
}

// parseEnterprisePrereqPorts reads a comma-separated port list; entries that
// are not ports are ignored.
func parseEnterprisePrereqPorts(value string) []int {
	var ports []int
	for _, field := range strings.Split(value, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(field))
		if err == nil && port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return ports
}

func init() {
	enterprisePrereqCheckCmd.Flags().StringVar(&enterprisePrereqInstallRoot, "install-root", "", "managed install root (default: the platform install root)")
	enterprisePrereqCheckCmd.Flags().StringVar(&enterprisePrereqPorts, "ports", "", "comma-separated gateway loopback ports to check (API, guardrail)")
	enterprisePrereqCheckCmd.Flags().BoolVar(&enterprisePrereqExecProbe, "exec-probe", false, "run the gateway binary with --version (before bootstrap)")
	enterprisePrereqCheckCmd.Flags().BoolVar(&enterprisePrereqJSON, "json", false, "also print the findings as JSON on stdout")
	enterpriseCmd.AddCommand(enterprisePrereqCheckCmd)
}

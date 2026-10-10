// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// codeUnitDropIn names local systemd drop-ins on the DefenseClaw units that
// keep the units' identity, sandbox and inputs (a site proxy, say).
const codeUnitDropIn = "unit_drop_in"

// dropInReporter is implemented by service managers that list the drop-in
// files systemd merged into a unit.
type dropInReporter interface {
	DropInPaths(ctx context.Context, unit Unit) []string
}

// DropInPaths lists the drop-ins systemd merged into the unit, global ones
// (service.d) included.
func (m *systemdManager) DropInPaths(ctx context.Context, unit Unit) []string {
	return strings.Fields(m.properties(ctx, unit.Name, "DropInPaths")["DropInPaths"])
}

// dropInKeepKeys are the drop-in settings that leave a DefenseClaw unit's
// identity, sandbox and inputs as installed: unit ordering and text,
// resource limits, restart and timeout tuning, and environment for the host
// (proxies, CA bundles). Any other setting in a drop-in DefenseClaw did not
// write changes who the unit runs as, what it runs or what it can reach.
var dropInKeepKeys = map[string]bool{
	"Description": true, "Documentation": true, "After": true, "Before": true, "Wants": true,
	"Environment": true,
	"Nice":        true, "CPUWeight": true, "CPUQuota": true, "CPUShares": true, "AllowedCPUs": true, "CPUAffinity": true,
	"MemoryMax": true, "MemoryHigh": true, "MemoryLow": true, "MemoryMin": true, "MemoryLimit": true, "MemorySwapMax": true,
	"TasksMax": true, "IOWeight": true, "IOSchedulingClass": true, "IOSchedulingPriority": true,
	"LimitNOFILE": true, "LimitNPROC": true, "LimitCORE": true, "LimitMEMLOCK": true, "OOMScoreAdjust": true,
	"Restart": true, "RestartSec": true, "TimeoutSec": true, "TimeoutStartSec": true, "TimeoutStopSec": true,
	"StartLimitIntervalSec": true, "StartLimitBurst": true,
	"LogLevelMax": true, "LogRateLimitIntervalSec": true, "LogRateLimitBurst": true, "SyslogIdentifier": true,
}

// dropInEnvironmentRefused reports an Environment= variable a drop-in must
// not set: DefenseClaw's own pins (the config, the data directory, the
// deployment mode) and loader variables.
func dropInEnvironmentRefused(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "DEFENSECLAW_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "GODEBUG")
}

// dropInEnvironmentReset names an Environment= with no assignment: systemd
// then drops every Environment= set before it, the managed pins of the unit
// (DEFENSECLAW_CONFIG, DEFENSECLAW_HOME, the deployment mode) included
// (GAP-1380).
const dropInEnvironmentReset = "an empty Environment=, which clears the unit's DEFENSECLAW_* pins"

// dropInChanges returns the settings of a drop-in that change what the unit
// is (Key, Environment=NAME for a refused variable, or
// dropInEnvironmentReset).
func dropInChanges(data []byte) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if !dropInKeepKeys[key] {
			seen[key] = true
			continue
		}
		if key != "Environment" {
			continue
		}
		assignments := strings.Fields(strings.NewReplacer(`"`, " ", "'", " ").Replace(value))
		if len(assignments) == 0 {
			seen[dropInEnvironmentReset] = true
		}
		for _, assignment := range assignments {
			if name, _, ok := strings.Cut(assignment, "="); ok && dropInEnvironmentRefused(name) {
				seen["Environment="+name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for key := range seen {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// unitDropIns reviews the drop-ins of the DefenseClaw units that the
// deployment did not write (GAP-0474). problems are the drop-ins that change
// a unit's identity, sandbox or inputs (User=root, ProtectHome=false, another
// DEFENSECLAW_CONFIG), each named with the settings; overrides are the
// others, which the docs allow for host-specific settings.
func (l *lifecycle) unitDropIns(ctx context.Context, record *Deployment) (problems, overrides []string) {
	env := l.env
	reporter, ok := env.Services.(dropInReporter)
	if !ok {
		return nil, nil
	}
	listed := map[string]bool{}
	for _, unit := range env.Services.Units() {
		for _, path := range reporter.DropInPaths(ctx, unit) {
			if _, ours := record.Files[path]; ours || listed[path] {
				continue
			}
			listed[path] = true
			data, err := readBounded(env.P(path), maxInputBytes)
			if err != nil {
				problems = append(problems, fmt.Sprintf("cannot read the drop-in %s on %s: %v", path, unit.Name, err))
				continue
			}
			if changes := dropInChanges(data); len(changes) > 0 {
				problems = append(problems, fmt.Sprintf("the drop-in %s changes %s (%s), which DefenseClaw does not allow; remove it or those settings, run `systemctl daemon-reload` and `%s`",
					path, unit.Name, strings.Join(changes, ", "), env.lifecycleCommand("repair")))
				continue
			}
			overrides = append(overrides, path)
		}
	}
	return problems, overrides
}

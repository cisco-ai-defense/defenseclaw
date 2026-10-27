// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

const bundleSessionProcessCap = 4096
const bundleSessionScanTimeout = 3 * time.Second

// UnprotectedSessions checks active managed agent runs against the settings
// files those agents loaded when they started. A bounded or unprivileged scan
// reports unknown instead of claiming there are no old sessions.
func (e *Env) UnprotectedSessions(parent context.Context) enterprisestatus.SessionRestartStatus {
	privileged := e.Geteuid != nil && e.Geteuid() == 0
	if !privileged {
		return enterprisestatus.ScanSessions(nil, nil, false)
	}
	ctx, cancel := context.WithTimeout(parent, bundleSessionScanTimeout)
	defer cancel()
	aliases, err := bundleAgentAliases()
	if err != nil {
		return enterprisestatus.SessionRestartStatus{State: "unknown", Entries: []enterprisestatus.SessionEntry{}, Reason: err.Error()}
	}
	var processes []enterprisestatus.SessionProcess
	switch e.GOOS {
	case "linux":
		processes, err = e.bundleLinuxProcesses(ctx, aliases)
	case "darwin":
		processes, err = e.bundleDarwinProcesses(ctx, aliases)
	default:
		err = errors.New("unsupported platform")
	}
	if err != nil || ctx.Err() != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return enterprisestatus.SessionRestartStatus{State: "unknown", Entries: []enterprisestatus.SessionEntry{}, Reason: err.Error()}
	}
	changed, err := e.bundleManagedSettingsTimes()
	if err != nil {
		return enterprisestatus.SessionRestartStatus{State: "unknown", Entries: []enterprisestatus.SessionEntry{}, Reason: err.Error()}
	}
	return enterprisestatus.ScanSessions(func() ([]enterprisestatus.SessionProcess, error) { return processes, nil }, changed, true)
}

func bundleAgentAliases() (map[string]string, error) {
	catalog, err := inventory.LoadAISignatures()
	if err != nil {
		return nil, err
	}
	aliases := map[string]string{}
	for _, sig := range catalog {
		if sig.SupportedConnector == "" {
			continue
		}
		for _, name := range append(append([]string{}, sig.ProcessNames...), sig.BinaryNames...) {
			aliases[strings.ToLower(strings.TrimSuffix(filepath.Base(name), ".exe"))] = sig.SupportedConnector
		}
	}
	return aliases, nil
}

func bundleAgentName(name string, aliases map[string]string) string {
	name = strings.ToLower(strings.TrimSuffix(filepath.Base(name), ".exe"))
	if connector := aliases[name]; connector != "" {
		return connector
	}
	return aliases[strings.TrimSuffix(name, "-agent")]
}

// bundleManagedSettingsTimes dates the managed settings of each connector
// the installed config enables. A session of an agent DefenseClaw does not
// manage on this device loads no DefenseClaw hook before or after a bundle,
// so no restart brings it under enforcement: it is not counted (sidecar F04;
// management-agent.md 4.3 counts sessions running "when a bundle enabled or
// changed its connector").
func (e *Env) bundleManagedSettingsTimes() (map[string]time.Time, error) {
	raw, err := readBounded(e.P(e.Layout.ConfigPath), maxInputBytes)
	if err != nil {
		return nil, fmt.Errorf("read the installed config for its enabled connectors: %w", err)
	}
	cfg, err := e.loadConfigCandidate(raw)
	if err == nil && cfg == nil {
		err = errors.New("empty config")
	}
	if err != nil {
		return nil, fmt.Errorf("load the installed config for its enabled connectors: %w", err)
	}
	enabled := enterprisehooks.EffectiveUnixHookConnectors(cfg, connector.NewDefaultRegistry())
	changed := map[string]time.Time{}
	opts := enterprisepolicy.LayoutOptions(e.Layout, "", "")
	opts.Root = e.Root
	for _, name := range enabled {
		target, ok := enterprisepolicy.TargetFor(name)
		if !ok {
			continue
		}
		paths, err := target.Paths(opts)
		if err != nil {
			continue
		}
		for _, path := range paths {
			// Claude's first path is an administrator file; its second path
			// is DefenseClaw's hook drop-in.
			if name == enterprisepolicy.ConnectorClaudeCode && !strings.HasSuffix(path, enterprisepolicy.DefenseClawDropInName) {
				continue
			}
			if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.ModTime().After(changed[name]) {
				changed[name] = info.ModTime()
			}
		}
	}
	// A policy applied-at is the fallback on a device whose vendor policy
	// file cannot be dated (for example a legacy receipt after migration).
	if raw, err := os.ReadFile(e.P(filepath.Join(e.Layout.LifecycleDir, enterprisestatus.PolicyStateFileName))); err == nil {
		var state enterprisestatus.PolicyStateRecord
		if json.Unmarshal(raw, &state) == nil {
			if at, err := time.Parse(time.RFC3339Nano, state.AppliedAt); err == nil {
				for _, name := range enabled {
					if changed[name].IsZero() {
						changed[name] = at
					}
				}
			}
		}
	}
	return changed, nil
}

func (e *Env) bundleLinuxProcesses(ctx context.Context, aliases map[string]string) ([]enterprisestatus.SessionProcess, error) {
	boot, err := e.linuxBootSeconds()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(e.P("/proc"))
	if err != nil {
		return nil, err
	}
	var out []enterprisestatus.SessionProcess
	seen := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		seen++
		if seen > bundleSessionProcessCap {
			return nil, errors.New("process cap reached")
		}
		dir := filepath.Join(e.P("/proc"), entry.Name())
		cmdline, err := readBounded(filepath.Join(dir, "cmdline"), 64<<10)
		if err != nil || len(cmdline) == 0 {
			continue
		}
		argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		agent := agentCLIOf(argv)
		connector := bundleAgentName(agent, aliases)
		if connector == "" {
			continue
		}
		data, err := readBounded(filepath.Join(dir, "stat"), 64<<10)
		if err != nil {
			continue
		}
		end := bytes.LastIndexByte(data, ')')
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) < 20 {
			continue
		}
		ticks, err := strconv.ParseInt(fields[19], 10, 64)
		if err != nil {
			continue
		}
		info, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		who := strconv.FormatUint(uint64(owner.Uid), 10)
		if account, err := user.LookupId(who); err == nil {
			who = account.Username
		}
		out = append(out, enterprisestatus.SessionProcess{PID: pid, User: who, Agent: connector,
			StartedAt: time.Unix(boot, 0).Add(time.Duration(ticks) * time.Second / 100)})
	}
	return out, nil
}

func (e *Env) bundleDarwinProcesses(ctx context.Context, aliases map[string]string) ([]enterprisestatus.SessionProcess, error) {
	result, err := e.Runner.Run(ctx, "ps", "-axww", "-o", "pid=,user=,lstart=,comm=")
	if err != nil {
		return nil, err
	}
	var out []enterprisestatus.SessionProcess
	for i, line := range strings.Split(string(result.Stdout), "\n") {
		if i > bundleSessionProcessCap {
			return nil, errors.New("process cap reached")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		started, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(fields[2:7], " "), time.Local)
		if err != nil {
			continue
		}
		if !agentCLINames[filepath.Base(fields[7])] {
			continue
		}
		if connector := bundleAgentName(fields[7], aliases); connector != "" {
			out = append(out, enterprisestatus.SessionProcess{PID: pid, User: fields[1], Agent: connector, StartedAt: started})
		}
	}
	return out, nil
}

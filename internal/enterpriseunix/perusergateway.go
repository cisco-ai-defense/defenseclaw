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
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// codePerUserGatewayRunning names an account that still runs its own
// per-user DefenseClaw gateway beside the managed deployment: a per-user
// install from before the deployment that nothing stopped (GAP-1474).
const codePerUserGatewayRunning = "per_user_gateway_running"

// gatewayProcess is a running defenseclaw-gateway process.
type gatewayProcess struct {
	PID  int
	UID  int
	Path string
}

// gatewayProcesses lists the running defenseclaw-gateway processes other
// than the managed binary: on Linux from /proc/<pid>/exe, on macOS from ps
// and the executable path the kernel recorded for each candidate (as root
// both see every process). ps reports argv[0], so the managed binary run by
// its bare name (an admin's repair or status) looks like any other
// defenseclaw-gateway there (GAP-2245).
func (e *Env) gatewayProcesses(ctx context.Context) []gatewayProcess {
	var all []gatewayProcess
	switch e.GOOS {
	case "linux":
		entries, _ := os.ReadDir(e.P("/proc"))
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			dir := filepath.Join(e.P("/proc"), entry.Name())
			exe, err := os.Readlink(filepath.Join(dir, "exe"))
			if err != nil {
				continue
			}
			info, err := os.Lstat(dir)
			if err != nil {
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			all = append(all, gatewayProcess{PID: pid, UID: int(stat.Uid), Path: strings.TrimSuffix(exe, " (deleted)")})
		}
	case "darwin":
		result, err := e.Runner.Run(ctx, "ps", "-axo", "pid=,uid=,comm=")
		if err != nil && len(result.Stdout) == 0 {
			return nil
		}
		for _, line := range strings.Split(string(result.Stdout), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			pid, pidErr := strconv.Atoi(fields[0])
			uid, uidErr := strconv.Atoi(fields[1])
			if pidErr != nil || uidErr != nil {
				continue
			}
			path := strings.Join(fields[2:], " ")
			if filepath.Base(path) != "defenseclaw-gateway" {
				continue
			}
			if exe, err := e.ProcessExecPath(pid); err == nil && filepath.IsAbs(exe) {
				path = exe
			} else if !filepath.IsAbs(path) {
				// Neither names the binary: it may be the managed one.
				continue
			}
			if resolved, err := filepath.EvalSymlinks(path); err == nil {
				path = resolved
			}
			all = append(all, gatewayProcess{PID: pid, UID: uid, Path: path})
		}
	}
	managedGateway := filepath.Join(e.Layout.BinDir, "defenseclaw-gateway")
	resolvedManaged, err := filepath.EvalSymlinks(managedGateway)
	if err != nil {
		resolvedManaged = managedGateway
	}
	var out []gatewayProcess
	for _, process := range all {
		path := filepath.Clean(process.Path)
		if filepath.Base(path) != "defenseclaw-gateway" || path == managedGateway || path == resolvedManaged || process.PID == os.Getpid() {
			continue
		}
		out = append(out, process)
	}
	return out
}

// describePerUserGateways warns, per account, about per-user gateways that
// still run beside the managed deployment. The managed host refuses to
// start them again, but one started before the deployment keeps running
// with its own config and policy until it is stopped.
func (l *lifecycle) describePerUserGateways(ctx context.Context) {
	byUID := map[int][]string{}
	for _, process := range l.env.gatewayProcesses(ctx) {
		byUID[process.UID] = append(byUID[process.UID], strconv.Itoa(process.PID))
	}
	uids := make([]int, 0, len(byUID))
	for uid := range byUID {
		uids = append(uids, uid)
	}
	sort.Ints(uids)
	for _, uid := range uids {
		who := "uid " + strconv.Itoa(uid)
		if account, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			who = account.Username
		}
		pids := byUID[uid]
		l.result.AddWarning(codePerUserGatewayRunning, fmt.Sprintf(
			"user %s still runs a per-user DefenseClaw gateway beside the managed deployment (pid %s), with its own config and policy; "+
				"stop it with `kill %s` (this computer refuses to start it again) and have that user remove the per-user install with "+
				"`defenseclaw uninstall --binaries --yes`",
			who, strings.Join(pids, ", "), strings.Join(pids, " ")))
	}
}

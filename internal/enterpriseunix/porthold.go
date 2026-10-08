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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Another local account can bind the gateway API port (127.0.0.1:18970)
// while the DefenseClaw listener is down: on Linux while the socket unit is
// stopped, on macOS while the gateway job restarts. The /health probe then
// talks to that process, and a failed socket start only says "Job failed".
// The lifecycle names the process instead, so the administrator can stop it.

// portHolder is a process listening on the gateway API port.
type portHolder struct {
	PID  int
	UID  int
	User string
}

func (h portHolder) String() string {
	who := "uid " + strconv.Itoa(h.UID)
	if h.User != "" {
		who += ", " + h.User
	}
	if h.PID > 0 {
		return fmt.Sprintf("pid %d (%s)", h.PID, who)
	}
	return who
}

// apiPortHolders lists the processes listening on the gateway API port.
func (e *Env) apiPortHolders(ctx context.Context) []portHolder {
	_, portText, err := net.SplitHostPort(e.Layout.APIAddr)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil
	}
	var holders []portHolder
	switch e.GOOS {
	case "linux":
		holders = e.linuxPortHolders(port)
	case "darwin":
		holders = e.darwinPortHolders(ctx, port)
	}
	for index := range holders {
		if account, err := user.LookupId(strconv.Itoa(holders[index].UID)); err == nil {
			holders[index].User = account.Username
		}
	}
	return holders
}

// linuxListenAddrs are the /proc/net/tcp{,6} local addresses whose listener
// keeps the gateway from binding 127.0.0.1: the address itself and the
// wildcards.
var linuxListenAddrs = map[string]bool{
	"0100007F":                         true, // 127.0.0.1
	"00000000":                         true, // 0.0.0.0
	"00000000000000000000000000000000": true, // ::
	"0000000000000000FFFF00000100007F": true, // ::ffff:127.0.0.1
}

// linuxPortHolders reads the listening sockets from /proc/net/tcp and
// tcp6 and finds the processes holding them through /proc/<pid>/fd.
func (e *Env) linuxPortHolders(port int) []portHolder {
	inodes := map[string]int{} // socket inode -> uid
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := readBounded(e.P(table), 64<<20)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[3] != "0A" { // 0A: LISTEN
				continue
			}
			addr, portHex, ok := strings.Cut(fields[1], ":")
			if !ok || !linuxListenAddrs[strings.ToUpper(addr)] {
				continue
			}
			if value, err := strconv.ParseUint(portHex, 16, 16); err != nil || int(value) != port {
				continue
			}
			uid, err := strconv.Atoi(fields[7])
			if err != nil {
				continue
			}
			inodes[fields[9]] = uid
		}
	}
	if len(inodes) == 0 {
		return nil
	}
	var holders []portHolder
	found := map[string]bool{}
	entries, _ := os.ReadDir(e.P("/proc"))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(e.P("/proc"), entry.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(e.P("/proc"), entry.Name(), "fd", fd.Name()))
			inode, ok := strings.CutPrefix(target, "socket:[")
			if err != nil || !ok {
				continue
			}
			inode = strings.TrimSuffix(inode, "]")
			if uid, listening := inodes[inode]; listening {
				holders = append(holders, portHolder{PID: pid, UID: uid})
				found[inode] = true
				break
			}
		}
	}
	for inode, uid := range inodes {
		if !found[inode] {
			holders = append(holders, portHolder{UID: uid})
		}
	}
	return holders
}

// darwinPortHolders asks lsof (as root it sees every process) for the
// listeners on port.
func (e *Env) darwinPortHolders(ctx context.Context, port int) []portHolder {
	result, err := e.Runner.Run(ctx, "lsof", "-nP", "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fpu")
	if err != nil && len(result.Stdout) == 0 {
		return nil
	}
	var holders []portHolder
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if len(line) < 2 {
			continue
		}
		value, err := strconv.Atoi(line[1:])
		if err != nil {
			continue
		}
		switch line[0] {
		case 'p':
			holders = append(holders, portHolder{PID: value, UID: -1})
		case 'u':
			if len(holders) > 0 {
				holders[len(holders)-1].UID = value
			}
		}
	}
	return holders
}

// foreignAPIPortHolders lists the port holders that are not the DefenseClaw
// listener: PID 1 (the Linux socket unit), the gateway unit's process, or
// the service account.
func (l *lifecycle) foreignAPIPortHolders(ctx context.Context, serviceUID int) []portHolder {
	env := l.env
	gatewayPID := 0
	for _, unit := range env.Services.Units() {
		if unit.Kind == "gateway" {
			if status, err := env.Services.Status(ctx, unit); err == nil {
				gatewayPID = status.PID
			}
		}
	}
	var foreign []portHolder
	for _, holder := range env.apiPortHolders(ctx) {
		if holder.PID == 1 || (gatewayPID > 0 && holder.PID == gatewayPID) || (serviceUID > 0 && holder.UID == serviceUID) {
			continue
		}
		foreign = append(foreign, holder)
	}
	return foreign
}

// portHeldProblem describes foreign holders of the gateway API port, or "".
func (l *lifecycle) portHeldProblem(ctx context.Context, serviceUID int, servingHooks bool) string {
	foreign := l.foreignAPIPortHolders(ctx, serviceUID)
	if len(foreign) == 0 {
		return ""
	}
	names := make([]string, 0, len(foreign))
	for _, holder := range foreign {
		names = append(names, holder.String())
	}
	message := fmt.Sprintf("the gateway API port %s is held by %s, not by the DefenseClaw gateway", l.env.Layout.APIAddr, strings.Join(names, ", "))
	if servingHooks {
		message += "; the gateway serves hooks on its socket and keeps retrying the port"
	}
	return message + "; stop that process, then run `" + l.env.lifecycleCommand("repair") + "`"
}

// codeAPIPortHeld names a transaction refused before it changed anything
// because another process listens on the gateway API port (GAP-0366).
const codeAPIPortHeld = "api_port_held"

// apiPortPreflight describes another process listening on the gateway API
// port before a transaction changes anything, or "". A per-user gateway
// still running from before the deployment is the usual holder: the socket
// unit could not listen, so the install changed everything and then rolled
// back with activation_failed.
func (l *lifecycle) apiPortPreflight(ctx context.Context, record *Deployment) string {
	env := l.env
	if env.GOOS == "linux" && env.Services.Active(ctx, Unit{Name: unitAPISocket, Kind: "socket"}) {
		// systemd listens on the port, so nothing else can.
		return ""
	}
	serviceUID := -1
	if record != nil {
		serviceUID = record.ServiceUID
	} else if account, ok, err := env.Accounts.Lookup(ctx, env.Layout.ServiceUser); err == nil && ok {
		serviceUID = account.UID
	}
	foreign := l.foreignAPIPortHolders(ctx, serviceUID)
	if len(foreign) == 0 {
		return ""
	}
	perUser := map[int]bool{}
	for _, process := range env.gatewayProcesses(ctx) {
		perUser[process.PID] = true
	}
	var names, pids []string
	perUserGateway := false
	for _, holder := range foreign {
		name := holder.String()
		if holder.PID > 0 && perUser[holder.PID] {
			name += ", a per-user DefenseClaw gateway"
			perUserGateway = true
		}
		names = append(names, name)
		if holder.PID > 0 {
			pids = append(pids, strconv.Itoa(holder.PID))
		}
	}
	message := fmt.Sprintf("the gateway API port %s is held by %s, so the managed gateway cannot listen on it; nothing was changed. ",
		env.Layout.APIAddr, strings.Join(names, "; "))
	stop := "Stop that process or move it to another port"
	if len(pids) > 0 {
		stop = "Stop it with `kill " + strings.Join(pids, " ") + "` or move it to another port"
	}
	if perUserGateway {
		stop += ", and have that user remove the per-user install with `defenseclaw uninstall --binaries --yes`"
	}
	retry := "run this command again"
	if l.opts.FromPackage {
		retry = "run `" + env.lifecycleCommand(ActionEnsure) + " --from-package`"
	}
	return message + stop + ", then " + retry
}

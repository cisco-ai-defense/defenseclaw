// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package netprobe

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// snapshotTimeout bounds one lsof invocation. A hung lsof must not stall the
// poll loop, because a stalled poll looks exactly like a quiet host.
const snapshotTimeout = 15 * time.Second

// snapshot shells out to lsof.
//
// macOS has no /proc and no unprivileged sysctl that maps a socket to a pid
// without cgo. lsof is part of the base system and is the same source the
// upstream detector used.
//
// -F is the machine-readable field mode, which is parsed here rather than the
// human table: the table's columns shift with the widest value in each column,
// and a long process name silently reflows every field after it.
func snapshot() ([]Connection, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), snapshotTimeout)
	defer cancel()

	// -n and -P suppress DNS and service-name lookups. Both matter: a
	// reverse lookup per socket would make the poll slow and, worse, would
	// itself generate DNS traffic the DNS plane then observes.
	cmd := processutil.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-iTCP", "-Fpn")
	output, err := cmd.Output()
	if err != nil {
		// lsof exits non-zero when some processes could not be examined, which
		// is the ordinary unprivileged case, and still prints what it could
		// read. Only treat it as fatal when nothing came back.
		if len(output) == 0 {
			return nil, 0, err
		}
	}
	return parseLsof(string(output))
}

// parseLsof decodes lsof -F output: one field per line, tagged by its first
// byte, with 'p' opening a new process block and 'n' carrying each socket's
// address pair.
func parseLsof(output string) ([]Connection, int, error) {
	connections := make([]Connection, 0, 256)
	unattributed := 0
	currentPID := 0

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, err := strconv.Atoi(line[1:])
			if err != nil {
				currentPID = 0
				continue
			}
			currentPID = pid
		case 'n':
			connection, ok := parseLsofAddress(line[1:])
			if !ok {
				continue
			}
			connection.PID = currentPID
			if currentPID <= 0 {
				unattributed++
			}
			connections = append(connections, connection)
		}
	}
	return connections, unattributed, scanner.Err()
}

// parseLsofAddress decodes the 'n' field, which is either
// "local->remote (STATE)" for a connection or "*:port" / "host:port" for a
// listener.
func parseLsofAddress(value string) (Connection, bool) {
	state := StateOther
	if open := strings.LastIndex(value, " ("); open >= 0 && strings.HasSuffix(value, ")") {
		switch strings.ToUpper(value[open+2 : len(value)-1]) {
		case "ESTABLISHED":
			state = StateEstablished
		case "LISTEN":
			state = StateListen
		}
		value = value[:open]
	}
	local, remote, hasRemote := strings.Cut(value, "->")
	_, localPort, _ := splitHostPort(local)
	if !hasRemote {
		if state != StateListen {
			return Connection{}, false
		}
		return Connection{LocalPort: localPort, State: StateListen}, true
	}
	remoteHost, remotePort, ok := splitHostPort(remote)
	if !ok {
		return Connection{}, false
	}
	return Connection{
		LocalPort: localPort, RemoteIP: net.ParseIP(remoteHost),
		RemotePort: remotePort, State: state,
	}, true
}

// splitHostPort handles the bracketed IPv6 form lsof emits as well as IPv4.
func splitHostPort(value string) (string, int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, false
	}
	if strings.HasPrefix(value, "[") {
		if closing := strings.Index(value, "]"); closing > 0 {
			host := value[1:closing]
			rest := strings.TrimPrefix(value[closing+1:], ":")
			port, err := strconv.Atoi(rest)
			if err != nil {
				return host, 0, false
			}
			return host, port, true
		}
	}
	separator := strings.LastIndexByte(value, ':')
	if separator < 0 {
		return value, 0, false
	}
	port, err := strconv.Atoi(value[separator+1:])
	if err != nil {
		return value[:separator], 0, false
	}
	return value[:separator], port, true
}

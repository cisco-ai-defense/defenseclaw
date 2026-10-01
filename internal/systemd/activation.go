// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package systemd implements the two service-manager protocols the managed
// gateway needs without external dependencies: socket activation
// (LISTEN_PID / LISTEN_FDS / LISTEN_FDNAMES) and readiness/watchdog
// notification (NOTIFY_SOCKET, WATCHDOG_USEC).
//
// Socket activation is what makes the standalone Linux hook endpoints
// unsquattable: PID 1 binds 127.0.0.1:18970 and /run/defenseclaw-hook/hook.sock
// before any user process runs and keeps holding them across gateway restarts,
// so a hook that connects while the gateway restarts queues instead of
// reaching a user-owned impostor.
//
// macOS: launchd hands over its sockets only through launch_activate_socket(3),
// a libxpc call that needs cgo, and release builds are CGO_ENABLED=0. The
// darwin gateway therefore binds its own listeners; the standalone hook
// socket still lives in a directory only root or the service account can
// write, so a user cannot pre-create an impostor there either.
package systemd

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// listenFDsStart is SD_LISTEN_FDS_START: the first passed descriptor.
const listenFDsStart = 3

// maxListenFDs bounds the descriptor count accepted from the environment.
const maxListenFDs = 64

// inheritedFD is one descriptor passed by the service manager.
type inheritedFD struct {
	fd   int
	name string
}

// ErrNotActivated reports that the process was not socket-activated.
var ErrNotActivated = errors.New("systemd: process was not socket-activated")

// parseListenEnv decodes the socket-activation environment for process pid.
// It returns ErrNotActivated when LISTEN_PID/LISTEN_FDS are absent or name a
// different process (a child inheriting the parent's environment must never
// adopt the parent's sockets).
func parseListenEnv(pid int, getenv func(string) string) ([]inheritedFD, error) {
	rawPID := strings.TrimSpace(getenv("LISTEN_PID"))
	rawFDs := strings.TrimSpace(getenv("LISTEN_FDS"))
	if rawPID == "" || rawFDs == "" {
		return nil, ErrNotActivated
	}
	listenPID, err := strconv.Atoi(rawPID)
	if err != nil || listenPID <= 0 {
		return nil, fmt.Errorf("systemd: invalid LISTEN_PID %q", rawPID)
	}
	if listenPID != pid {
		return nil, ErrNotActivated
	}
	count, err := strconv.Atoi(rawFDs)
	if err != nil || count < 0 {
		return nil, fmt.Errorf("systemd: invalid LISTEN_FDS %q", rawFDs)
	}
	if count == 0 {
		return nil, ErrNotActivated
	}
	if count > maxListenFDs {
		return nil, fmt.Errorf("systemd: LISTEN_FDS %d exceeds %d", count, maxListenFDs)
	}
	var names []string
	if rawNames := getenv("LISTEN_FDNAMES"); rawNames != "" {
		names = strings.Split(rawNames, ":")
		if len(names) != count {
			return nil, fmt.Errorf("systemd: LISTEN_FDNAMES has %d names for %d descriptors", len(names), count)
		}
	}
	fds := make([]inheritedFD, 0, count)
	seen := make(map[string]bool, count)
	for index := 0; index < count; index++ {
		name := "unknown"
		if names != nil {
			name = names[index]
		}
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return nil, fmt.Errorf("systemd: descriptor %d has an invalid name", listenFDsStart+index)
		}
		if name != "unknown" && seen[name] {
			return nil, fmt.Errorf("systemd: descriptor name %q is passed more than once", name)
		}
		seen[name] = true
		fds = append(fds, inheritedFD{fd: listenFDsStart + index, name: name})
	}
	return fds, nil
}

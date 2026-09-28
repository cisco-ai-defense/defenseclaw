// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package systemd

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Notification states understood by systemd.
const (
	StateReady    = "READY=1"
	StateStopping = "STOPPING=1"
	StateWatchdog = "WATCHDOG=1"
)

// Notify sends state to the service manager's notification socket. It
// reports false with no error when the process was not started with
// NOTIFY_SOCKET (an ordinary per-user run, or a non-systemd host).
func Notify(state string) (bool, error) {
	return notifySocket(os.Getenv("NOTIFY_SOCKET"), state)
}

func notifySocket(socket, state string) (bool, error) {
	socket = strings.TrimSpace(socket)
	if socket == "" {
		return false, nil
	}
	if strings.ContainsAny(state, "\x00") {
		return false, fmt.Errorf("systemd: notification state contains NUL")
	}
	address := socket
	if strings.HasPrefix(address, "@") {
		// Abstract namespace (Linux): a leading NUL byte replaces '@'.
		address = "\x00" + address[1:]
	} else if !strings.HasPrefix(address, "/") {
		return false, fmt.Errorf("systemd: NOTIFY_SOCKET %q is neither absolute nor abstract", socket)
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return false, fmt.Errorf("systemd: dial notification socket: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, fmt.Errorf("systemd: send notification: %w", err)
	}
	return true, nil
}

// WatchdogInterval reports the service watchdog timeout when systemd asked
// this process (WATCHDOG_PID, when present, must be ours) to send keep-alives.
func WatchdogInterval() (time.Duration, bool) {
	return watchdogInterval(os.Getpid(), os.Getenv)
}

func watchdogInterval(pid int, getenv func(string) string) (time.Duration, bool) {
	rawUSec := strings.TrimSpace(getenv("WATCHDOG_USEC"))
	if rawUSec == "" {
		return 0, false
	}
	usec, err := strconv.ParseInt(rawUSec, 10, 64)
	if err != nil || usec <= 0 {
		return 0, false
	}
	if rawPID := strings.TrimSpace(getenv("WATCHDOG_PID")); rawPID != "" {
		watchdogPID, err := strconv.Atoi(rawPID)
		if err != nil || watchdogPID != pid {
			return 0, false
		}
	}
	return time.Duration(usec) * time.Microsecond, true
}

// RunWatchdog sends WATCHDOG=1 at half the configured interval until ctx is
// done. alive is consulted before each ping; a false result skips the ping so
// systemd restarts a gateway whose serving loop has wedged. It returns
// immediately when no watchdog was requested.
func RunWatchdog(ctx context.Context, alive func() bool) {
	interval, ok := WatchdogInterval()
	if !ok {
		return
	}
	period := interval / 2
	if period < time.Second {
		period = time.Second
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if alive != nil && !alive() {
				continue
			}
			if _, err := Notify(StateWatchdog); err != nil {
				fmt.Fprintf(os.Stderr, "[systemd] watchdog notification failed: %v\n", err)
			}
		}
	}
}

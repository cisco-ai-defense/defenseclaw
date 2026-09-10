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

// Command defenseclaw-sensor-helper holds the privilege the gateway does
// not, and answers a fixed set of questions about what the kernel sees.
//
// It exists because the two halves of AI runtime detection want opposite
// things. Reading the process table, the connection table and kernel events
// needs privilege. The component that reasons about them is network-facing
// and, in a managed deployment, is deliberately de-privileged for exactly
// that reason -- an unprivileged account inside a systemd sandbox on Linux,
// a virtual service account on Windows.
//
// So the privilege lives here, in a process that does nothing else: no
// network listener, no policy, no scoring, no writes to anything a user
// owns. It answers three questions -- the process table, the connection
// table, the kernel event stream -- and takes no instruction about any of
// them. What it watches comes from its own root-owned configuration.
//
// The security argument is the smallness. Anything added here that lets the
// caller say *what* to read turns a root process into a confused deputy for
// whoever holds the socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/ipc"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "defenseclaw-sensor-helper:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		socketPath = flag.String("socket", "",
			"path to listen on (default: the deployment's standard location)")
		homeDirs = flag.String("home-dirs", "",
			"comma-separated user homes whose credential paths Plane C watches")
		allowUIDs = flag.String("allow-uid", "",
			"comma-separated peer uids permitted to connect (default: this process's own)")
		socketGID = flag.Int("socket-gid", -1,
			"group to own the socket, so the gateway's account can reach it")
		dataDir = flag.String("data-dir", "",
			"data directory, used to place the socket outside managed deployments")
		managedEnterprise = flag.Bool("managed-enterprise", false,
			"use the managed deployment's socket location")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	path := *socketPath
	if path == "" {
		path = acquire.DefaultSocketPath(*dataDir, *managedEnterprise)
	}

	uids, err := parseUIDs(*allowUIDs)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 0o660 with a group the gateway belongs to: the socket is reachable by
	// exactly one other account and by nobody else. The peer uid is checked
	// again at accept, because a mode is a filter that can be widened by an
	// unrelated packaging change without anyone noticing.
	listener, err := ipc.ListenSecured(ctx, ipc.ListenSpec{
		Path:       path,
		SocketMode: 0o660,
		DirMode:    0o750,
		OwnerUID:   os.Getuid(),
		OwnerGID:   *socketGID,
	})
	if err != nil {
		return err
	}

	server := acquire.NewServer(acquire.ServerConfig{
		HomeDirs:    splitList(*homeDirs),
		AllowedUIDs: uids,
		Logger:      logger,
	})

	logger.Info("sensor helper listening",
		"socket", path, "uid", os.Getuid(),
		"allowed_uids", uids, "home_dirs", splitList(*homeDirs))

	if err := server.Serve(ctx, listener); err != nil {
		return err
	}
	logger.Info("sensor helper stopped")
	return nil
}

func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseUIDs(value string) ([]int, error) {
	var out []int
	for _, part := range splitList(value) {
		uid, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("--allow-uid %q: not a uid", part)
		}
		if uid < 0 {
			return nil, fmt.Errorf("--allow-uid %d: negative", uid)
		}
		out = append(out, uid)
	}
	return out, nil
}

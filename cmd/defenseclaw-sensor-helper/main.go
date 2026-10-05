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
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/ipc"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
)

// Set by the release build's -ldflags -X, so a service log and --version name
// the exact helper build.
var (
	version = "dev"
	commit  = "unknown"
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
		serviceAccount = flag.String("service-account", "",
			"gateway account: permit its uid and give the socket its group (unless --allow-uid/--socket-gid are set)")
		homesFromManifest = flag.String("home-dirs-from-manifest", "",
			"protected guardian manifest whose enabled users' homes Plane C watches; restarts when it changes")
		showVersion = flag.Bool("version", false, "print the helper's version and commit, then exit")
	)
	flag.Parse()
	if *showVersion {
		_, err := fmt.Fprintln(os.Stdout, versionString())
		return err
	}

	// The log destination comes from the protected service environment, not
	// the command line, so the ImagePath of an installed helper never changes
	// shape and a rollback to an older helper binary still starts.
	logger, closeLog := newHelperLogger(serviceLogPath(), os.Stderr)
	defer closeLog()
	logger.Info("sensor helper starting", "version", version, "commit", commit)

	err := runHelper(logger, *socketPath, *homeDirs, *allowUIDs, *socketGID, *dataDir, *managedEnterprise,
		*serviceAccount, *homesFromManifest)
	if err != nil {
		// Under the Service Control Manager this line is the only record of
		// why the helper, and therefore the gateway that depends on it,
		// did not come up.
		logger.Error("sensor helper exited", "error", err)
	}
	return err
}

// versionString names the build in the same form as defenseclaw-gateway
// --version, so an administrator can match the privileged helper to the
// package and the gateway it shipped with.
func versionString() string {
	return fmt.Sprintf("defenseclaw-sensor-helper version %s (commit=%s)", version, commit)
}

func runHelper(
	logger *slog.Logger,
	socketPath, homeDirs, allowUIDs string,
	socketGID int,
	dataDir string,
	managedEnterprise bool,
	serviceAccount, homesFromManifest string,
) error {
	path := socketPath
	if path == "" {
		path = acquire.DefaultSocketPath(dataDir, managedEnterprise)
	}

	uids, err := parseUIDs(allowUIDs)
	if err != nil {
		return err
	}
	if serviceAccount != "" {
		uid, gid, err := resolveServiceAccount(serviceAccount)
		if err != nil {
			return err
		}
		if len(uids) == 0 {
			uids = []int{uid}
		}
		if socketGID < 0 {
			socketGID = gid
		}
	}
	homes := splitList(homeDirs)
	manifestDigest := ""
	if homesFromManifest != "" {
		fromManifest, digest, err := manifestHomes(homesFromManifest)
		if err != nil {
			return err
		}
		homes, manifestDigest = append(homes, fromManifest...), digest
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if homesFromManifest != "" {
		ctx = watchManifest(ctx, homesFromManifest, manifestDigest, 30*time.Second, logger)
	}

	// Under the Windows SCM there is no console and no signal: the service
	// control manager expects the process to report Running within seconds
	// and to stop when told. runUnderServiceManager takes over the
	// lifecycle when that is where we are, and is a passthrough everywhere
	// else. Without it the service registers, fails to answer SCM, and is
	// killed with error 1053 -- a helper that can never start, on the one
	// platform whose gateway most needs it.
	return runUnderServiceManager(ctx, func(ctx context.Context) error {
		return serve(ctx, path, uids, socketGID, homes, logger)
	})
}

// newHelperLogger writes to the service log when one is configured and it
// can be opened safely, and to fallback otherwise. A log that cannot be
// opened is a diagnostics gap, not a reason to refuse to start: the gateway
// depends on this service, so failing here would take managed hooks down
// with it.
func newHelperLogger(path string, fallback io.Writer) (*slog.Logger, func()) {
	options := &slog.HandlerOptions{Level: slog.LevelInfo}
	if strings.TrimSpace(path) == "" {
		return slog.New(slog.NewTextHandler(fallback, options)), func() {}
	}
	file, err := openHelperLog(path)
	if err != nil {
		logger := slog.New(slog.NewTextHandler(fallback, options))
		logger.Warn("sensor helper log is unavailable; logging to stderr",
			"log", path, "error", err)
		return logger, func() {}
	}
	return slog.New(slog.NewTextHandler(file, options)), func() { _ = file.Close() }
}

func serve(
	ctx context.Context,
	path string,
	uids []int,
	socketGID int,
	homeDirs []string,
	logger *slog.Logger,
) error {

	// 0o660 with a group the gateway belongs to: the socket is reachable by
	// exactly one other account and by nobody else. The peer uid is checked
	// again at accept, because a mode is a filter that can be widened by an
	// unrelated packaging change without anyone noticing.
	listener, err := ipc.ListenSecured(ctx, ipc.ListenSpec{
		Path: path,
		// Named, not borrowed. Windows anchors a bind to the trusted
		// managed IPC directory and to a declared filename; this service
		// has its own access boundary, so it must not share the UI IPC
		// socket's identity.
		BaseName:    acquire.SocketFileName,
		SocketMode:  0o660,
		DirMode:     0o750,
		OwnerUID:    os.Getuid(),
		OwnerGID:    socketGID,
		GatewayOnly: true,
	})
	if err != nil {
		return err
	}

	server := acquire.NewServer(acquire.ServerConfig{
		HomeDirs:    homeDirs,
		AllowedUIDs: uids,
		Logger:      logger,
	})

	logger.Info("sensor helper listening",
		"socket", path, "uid", os.Getuid(),
		"allowed_uids", uids, "home_dirs", homeDirs)

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

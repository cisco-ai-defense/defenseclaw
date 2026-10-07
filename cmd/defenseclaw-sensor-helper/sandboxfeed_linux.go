// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed/feed"
)

// The sandbox kernel feed is a mode of this binary of its own:
//
//	defenseclaw-sensor-helper --sandbox-feed              serve (the systemd unit)
//	defenseclaw-sensor-helper --sandbox-feed --check      can this host run it?
//	defenseclaw-sensor-helper --sandbox-feed --uninstall  remove the service and this copy
//
// --uninstall is what a user's `defenseclaw uninstall` names once the
// gateway (and its `sandbox kernel-feed uninstall`) is gone: the root copy
// can always remove itself.
//
// It shares none of the broker's flags: the managed helper's socket, peer
// uids, homes and Tetragon intent mean nothing to it, and it takes no
// argument that could widen what it reads. So it is picked off the command
// line before the broker's flag set is parsed, and only as the first
// argument.
func init() {
	if len(os.Args) < 2 || (os.Args[1] != "--sandbox-feed" && os.Args[1] != "-sandbox-feed") {
		return
	}
	os.Exit(runSandboxFeed(os.Args[2:], os.Stdout, os.Stderr))
}

// runSandboxFeed is the mode's whole command; it returns the exit status.
func runSandboxFeed(args []string, stdout, stderr io.Writer) int {
	mode := ""
	switch {
	case len(args) == 0:
	case len(args) == 1 && (args[0] == "--check" || args[0] == "-check"):
		mode = "check"
	case len(args) == 1 && (args[0] == "--uninstall" || args[0] == "-uninstall"):
		mode = "uninstall"
	default:
		fmt.Fprintln(stderr, "usage: defenseclaw-sensor-helper --sandbox-feed [--check | --uninstall]")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "defenseclaw-sensor-helper: the sandbox kernel feed runs as root (it reads Tetragon's root-only socket)")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch mode {
	case "uninstall":
		removed, err := (&sandboxfeed.Lifecycle{}).Uninstall(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "defenseclaw-sensor-helper:", err)
			return 1
		}
		if len(removed) == 0 {
			fmt.Fprintln(stdout, "the sandbox kernel feed is not installed; nothing was changed")
		} else {
			fmt.Fprintln(stdout, "the sandbox kernel feed is removed:", strings.Join(removed, ", "))
		}
		return 0
	case "check":
		checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		summary, err := feed.Check(checkCtx, nil)
		if err != nil {
			fmt.Fprintln(stdout, err)
			return 1
		}
		if _, err := dockerGroup(); err != nil {
			fmt.Fprintln(stdout, err)
			return 1
		}
		fmt.Fprintln(stdout, summary)
		return 0
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("sandbox kernel feed starting", "version", version, "commit", commit, "protocol", sandboxfeed.ProtocolVersion)
	gid, err := dockerGroup()
	if err != nil {
		logger.Error("sandbox kernel feed cannot start", "error", err)
		return 1
	}
	hub := feed.NewHub(nil)
	mapper := feed.NewMapper(feed.MapperConfig{
		Containers: feed.NewContainers(&feed.DockerInspector{}, nil),
		Proc:       feed.HostProc{},
	})
	source := &feed.Source{Mapper: mapper, Hub: hub, Logger: logger}
	go source.Run(ctx)
	server := &feed.Server{GID: gid, Hub: hub, Build: version, Logger: logger}
	if err := server.Serve(ctx); err != nil {
		logger.Error("sandbox kernel feed stopped", "error", err)
		return 1
	}
	logger.Info("sandbox kernel feed stopped")
	return 0
}

// dockerGroup is the gid of the docker group: the feed's readers.
func dockerGroup() (int, error) {
	group, err := user.LookupGroup(sandboxfeed.DockerGroup)
	if err != nil {
		return -1, fmt.Errorf("no %s group on this host (%v): the sandbox kernel feed serves docker sandboxes", sandboxfeed.DockerGroup, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid <= 0 {
		return -1, fmt.Errorf("the %s group has the unusable gid %q", sandboxfeed.DockerGroup, group.Gid)
	}
	return gid, nil
}

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

//go:build linux

package platform

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type linuxPlatform struct{}

func current() Platform { return linuxPlatform{} }

func (linuxPlatform) OSType() string { return "linux" }
func (linuxPlatform) Name() string   { return "Linux" }

// WideCoverage is euid == 0 on Linux, the same question macOS answers the same
// way: /proc shows every process's stat to anyone, but /proc/<pid>/fd -- which
// is what attributes a socket inode to a pid -- is readable only by the owner
// or root.
func (linuxPlatform) WideCoverage() bool { return os.Geteuid() == 0 }

func (p linuxPlatform) Capabilities() map[Plane]Capability {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		// Without /proc there is no acquisition at all for the first two
		// planes. Say so rather than reporting a quiet host.
		unavailable := func(plane Plane) Capability {
			return Capability{Plane: plane, Available: false, Reason: "/proc is not mounted"}
		}
		return map[Plane]Capability{
			PlaneA: unavailable(PlaneA),
			PlaneB: unavailable(PlaneB),
			PlaneC: p.planeC(),
		}
	}
	return map[Plane]Capability{
		PlaneA: {Plane: PlaneA, Available: true, Mechanism: "/proc"},
		PlaneB: {
			Plane: PlaneB, Available: true,
			Mechanism: "/proc/net and /proc/<pid>/fd",
			// Same shape as macOS: works unprivileged for our own user, needs
			// root to attribute every user's sockets.
			RequiresRoot: false,
		},
		PlaneC: p.planeC(),
	}
}

// planeC reports the netlink process connector plus fanotify.
//
// Both halves are probed independently. cn_proc alone is enough for
// Available -- it is the process half, it is unprivileged in the host
// namespace, and an unprivileged Linux host getting the process half with the
// file half honestly reported absent is strictly better than losing the whole
// plane to one missing capability.
//
// RequiresRoot is therefore false even when fanotify is out of reach: it
// describes what Plane C being *available* costs, and cn_proc costs nothing.
// The mechanism text is where the two halves' independent reachability shows,
// because one bool cannot carry "the process half does not need root, the file
// half does".
func (linuxPlatform) planeC() Capability {
	if reason := connectorUnreachable(); reason != "" {
		return Capability{
			Plane:     PlaneC,
			Available: false,
			Reason: reason + ". The file half of Plane C additionally needs " +
				"fanotify, which needs CAP_SYS_ADMIN",
			RequiresRoot: false,
		}
	}
	mechanism := "netlink process connector (cn_proc) + fanotify (process and file events)"
	if reason := fanotifyUnreachable(); reason != "" {
		mechanism = "netlink process connector (cn_proc) only -- file events need fanotify: " + reason
	}
	return Capability{Plane: PlaneC, Available: true, Mechanism: mechanism, RequiresRoot: false}
}

// connectorUnreachable returns why cn_proc cannot be used, or "" when it can.
// It opens the socket rather than inspecting kernel config, because a
// restricted namespace, a seccomp filter, and a kernel built without
// CONFIG_PROC_EVENTS all fail here and none of them show up in /boot/config.
func connectorUnreachable() string {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Sprintf("netlink connector socket refused: %v", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: 1, // CN_IDX_PROC
	}); err != nil {
		return fmt.Sprintf("netlink connector bind refused: %v", err)
	}
	return ""
}

// fanotifyUnreachable returns why the file half is unavailable, or "" when it
// is reachable. FAN_CLASS_NOTIF with no marks is inert, so this probe observes
// nothing and changes nothing.
func fanotifyUnreachable() string {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		return err.Error()
	}
	_ = unix.Close(fd)
	return ""
}

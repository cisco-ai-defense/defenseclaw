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
// Both halves are probed independently, and either one is enough for
// Available: a host that gets the process half with the file half honestly
// reported absent is strictly better off than one that loses the whole plane
// to one missing capability.
//
// Neither half is unprivileged. Subscribing to the process connector's
// multicast group needs CAP_NET_ADMIN in the initial user namespace (RHEL 9,
// kernel 5.14: an ordinary uid's bind fails with EPERM), and fanotify needs
// CAP_SYS_ADMIN. RequiresRoot is therefore true: it describes what Plane C
// being available costs. The managed sensor helper holds both capabilities;
// a per-user gateway gets them from `defenseclaw agent discovery runtime
// permissions --grant` or by running as root.
func (linuxPlatform) planeC() Capability {
	if reason := connectorUnreachable(); reason != "" {
		return Capability{
			Plane:     PlaneC,
			Available: false,
			Reason: reason + ". Process events need CAP_NET_ADMIN (the netlink " +
				"process connector); file events need CAP_SYS_ADMIN (fanotify)",
			RequiresRoot: true,
		}
	}
	mechanism := "netlink process connector (cn_proc) + fanotify (process and file events)"
	if reason := fanotifyUnreachable(); reason != "" {
		mechanism = "netlink process connector (cn_proc) only -- file events need fanotify, " +
			"which needs CAP_SYS_ADMIN: " + reason
	}
	return Capability{Plane: PlaneC, Available: true, Mechanism: mechanism, RequiresRoot: true}
}

// connectorUnreachable returns why cn_proc cannot be used, or "" when it can.
// It opens and binds the socket rather than inspecting kernel config, because
// a missing CAP_NET_ADMIN, a restricted namespace, a seccomp filter, and a
// kernel built without CONFIG_PROC_EVENTS all fail here and none of them show
// up in /boot/config.
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

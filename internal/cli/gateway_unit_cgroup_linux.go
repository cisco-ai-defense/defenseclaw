// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os"
	"strconv"
	"strings"
)

// systemdUnitProbe reads what identifies a process that systemd itself runs
// as a unit's ExecStart or ExecStop (GAP-0205). A seam: tests stand in for
// the environment, the parent PID and the /proc files.
type systemdUnitProbe struct {
	getenv   func(string) string
	getppid  func() int
	readFile func(string) ([]byte, error)
}

var gatewayUnitProbe = systemdUnitProbe{getenv: os.Getenv, getppid: os.Getppid, readFile: os.ReadFile}

// systemdServiceCgroup returns this process's cgroup when systemd runs it
// as a service's ExecStart or ExecStop: INVOCATION_ID is set, the process's
// own cgroup ends in a "*.service" leaf (system or user manager) and its
// parent is systemd itself. A stop or start from a shell, a hook, an
// uninstall, or an SSM, Salt or CI agent (an inherited INVOCATION_ID, but a
// parent that is not systemd) does not match.
func systemdServiceCgroup() (string, bool) { return gatewayUnitProbe.serviceCgroup() }

// processOutsideCgroup reports whether pid runs in a cgroup other than
// cgroup. An unreadable or unparseable record is not proof: false, so the
// caller keeps the behaviour it had before (GAP-0205).
func processOutsideCgroup(pid int, cgroup string) bool {
	return gatewayUnitProbe.processOutsideCgroup(pid, cgroup)
}

func (p systemdUnitProbe) serviceCgroup() (string, bool) {
	if strings.TrimSpace(p.getenv("INVOCATION_ID")) == "" {
		return "", false
	}
	ppid := p.getppid()
	if ppid <= 0 {
		return "", false
	}
	comm, err := p.readFile("/proc/" + strconv.Itoa(ppid) + "/comm")
	if err != nil || strings.TrimSuffix(string(comm), "\n") != "systemd" {
		return "", false
	}
	raw, err := p.readFile("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	cgroup, ok := systemdCgroupPath(raw)
	if !ok {
		return "", false
	}
	leaf := cgroup[strings.LastIndex(cgroup, "/")+1:]
	// A user manager's own user@N.service is not a unit that runs the gateway.
	if len(leaf) <= len(".service") || !strings.HasSuffix(leaf, ".service") || strings.HasPrefix(leaf, "user@") {
		return "", false
	}
	return cgroup, true
}

func (p systemdUnitProbe) processOutsideCgroup(pid int, cgroup string) bool {
	if pid <= 0 || cgroup == "" {
		return false
	}
	raw, err := p.readFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return false
	}
	other, ok := systemdCgroupPath(raw)
	return ok && other != cgroup
}

// systemdCgroupPath returns the cgroup path systemd tracks a process by,
// from /proc/<pid>/cgroup: the named "name=systemd" hierarchy on cgroup v1
// and hybrid hosts, else the unified "0::" line of cgroup v2.
func systemdCgroupPath(raw []byte) (string, bool) {
	unified, haveUnified := "", false
	for _, line := range strings.Split(string(raw), "\n") {
		id, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		controllers, cgroup, ok := strings.Cut(rest, ":")
		if !ok {
			continue
		}
		for _, controller := range strings.Split(controllers, ",") {
			if controller == "name=systemd" {
				return validSystemdCgroupPath(cgroup)
			}
		}
		if id == "0" && controllers == "" && !haveUnified {
			unified, haveUnified = cgroup, true
		}
	}
	if !haveUnified {
		return "", false
	}
	return validSystemdCgroupPath(unified)
}

func validSystemdCgroupPath(cgroup string) (string, bool) {
	if !strings.HasPrefix(cgroup, "/") || strings.ContainsAny(cgroup, "\x00\r") {
		return "", false
	}
	return cgroup, true
}

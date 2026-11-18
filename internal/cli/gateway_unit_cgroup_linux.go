// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// gatewayUnitRecordName binds a data directory's gateway to the systemd unit
// that runs it (GAP-0205): the cgroup of the unit whose ExecStart last
// launched the gateway, or, from a release before the record, the unit the
// running gateway was found in. Only that unit's ExecStop leaves a gateway
// outside the unit running, and only its ExecStart takes such a gateway over.
const (
	gatewayUnitRecordName = "gateway.unit-cgroup"
	maxGatewayUnitRecord  = 4 << 10
)

// systemdRunUnitName matches the names systemd-run gives a transient service
// it is not told to name (run-u7, run-p812-i813, run-r1f2e). Such a unit
// lives for one command, so it never becomes the unit a gateway is bound to.
var systemdRunUnitName = lazyregexp.New(`^run-(u[0-9]+|p[0-9]+-i[0-9]+|r[0-9a-f]+)\.service$`)

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

// boundSystemdUnitCgroup returns this process's unit cgroup when systemd runs
// it as the ExecStart or ExecStop of the unit dataDir's gateway is bound to
// (gatewayUnitRecordName). Every other unit, a transient
// `systemd-run defenseclaw-gateway start` or a timer's service, starts and
// stops the gateway as a shell does (GAP-0205).
func boundSystemdUnitCgroup(dataDir string) (string, bool) {
	cgroup, ok := systemdServiceCgroup()
	if !ok || recordedGatewayUnitCgroup(dataDir) != cgroup {
		return "", false
	}
	return cgroup, true
}

// recordGatewayLaunchUnit binds dataDir's gateway to the unit whose ExecStart
// this start runs as, before the start launches the gateway under it.
func recordGatewayLaunchUnit(dataDir string) {
	if cgroup, ok := systemdServiceCgroup(); ok {
		writeGatewayUnitRecord(dataDir, cgroup)
	}
}

// adoptGatewayUnitOf binds dataDir's gateway to the unit the running gateway
// pid is in, when no unit is recorded yet: a gateway that a release before
// the record (1.0.9 and older) launched from its unit. Kept while upgrades
// from those releases are supported.
func adoptGatewayUnitOf(dataDir string, pid int) {
	if recordedGatewayUnitCgroup(dataDir) != "" {
		return
	}
	if cgroup, ok := gatewayUnitProbe.processCgroup(pid); ok {
		writeGatewayUnitRecord(dataDir, cgroup)
	}
}

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
	if !ok || !serviceUnitCgroup(cgroup) {
		return "", false
	}
	return cgroup, true
}

func (p systemdUnitProbe) processCgroup(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	raw, err := p.readFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", false
	}
	return systemdCgroupPath(raw)
}

func (p systemdUnitProbe) processOutsideCgroup(pid int, cgroup string) bool {
	if cgroup == "" {
		return false
	}
	other, ok := p.processCgroup(pid)
	return ok && other != cgroup
}

// serviceUnitCgroup reports whether cgroup is a service unit's own cgroup:
// a "*.service" leaf that is not a user manager's user@N.service.
func serviceUnitCgroup(cgroup string) bool {
	leaf := systemdUnitName(cgroup)
	return len(leaf) > len(".service") && strings.HasSuffix(leaf, ".service") && !strings.HasPrefix(leaf, "user@")
}

// bindableUnitCgroup is a service unit cgroup a gateway can be bound to: not
// one systemd-run named for a single command.
func bindableUnitCgroup(cgroup string) bool {
	if _, ok := validSystemdCgroupPath(cgroup); !ok || strings.Contains(cgroup, "\n") {
		return false
	}
	return serviceUnitCgroup(cgroup) && !systemdRunUnitName.MatchString(systemdUnitName(cgroup))
}

// recordedGatewayUnitCgroup is the bound unit's cgroup, or "" when none is
// recorded or the record is not one.
func recordedGatewayUnitCgroup(dataDir string) string {
	data, err := safefile.ReadRegularFileBounded(filepath.Join(dataDir, gatewayUnitRecordName), maxGatewayUnitRecord+1)
	if err != nil || len(data) > maxGatewayUnitRecord {
		return ""
	}
	cgroup := strings.TrimSuffix(string(data), "\n")
	if !bindableUnitCgroup(cgroup) {
		return ""
	}
	return cgroup
}

// writeGatewayUnitRecord binds dataDir's gateway to the unit of cgroup.
// Best effort: without the record the unit's start and stop act as a
// shell's.
func writeGatewayUnitRecord(dataDir, cgroup string) {
	if !bindableUnitCgroup(cgroup) || recordedGatewayUnitCgroup(dataDir) == cgroup {
		return
	}
	if info, err := os.Stat(dataDir); err != nil || !info.IsDir() {
		return
	}
	writePrivateDataDirFile(dataDir, gatewayUnitRecordName, cgroup+"\n")
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

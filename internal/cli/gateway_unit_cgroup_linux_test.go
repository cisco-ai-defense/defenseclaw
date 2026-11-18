// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"errors"
	"os"
	"testing"
)

// GAP-0205: the positive identification of a systemd unit's ExecStart or
// ExecStop, and the cgroup comparison of the gateway it would act on.
func TestGAP0205SystemdServiceCgroupIdentification(t *testing.T) {
	const systemUnit = "0::/system.slice/defenseclaw-gateway.service\n"
	const userUnit = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/defenseclaw-gateway.service\n"
	const v1 = "12:pids:/system.slice/defenseclaw-gateway.service\n" +
		"3:cpu,cpuacct:/system.slice/defenseclaw-gateway.service\n" +
		"1:name=systemd:/system.slice/defenseclaw-gateway.service\n"
	const hybrid = "1:name=systemd:/system.slice/defenseclaw-gateway.service\n0::/system.slice/defenseclaw-gateway.service\n"
	for _, tc := range []struct {
		name, invocation, comm, cgroup string
		ppid                           int
		commErr, cgroupErr             bool
		want                           string
	}{
		{name: "system unit, cgroup v2", invocation: "abc", comm: "systemd\n", cgroup: systemUnit, ppid: 1, want: "/system.slice/defenseclaw-gateway.service"},
		{name: "user unit, cgroup v2", invocation: "abc", comm: "systemd\n", cgroup: userUnit, ppid: 812, want: "/user.slice/user-1000.slice/user@1000.service/app.slice/defenseclaw-gateway.service"},
		{name: "system unit, cgroup v1", invocation: "abc", comm: "systemd\n", cgroup: v1, ppid: 1, want: "/system.slice/defenseclaw-gateway.service"},
		{name: "system unit, hybrid", invocation: "abc", comm: "systemd\n", cgroup: hybrid, ppid: 1, want: "/system.slice/defenseclaw-gateway.service"},
		{name: "INVOCATION_ID unset", comm: "systemd\n", cgroup: systemUnit, ppid: 1},
		{name: "INVOCATION_ID inherited by an SSM agent's child", invocation: "abc", comm: "ssm-agent-worke\n", cgroup: "0::/system.slice/amazon-ssm-agent.service\n", ppid: 900},
		{name: "a shell in a unit", invocation: "abc", comm: "bash\n", cgroup: systemUnit, ppid: 4242},
		{name: "a login session scope", invocation: "abc", comm: "systemd\n", cgroup: "0::/user.slice/user-1000.slice/session-3.scope\n", ppid: 1},
		{name: "an app.slice leaf", invocation: "abc", comm: "systemd\n", cgroup: "0::/user.slice/user-1000.slice/user@1000.service/app.slice\n", ppid: 812},
		{name: "the user manager's own unit", invocation: "abc", comm: "systemd\n", cgroup: "0::/user.slice/user-1000.slice/user@1000.service\n", ppid: 1},
		{name: "a bare .service leaf", invocation: "abc", comm: "systemd\n", cgroup: "0::/.service\n", ppid: 1},
		{name: "the root cgroup", invocation: "abc", comm: "systemd\n", cgroup: "0::/\n", ppid: 1},
		{name: "no parent", invocation: "abc", comm: "systemd\n", cgroup: systemUnit, ppid: 0},
		{name: "unreadable parent comm", invocation: "abc", commErr: true, cgroup: systemUnit, ppid: 1},
		{name: "unreadable own cgroup", invocation: "abc", comm: "systemd\n", cgroupErr: true, ppid: 1},
		{name: "unparseable own cgroup", invocation: "abc", comm: "systemd\n", cgroup: "garbage\n", ppid: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := systemdUnitProbe{
				getenv: func(name string) string {
					if name == "INVOCATION_ID" {
						return tc.invocation
					}
					return ""
				},
				getppid: func() int { return tc.ppid },
				readFile: func(name string) ([]byte, error) {
					switch {
					case name == "/proc/self/cgroup" && !tc.cgroupErr:
						return []byte(tc.cgroup), nil
					case name != "/proc/self/cgroup" && !tc.commErr:
						return []byte(tc.comm), nil
					}
					return nil, os.ErrPermission
				},
			}
			got, ok := probe.serviceCgroup()
			if ok != (tc.want != "") || got != tc.want {
				t.Fatalf("serviceCgroup() = %q, %v; want %q", got, ok, tc.want)
			}
		})
	}
}

func TestGAP0205ProcessOutsideCgroupFailsTowardTheOldBehaviour(t *testing.T) {
	const unit = "/system.slice/defenseclaw-gateway.service"
	for _, tc := range []struct {
		name   string
		record string
		err    error
		pid    int
		want   bool
	}{
		{name: "same cgroup, v2", record: "0::" + unit + "\n", pid: 77},
		{name: "same cgroup, v1", record: "4:memory:" + unit + "\n1:name=systemd:" + unit + "\n", pid: 77},
		{name: "a login session", record: "0::/user.slice/user-1000.slice/session-3.scope\n", pid: 77, want: true},
		{name: "another unit", record: "0::/system.slice/other.service\n", pid: 77, want: true},
		{name: "a child cgroup of the unit", record: "0::" + unit + "/sub\n", pid: 77, want: true},
		{name: "unreadable record", err: os.ErrPermission, pid: 77},
		{name: "gone process", err: os.ErrNotExist, pid: 77},
		{name: "unparseable record", record: "nothing here\n", pid: 77},
		{name: "no PID", record: "0::/user.slice\n", pid: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := systemdUnitProbe{readFile: func(name string) ([]byte, error) {
				if name != "/proc/77/cgroup" {
					return nil, errors.New("unexpected read of " + name)
				}
				return []byte(tc.record), tc.err
			}}
			if got := probe.processOutsideCgroup(tc.pid, unit); got != tc.want {
				t.Fatalf("processOutsideCgroup = %v, want %v", got, tc.want)
			}
		})
	}
	if (systemdUnitProbe{readFile: func(string) ([]byte, error) { return []byte("0::/x\n"), nil }}).processOutsideCgroup(77, "") {
		t.Fatal("an empty unit cgroup was taken as a cgroup to compare with")
	}
}

// The real process: `go test` is not a systemd unit's ExecStart or ExecStop.
func TestGAP0205TestProcessIsNotAUnitProcess(t *testing.T) {
	t.Setenv("INVOCATION_ID", "0205c0ffee0205c0ffee0205c0ffee02")
	if cgroup, ok := systemdServiceCgroup(); ok {
		t.Fatalf("the test process was identified as a unit process in %q", cgroup)
	}
}

func TestGAP0205SystemdUnitNameAndCommand(t *testing.T) {
	if got := systemdUnitName("/system.slice/defenseclaw-gateway.service"); got != "defenseclaw-gateway.service" {
		t.Fatalf("unit name = %q", got)
	}
	if got := systemctlFor("/system.slice/defenseclaw-gateway.service"); got != "sudo systemctl" {
		t.Fatalf("system unit command = %q", got)
	}
	if got := systemctlFor("/user.slice/user-1000.slice/user@1000.service/app.slice/dc.service"); got != "systemctl --user" {
		t.Fatalf("user unit command = %q", got)
	}
}

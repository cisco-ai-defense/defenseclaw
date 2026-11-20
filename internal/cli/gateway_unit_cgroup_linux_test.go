// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// gap0205UnitProbeAt is systemd running this process as an ExecStart or
// ExecStop in cgroup; procs serves other /proc files.
func gap0205UnitProbeAt(cgroup string, procs map[string]string) systemdUnitProbe {
	return systemdUnitProbe{
		getenv: func(name string) string {
			if name == "INVOCATION_ID" {
				return "abc"
			}
			return ""
		},
		getppid: func() int { return 1 },
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/1/comm":
				return []byte("systemd\n"), nil
			case "/proc/self/cgroup":
				return []byte("0::" + cgroup + "\n"), nil
			}
			if body, ok := procs[name]; ok {
				return []byte(body), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

func withGatewayUnitProbe(t *testing.T, probe systemdUnitProbe) {
	t.Helper()
	old := gatewayUnitProbe
	t.Cleanup(func() { gatewayUnitProbe = old })
	gatewayUnitProbe = probe
}

const (
	gap0205SystemUnit = "/system.slice/defenseclaw-gateway.service"
	gap0205UserApps   = "/user.slice/user-1000.slice/user@1000.service/app.slice/"
)

// Review round 4, P2-1: only the unit whose ExecStart launched the data
// directory's gateway is bound to it. A transient systemd-run unit never
// is, and never replaces the binding.
func TestGAP0205OnlyTheUnitThatLaunchedTheGatewayIsBound(t *testing.T) {
	if gap0205UnitRecordFile != gatewayUnitRecordName {
		t.Fatalf("the process tests write %q, the gateway reads %q", gap0205UnitRecordFile, gatewayUnitRecordName)
	}
	dataDir := t.TempDir()
	withGatewayUnitProbe(t, gap0205UnitProbeAt(gap0205SystemUnit, nil))
	if cgroup, bound := boundSystemdUnitCgroup(dataDir); bound {
		t.Fatalf("unit %q is bound with nothing recorded", cgroup)
	}
	recordGatewayLaunchUnit(dataDir)
	if cgroup, bound := boundSystemdUnitCgroup(dataDir); !bound || cgroup != gap0205SystemUnit {
		t.Fatalf("the unit that launched the gateway is not bound: %q, %v", cgroup, bound)
	}
	info, err := os.Stat(filepath.Join(dataDir, gatewayUnitRecordName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unit record: %v %v", info, err)
	}

	for _, name := range []string{"run-u42.service", "run-p812-i813.service", "run-r1f2e3d4c.service"} {
		withGatewayUnitProbe(t, gap0205UnitProbeAt(gap0205UserApps+name, nil))
		if _, bound := boundSystemdUnitCgroup(dataDir); bound {
			t.Fatalf("transient %s is bound", name)
		}
		recordGatewayLaunchUnit(dataDir)
		if got := recordedGatewayUnitCgroup(dataDir); got != gap0205SystemUnit {
			t.Fatalf("transient %s replaced the binding: %q", name, got)
		}
	}

	// A shell, or an agent inside the unit, records nothing.
	shell := gap0205UnitProbeAt(gap0205UserApps+"other.service", nil)
	shell.getppid = func() int { return 4242 }
	withGatewayUnitProbe(t, shell)
	recordGatewayLaunchUnit(dataDir)
	if got := recordedGatewayUnitCgroup(dataDir); got != gap0205SystemUnit {
		t.Fatalf("a shell replaced the binding: %q", got)
	}

	// Another named unit is bound once its ExecStart launches the gateway.
	other := gap0205UserApps + "defenseclaw-gateway.service"
	withGatewayUnitProbe(t, gap0205UnitProbeAt(other, nil))
	if _, bound := boundSystemdUnitCgroup(dataDir); bound {
		t.Fatal("a unit that never launched the gateway is bound")
	}
	recordGatewayLaunchUnit(dataDir)
	if cgroup, bound := boundSystemdUnitCgroup(dataDir); !bound || cgroup != other {
		t.Fatalf("the unit that launched the gateway last is not bound: %q, %v", cgroup, bound)
	}
}

func TestGAP0205UnitRecordThatIsNotABindableUnitBindsNothing(t *testing.T) {
	for _, record := range []string{
		"", "\n", "garbage\n", "system.slice/defenseclaw-gateway.service\n",
		"/user.slice/user-1000.slice/session-3.scope\n",
		"/user.slice/user-1000.slice/user@1000.service\n",
		gap0205UserApps + "run-u7.service\n",
		gap0205SystemUnit + "\n" + gap0205SystemUnit + "\n",
		gap0205SystemUnit + "\r\n",
		"/" + strings.Repeat("x", maxGatewayUnitRecord) + ".service\n",
	} {
		dataDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dataDir, gatewayUnitRecordName), []byte(record), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := recordedGatewayUnitCgroup(dataDir); got != "" {
			t.Fatalf("record %q was read as unit %q", record, got)
		}
	}
}

// A gateway a release before the record launched from its unit binds that
// unit when it is stopped or restarted; a binding on record stays.
func TestGAP0205AdoptsTheUnitAnOlderReleaseLaunchedTheGatewayFrom(t *testing.T) {
	for _, tc := range []struct {
		name, gateway string
		unreadable    bool
		want          string
	}{
		{name: "in a unit", gateway: "0::" + gap0205SystemUnit + "\n", want: gap0205SystemUnit},
		{name: "in a login session", gateway: "0::/user.slice/user-1000.slice/session-3.scope\n"},
		{name: "in the user manager", gateway: "0::/user.slice/user-1000.slice/user@1000.service\n"},
		{name: "in a transient unit", gateway: "0::" + gap0205UserApps + "run-u9.service\n"},
		{name: "unreadable", unreadable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procs := map[string]string{}
			if !tc.unreadable {
				procs["/proc/77/cgroup"] = tc.gateway
			}
			withGatewayUnitProbe(t, gap0205UnitProbeAt("/user.slice/user-1000.slice/session-3.scope", procs))
			dataDir := t.TempDir()
			adoptGatewayUnitOf(dataDir, 77)
			if got := recordedGatewayUnitCgroup(dataDir); got != tc.want {
				t.Fatalf("adopted %q, want %q", got, tc.want)
			}
		})
	}
	dataDir := t.TempDir()
	recorded := gap0205UserApps + "defenseclaw-gateway.service"
	writeGatewayUnitRecord(dataDir, recorded)
	withGatewayUnitProbe(t, gap0205UnitProbeAt(gap0205SystemUnit, map[string]string{"/proc/77/cgroup": "0::" + gap0205SystemUnit + "\n"}))
	adoptGatewayUnitOf(dataDir, 77)
	if got := recordedGatewayUnitCgroup(dataDir); got != recorded {
		t.Fatalf("adopt replaced the recorded unit %q with %q", recorded, got)
	}
}

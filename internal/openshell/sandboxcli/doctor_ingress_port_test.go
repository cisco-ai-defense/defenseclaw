// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

type verifiedDoctorStatusAPI struct {
	API
	pid int
}

func (a verifiedDoctorStatusAPI) StatusWithPeer(ctx context.Context) (*sandboxapi.Status, int, error) {
	st, err := a.Status(ctx)
	return st, a.pid, err
}

func TestDoctorDoesNotCallAnAdvertisedButUnboundIngressPortServed(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.status.Available = false // The manager's listener probe failed.
	var ingress, egress bool
	ta.HostDoctor = func(_ context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		for _, port := range d.Ports {
			switch port.Name {
			case "ingress":
				ingress = port.ServedByDaemon
			case "egress":
				egress = port.ServedByDaemon
			}
		}
		return &openshell.DoctorReport{}
	}
	report := ta.runDoctor(bg)
	if ingress || egress {
		t.Fatalf("advertised but unproven listeners treated as bound: ingress=%t egress=%t", ingress, egress)
	}
	for _, check := range report.Checks {
		if check.ID == CheckIDDaemon && check.Status == openshell.StatusPass {
			t.Fatalf("daemon reported ready with unproven listeners: %+v", check)
		}
	}
}

func TestManagedDoctorChecksOccupiedSandboxPorts(t *testing.T) {
	withManagedHost(t)
	for _, part := range []string{"ingress", "egress"} {
		t.Run(part, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			port := ln.Addr().(*net.TCPAddr).Port
			ta := newTestApp(t, "")
			ta.daemon.status.Managed = managedStatusFixture()
			ta.daemon.status.IngressPort = ta.Cfg.OpenShellIngressPort()
			ta.daemon.status.EgressPort = ta.Cfg.OpenShellEgressPort()
			if part == "ingress" {
				ta.daemon.status.IngressPort = port
			} else {
				ta.daemon.status.EgressPort = port
			}
			ta.daemon.status.Available = false
			ta.daemon.status.IngressAddr = ""
			ta.daemon.status.EgressAddr = ""
			ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
				return d.Run(ctx)
			}
			rep := ta.runDoctor(bg)
			c := rep.Get(openshell.CheckIDPortPrefix + part)
			if c == nil || c.Status != openshell.StatusFail || !strings.Contains(c.Detail, "127.0.0.1:"+strconv.Itoa(port)) ||
				!strings.Contains(c.Detail, "another process") || c.Fix == nil || !strings.Contains(c.Fix.Summary, "administrator") {
				t.Fatalf("managed doctor port check = %+v", c)
			}
		})
	}
}

// GAP-0617: an idle status can omit listener addresses even while the
// answering sandbox daemon still holds both configured ports. A holder of
// this account alone is insufficient; it must be that answering process.
func TestManagedDoctorProvesOnlyItsOwnSandboxDaemonPorts(t *testing.T) {
	withManagedHost(t)
	for _, tc := range []struct {
		name       string
		busy       bool
		foreignPID bool
		conflict   bool
		want       openshell.CheckStatus
		text       string
		advertised bool
	}{
		{"answering daemon", true, false, false, openshell.StatusPass, "served by the DefenseClaw daemon (PID ", false},
		{"idle status clears proven listener flags", true, false, false, openshell.StatusPass, "served by the DefenseClaw daemon (PID ", true},
		{"different process of the same account", true, true, false, openshell.StatusFail, "another process of your account", false},
		{"daemon reports a conflict", true, false, true, openshell.StatusFail, "another process of your account", false},
		{"free ports", false, false, false, openshell.StatusPass, "is free", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.API = verifiedDoctorStatusAPI{API: ta.API, pid: os.Getpid()}
			ta.daemon.status.Managed = managedStatusFixture()
			ta.daemon.status.Available = false
			ta.daemon.status.IngressAddr, ta.daemon.status.EgressAddr = "", ""
			ta.daemon.status.ListenersProven = true
			pid := os.Getpid()
			if tc.foreignPID {
				pid++
			}
			// An older status decoder ignores the additional field, which
			// keeps this regression executable against the release base.
			if err := json.Unmarshal([]byte(`{"daemon_pid":`+strconv.Itoa(pid)+`}`), &ta.daemon.status); err != nil {
				t.Fatal(err)
			}
			var listeners []net.Listener
			for _, part := range []string{"ingress", "egress"} {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port := ln.Addr().(*net.TCPAddr).Port
				if part == "ingress" {
					ta.daemon.status.IngressPort = port
					if tc.advertised {
						ta.daemon.status.IngressAddr = ln.Addr().String()
					}
				} else {
					ta.daemon.status.EgressPort = port
					if tc.advertised {
						ta.daemon.status.EgressAddr = ln.Addr().String()
					}
				}
				if tc.busy {
					listeners = append(listeners, ln)
				} else {
					_ = ln.Close()
				}
			}
			t.Cleanup(func() {
				for _, ln := range listeners {
					_ = ln.Close()
				}
			})
			if tc.conflict {
				ta.daemon.status.PortConflict = &sandboxapi.PortConflict{Name: "ingress", Port: ta.daemon.status.IngressPort, Holder: "own_process"}
			}
			ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
				if tc.advertised {
					for _, port := range d.Ports {
						if port.ServedByDaemon {
							t.Fatalf("idle status retained %s listener flag", port.Name)
						}
					}
				}
				d.PortHolder = func(string, int) (daemon.PortHolder, error) {
					return daemon.PortHolder{PID: os.Getpid(), UID: os.Geteuid()}, nil
				}
				return d.Run(ctx)
			}
			report := ta.runDoctor(bg)
			for _, part := range []string{"ingress", "egress"} {
				want, text := tc.want, tc.text
				if tc.conflict && part == "egress" {
					want, text = openshell.StatusPass, "served by the DefenseClaw daemon (PID "
				}
				check := report.Get(openshell.CheckIDPortPrefix + part)
				if check == nil || check.Status != want || !strings.Contains(check.Detail, text) {
					t.Fatalf("%s port row = %+v, want %s containing %q", part, check, want, text)
				}
				if want == openshell.StatusFail && check.Fix == nil {
					t.Fatalf("%s lost its port remedy: %+v", part, check)
				}
			}
		})
	}
}

// GAP-1875: with sandboxes unavailable because another account holds the
// ingress port, a daemon whose status names only the ports it holds still
// serves its egress port: the doctor does not call that port another
// process's.
func TestDoctorKeepsTheEgressPortTheDaemonHoldsWhileIngressIsTaken(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.status.Available = false
	ta.daemon.status.ListenersProven = true
	ta.daemon.status.IngressAddr = ""
	ta.daemon.status.EgressAddr = "127.0.0.1:19073"
	var ingress, egress bool
	ta.HostDoctor = func(_ context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		for _, port := range d.Ports {
			switch port.Name {
			case "ingress":
				ingress = port.ServedByDaemon
			case "egress":
				egress = port.ServedByDaemon
			}
		}
		return &openshell.DoctorReport{}
	}
	ta.runDoctor(bg)
	if ingress || !egress {
		t.Fatalf("ports served by the daemon: ingress=%t egress=%t, want the egress port only", ingress, egress)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

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

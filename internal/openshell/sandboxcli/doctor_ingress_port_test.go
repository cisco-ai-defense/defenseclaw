// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
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

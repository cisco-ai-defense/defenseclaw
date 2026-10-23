// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// GAP-0701: each port's readiness comes from that port's own listener.
func TestDoctorDoesNotClaimAnUnheldEgressPort(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.status.IngressAddr = "127.0.0.1:18971"
	ta.daemon.status.EgressAddr = ""
	var ports []openshell.PortRequirement
	ta.HostDoctor = func(_ context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		ports = append(ports, d.Ports...)
		return &openshell.DoctorReport{}
	}
	ta.runDoctor(context.Background())
	if len(ports) != 2 || !ports[0].ServedByDaemon || ports[1].ServedByDaemon {
		t.Fatalf("doctor treats one listener as proof of both ports: %+v", ports)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package platform

import (
	"strings"
	"testing"
)

// TestLinuxPlaneCIsNotUnprivileged pins the cn_proc truth fix: joining the
// process connector's multicast group needs CAP_NET_ADMIN (an ordinary uid's
// bind fails with EPERM on RHEL 9), so Plane C always costs privilege, and a
// blind plane names both capabilities rather than only fanotify's.
func TestLinuxPlaneCIsNotUnprivileged(t *testing.T) {
	capability := linuxPlatform{}.planeC()
	if !capability.RequiresRoot {
		t.Fatalf("Plane C claims to need no privilege: %+v", capability)
	}
	if capability.Available {
		if !strings.Contains(capability.Summary(), "(root)") {
			t.Fatalf("Summary() hides the privilege: %q", capability.Summary())
		}
		return
	}
	for _, want := range []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"} {
		if !strings.Contains(capability.Reason, want) {
			t.Fatalf("Reason %q does not name %s", capability.Reason, want)
		}
	}
}

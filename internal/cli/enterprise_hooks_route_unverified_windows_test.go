// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-1111: a target whose route-only render verify could not read fails
// with route_config_unverified. The Windows lifecycle reports that code, the
// result is not ok and exits 1603, and the config-rejected cause is not
// route_config_drift. Any other result passes through.
func TestEnterpriseHookRouteOnlyUnverifiedIsNotOkAndNotDrift(t *testing.T) {
	if err := enterpriseHookRouteOnlyUnverified(enterprisehooks.InstallResult{Connector: "claudecode"}); err != nil {
		t.Fatalf("a verified render = %v; want nil", err)
	}
	err := enterpriseHookRouteOnlyUnverified(enterprisehooks.InstallResult{Connector: "Codex", RouteOnly: enterprisehooks.RouteOnlyUnverified})
	if err == nil {
		t.Fatal("an unread route-only render passed verify")
	}
	message := "guardian SCM process is running but protected target coverage is not verified: codex@HOST\\dcw-std1 (S-1-5-21-1-2-3-1017): " + err.Error()
	if strings.Contains(message, "route_config_drift") {
		t.Fatalf("message names drift: %s", message)
	}
	code := windowsEnterpriseMessageCode(message, "lifecycle_error")
	if code != enterprisehooks.RouteConfigUnverifiedCode {
		t.Fatalf("code = %q; want %q", code, enterprisehooks.RouteConfigUnverifiedCode)
	}
	result := enterprisestatus.New("verify", "standalone", "windows", "1.0.10")
	result.AddError(code, message)
	if exit := result.Finish("windows", 0); result.OK || exit != enterprisestatus.WindowsExitFailure {
		t.Fatalf("ok=%v exit=%d; want ok=false exit %d", result.OK, exit, enterprisestatus.WindowsExitFailure)
	}
}

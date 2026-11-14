// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A hook or guard launch image under bin\hooks\<16 hex> belongs to its install
// root's gateway service (GAP-0751); nothing else in a launch folder does.
func TestGatewayServiceForExecutableFollowsLaunchImages(t *testing.T) {
	roots, err := winpath.EnterpriseRootsFor(winpath.EnterpriseProfileStandalone, `C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	const bin = `C:\Program Files\Cisco\DefenseClaw\bin`
	for executable, want := range map[string]string{
		bin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`:                                                     StandaloneWindowsGatewaySvc,
		bin + `\hooks\0123456789abcdef\defenseclaw-hook-guard.exe`:                                               StandaloneWindowsGatewaySvc,
		`C:\Program Files\Cisco\DefenseClaw-Cert\0a1b2c3d4e\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`:     certificationGatewayServiceForTest,
		bin + `\hooks\0123456789abcdef\defenseclaw.exe`:                                                          "",
		bin + `\hooks\.staging-0123456789abcdef\defenseclaw-hook.exe`:                                            "",
		`C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`: "",
	} {
		if got := gatewayServiceForExecutable(executable, roots); got != want {
			t.Errorf("gatewayServiceForExecutable(%q) = %q, want %q", executable, got, want)
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import "testing"

func TestRefuseDeviceKeyMoveComparesEffectivePath(t *testing.T) {
	for _, tc := range []struct {
		name, platform, dataDir, before, after string
		code                                   Code
	}{
		{"linux default unchanged", PlatformLinux, "/var/lib/defenseclaw", "gateway: {}\n", "gateway:\n  device_key_file: /var/lib/defenseclaw/device.key\n", ""},
		{"linux move", PlatformLinux, "/var/lib/defenseclaw", "gateway: {}\n", "gateway:\n  device_key_file: /var/lib/defenseclaw/new.key\n", CodeInvalidArguments},
		{"windows same path", PlatformWindows, `C:\ProgramData\Cisco\DefenseClaw`, "gateway:\n  device_key_file: 'C:\\ProgramData\\Cisco\\DefenseClaw\\device.key'\n", "gateway:\n  device_key_file: 'c:/programdata/cisco/defenseclaw/device.key'\n", ""},
		{"windows move", PlatformWindows, `C:\ProgramData\Cisco\DefenseClaw`, "gateway: {}\n", "gateway:\n  device_key_file: 'C:\\ProgramData\\Cisco\\DefenseClaw\\new.key'\n", CodeInvalidArguments},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := &DeviceLayout{DataDir: tc.dataDir}
			if got := CodeOf(RefuseDeviceKeyMove([]byte(tc.before), []byte(tc.after), tc.platform, layout)); got != tc.code {
				t.Fatalf("code = %q, want %q", got, tc.code)
			}
		})
	}
}

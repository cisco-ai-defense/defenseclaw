// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestCoworkWindowsSettingsPreserveClaudeDesktopPolicy(t *testing.T) {
	const path = `C:\Program Files\Claude\edr-integration\defenseclaw-cowork-amd64.tar.gz`
	desired := []RegValue{{Name: CoworkPackageValue, Type: RegSZ, String: path}, {Name: CoworkVendorValue, Type: RegSZ, String: "cisco"}}
	admin := RegValue{Name: "inferenceProvider", Type: RegSZ, String: "bedrock"}
	for _, tc := range []struct {
		name    string
		machine []RegValue
		owned   []RegValue
		create  bool
		users   bool
		local   bool
		open    bool
		ready   bool
		refusal string
	}{
		{name: "merge does not create whole-hive override", refusal: "holds no machine policy"},
		{name: "create may add settings", create: true},
		{name: "merge into existing complete machine policy", machine: []RegValue{admin}},
		{name: "create refuses HKCU masking", create: true, users: true, refusal: "HKCU"},
		{name: "create refuses local 3P masking", create: true, local: true, refusal: "local Claude Desktop"},
		{name: "machine key must be admin only", machine: []RegValue{admin}, open: true, refusal: "grants write access"},
		{name: "matching admin values remain admin-owned", machine: desired, ready: true},
		{name: "own settings can be kept without create", machine: desired, owned: desired, ready: true},
		{name: "foreign conflicting value is refused", machine: []RegValue{{Name: CoworkVendorValue, Type: RegSZ, String: "other"}}, refusal: "administrator-owned"},
		{name: "REG_EXPAND_SZ refused", machine: []RegValue{{Name: CoworkPackageValue, Type: RegExpandSZ, String: path}}, refusal: "administrator-owned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := &fakeWSLRegistry{machine: map[string][]RegValue{}, users: map[string]map[string][]RegValue{}, open: tc.open}
			if tc.machine != nil {
				reg.machine[ClaudeDesktopPolicyKey] = append([]RegValue(nil), tc.machine...)
			}
			if tc.users {
				reg.users[ClaudeDesktopPolicyKey] = map[string][]RegValue{"S-1-5-21-1000": {admin}}
			}
			if tc.local {
				home := t.TempDir()
				dir := filepath.Join(home, "AppData", "Local", "Claude-3p", "configLibrary")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
				reg.homes = []string{home}
			}
			opts := Options{}
			if tc.create {
				opts.WSL.ClaudeDesktopKey = config.WSLClaudeDesktopKeyCreate
			}
			ready, refusal, err := checkWindowsCoworkSettings(reg, opts, path, "cisco", tc.owned)
			if err != nil || ready != tc.ready || (tc.refusal == "" && refusal != "") || (tc.refusal != "" && !strings.Contains(refusal, tc.refusal)) {
				t.Fatalf("ready=%v refusal=%q err=%v", ready, refusal, err)
			}
			if len(reg.machine[ClaudeDesktopPolicyKey]) != len(tc.machine) {
				t.Fatal("read-only inspection changed registry")
			}
		})
	}
}

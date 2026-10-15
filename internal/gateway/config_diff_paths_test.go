// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestConfigDiffWindowsPathSpellings(t *testing.T) {
	for _, pair := range [][2]string{
		{`C:\Policy\`, `c:/policy`},
		{`C:\Policy\.\Packs\..\`, `c:/policy`},
		{`\\Server\Share\Policy\`, `//server/share/policy`},
	} {
		if !equalConfigPathForDiff(pair[0], pair[1], "windows") {
			t.Errorf("Windows paths %q and %q differ", pair[0], pair[1])
		}
		if equalConfigPathForDiff(pair[0], pair[1], "linux") {
			t.Errorf("Unix paths %q and %q compare equal", pair[0], pair[1])
		}
	}
	if equalConfigPathForDiff(`C:\Policy`, `C:\Other`, "windows") ||
		equalConfigPathForDiff("", `C:\Policy`, "windows") {
		t.Fatal("different Windows paths compare equal")
	}
	old := config.GuardrailConfig{RulePackDir: `C:\Policy\Packs\`}
	next := config.GuardrailConfig{RulePackDir: `c:/policy/packs`}
	if !configValuesEqualForDiff(old, next, "windows") {
		t.Fatal("nested guardrail path spelling changed the config diff")
	}
	next.RulePackDir = `c:/policy/other`
	if configValuesEqualForDiff(old, next, "windows") {
		t.Fatal("a different rule pack directory disappeared from the diff")
	}
	oldCfg := config.Config{
		Claw:    config.ClawConfig{HomeDir: `C:\Users\Admin\.openclaw\`},
		Gateway: config.GatewayConfig{DeviceKeyFile: `C:\Keys\device.key`},
	}
	newCfg := config.Config{
		Claw:    config.ClawConfig{HomeDir: `c:/users/admin/.openclaw`},
		Gateway: config.GatewayConfig{DeviceKeyFile: `c:/keys/device.key`},
	}
	if !configValuesEqualForDiff(oldCfg.Claw, newCfg.Claw, "windows") ||
		!configValuesEqualForDiff(oldCfg.Gateway, newCfg.Gateway, "windows") {
		t.Fatal("other path-bearing config sections changed for Windows spelling alone")
	}
	if configValuesEqualForDiff(config.ObservabilityV8SignalOverrideSource{Path: "/Events"},
		config.ObservabilityV8SignalOverrideSource{Path: "/events"}, "windows") {
		t.Fatal("a case-sensitive HTTP route was treated as a filesystem path")
	}
}

func TestConfigManagerClassifiesWindowsGenerationPathCase(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows directory event spelling")
	}
	mgr := &ConfigManager{path: `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`}
	if got := mgr.classify(`c:/programdata/cisco/defenseclaw/etc/CONFIG.GENERATION.JSON`); got != configGenerationTrigger {
		t.Fatalf("generation event classified as %q", got)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestWindowsConnectorContractCompoundRegistryPersistence(t *testing.T) {
	t.Parallel()

	const command = `reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v DefenseClawContract /t REG_SZ /d harmless-placeholder /f; Set-Content -LiteralPath 'C:\Temp\registry-persistence.marker' -Value 'unexpected-execution'`
	for _, tool := range []string{"shell", "Bash"} {
		tool := tool
		t.Run(tool, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: tool,
				Args: json.RawMessage(`{"command":` + mustMarshalString(t, command) + `}`),
			})
			if facts.Parse.Dialect != DialectPowerShell ||
				facts.Parse.Status != StatusPartial {
				t.Fatalf("dialect=%q status=%q issues=%v commands=%+v paths=%+v", facts.Parse.Dialect, facts.Parse.Status, facts.Parse.Issues, facts.Commands, facts.Paths)
			}
			if len(facts.Commands) != 2 {
				t.Fatalf("commands=%+v, want registry write and sentinel", facts.Commands)
			}
			registry := facts.Commands[0]
			if registry.Program != "reg.exe" || !registry.ArgvComplete ||
				!commandHasOperation(registry, OperationConfigChange) {
				t.Fatalf("registry command=%+v", registry)
			}
			if !factsHavePath(
				facts,
				PathAccessWrite,
				`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
			) {
				t.Fatalf("registry persistence path missing from %+v", facts.Paths)
			}
		})
	}
}

func TestWindowsConnectorContractCompoundInferenceControls(t *testing.T) {
	t.Parallel()

	const registry = `reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Agent /t REG_SZ /d harmless /f`
	standalone := Analyze(Input{Tool: "shell", Command: registry})
	if !standalone.Authoritative() || !standalone.EnforcementEligible() ||
		standalone.Parse.Dialect != DialectCMD ||
		len(standalone.Commands) != 1 ||
		!commandHasOperation(standalone.Commands[0], OperationConfigChange) {
		t.Fatalf("standalone registry command=%+v", standalone)
	}

	for _, command := range []string{
		`printf '%s\n' 'fixture; Set-Content -LiteralPath C:\Temp\marker'`,
		`echo "fixture; Set-Content -LiteralPath C:\Temp\marker"`,
		`printf '%s\n' fixture\; Set-Content -LiteralPath C:\Temp\marker`,
	} {
		facts := Analyze(Input{Tool: "shell", Command: command})
		if facts.Parse.Dialect == DialectPowerShell {
			t.Errorf("quoted or escaped prose selected PowerShell for %q: %+v", command, facts)
		}
	}
	for _, command := range []string{
		`echo "fixture; Set-Content -LiteralPath C:\Temp\marker"`,
		registry + ` # fixture; Set-Content -LiteralPath C:\Temp\marker`,
		registry + ` \; Set-Content -LiteralPath C:\Temp\marker`,
	} {
		facts := Analyze(Input{Tool: "Bash", Command: command})
		if facts.Parse.Dialect != DialectPOSIX {
			t.Errorf("inert Bash suffix selected %q for %q: %+v", facts.Parse.Dialect, command, facts)
		}
	}
}

func mustMarshalString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

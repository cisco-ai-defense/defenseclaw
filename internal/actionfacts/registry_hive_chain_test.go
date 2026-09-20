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

package actionfacts

import "testing"

func TestRegistryExportActionFacts(t *testing.T) {
	credential := Analyze(Input{
		Tool: "shell", Command: `reg save HKLM\SAM C:\Temp\sam.hive /y`,
		CWD: `C:\repo`, DialectHint: DialectCMD,
	})
	if !credential.Authoritative() || len(credential.Commands) != 1 ||
		!hasFactOperation(credential.Commands[0], OperationRead) ||
		!hasFactOperation(credential.Commands[0], OperationWrite) ||
		!hasFactOperation(credential.Commands[0], OperationCredentialRead) ||
		len(credential.Paths) != 2 {
		t.Fatalf("credential hive facts=%#v", credential)
	}

	generic := Analyze(Input{
		Tool: "shell", Command: `reg export HKLM\SOFTWARE C:\Temp\software.reg`,
		CWD: `C:\repo`, DialectHint: DialectCMD,
	})
	if !generic.Authoritative() || len(generic.Commands) != 1 ||
		!hasFactOperation(generic.Commands[0], OperationRead) ||
		!hasFactOperation(generic.Commands[0], OperationWrite) ||
		hasFactOperation(generic.Commands[0], OperationCredentialRead) ||
		len(generic.Paths) != 2 {
		t.Fatalf("generic registry export facts=%#v", generic)
	}
}

func TestSensitiveRegistryHiveDumpPair(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{
			name: "atomic save sequence",
			command: "reg save HKLM\\sam %temp%\\sam\n" +
				"reg save HKLM\\system %temp%\\system\n" +
				"reg save HKLM\\security %temp%\\security",
			want: true,
		},
		{
			name: "reverse order export sequence",
			command: "reg.exe export HKEY_LOCAL_MACHINE\\SYSTEM C:\\Temp\\system.hive /y\n" +
				"reg.exe export HKEY_LOCAL_MACHINE\\SAM C:\\Temp\\sam.hive /y",
			want: true,
		},
		{name: "single hive backup", command: `reg save HKLM\SAM C:\Temp\sam.hive`},
		{
			name: "sam and security lack system",
			command: "reg save HKLM\\SAM C:\\Temp\\sam.hive\n" +
				"reg save HKLM\\SECURITY C:\\Temp\\security.hive",
		},
		{
			name: "generic backups",
			command: "reg export HKLM\\SOFTWARE C:\\Temp\\software.reg\n" +
				"reg export HKCU\\Environment C:\\Temp\\environment.reg",
		},
		{
			name: "same destination loses pair lineage",
			command: "reg save HKLM\\SAM C:\\Temp\\backup.hive\n" +
				"reg save HKLM\\SYSTEM C:\\Temp\\backup.hive",
		},
		{
			name: "dynamic source identity",
			command: "reg save HKLM\\%HIVE% C:\\Temp\\one.hive\n" +
				"reg save HKLM\\SYSTEM C:\\Temp\\system.hive",
		},
		{
			name: "pipeline is not a bounded pair",
			command: "reg save HKLM\\SAM C:\\Temp\\sam.hive | " +
				"reg save HKLM\\SYSTEM C:\\Temp\\system.hive",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command,
				CWD: `C:\repo`, DialectHint: DialectCMD,
			})
			if got := SensitiveRegistryHiveDumpPair(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}

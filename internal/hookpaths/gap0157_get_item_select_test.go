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

package hookpaths

import "testing"

// TestGetItemSelectObjectIsADisplayOfTheProtectedFile (rel-1-0-10:GAP-0157):
// Get-Item <key file> | Select-Object Length,LastWriteTime shows properties of
// the file and writes nothing, as Get-Item <key file> | Format-List does. A
// later stage that is not a read, or a common parameter that stores the
// object in a variable, still holds the call as a protected target.
func TestGetItemSelectObjectIsADisplayOfTheProtectedFile(t *testing.T) {
	const key = `C:\Users\alice\.ssh\authorized_keys`
	for _, test := range []struct {
		name, command, want string
	}{
		{"select properties", `Get-Item ` + key + ` | Select-Object Length,LastWriteTime`, ""},
		{"select alias", `gi ` + key + ` | select Length`, ""},
		{"plain Get-Item", `Get-Item ` + key, ""},
		{"Get-Acl into Set-Acl", `Get-Acl ` + key + ` | Set-Acl C:\work\x.txt`, "protected-target"},
		{"launcher Get-Content", `powershell -NoProfile -Command "Get-Content -Path ` + key + `"`, ""},
		{"launcher Get-Item select", `powershell -NoProfile -Command "Get-Item ` + key + ` | Select-Object Length,LastWriteTime"`, ""},
		{"launcher Get-Content into a writer", `powershell -NoProfile -Command "Get-Content ` + key + ` | Add-Content C:\work\x.txt"`, "protected-target"},
		{"launcher variable parameter", `powershell -NoProfile -Command "Get-Item ` + key + ` -OutVariable kept"`, "protected-target"},
		{"select then writer", `Get-Item ` + key + ` | Select-Object Length | Add-Content C:\work\x.txt`, "protected-target"},
		{"select expand then remove", `Get-Item ` + key + ` | Select-Object -ExpandProperty FullName | Remove-Item`, "protected-target"},
		{"select keeps the object in a variable", `Get-Item ` + key + ` | Select-Object -OutVariable kept`, "protected-target"},
		{"Get-Item keeps the object in a variable", `Get-Item ` + key + ` -OutVariable kept`, "protected-target"},
		{"abbreviated variable parameter", `gi ` + key + ` -ov kept`, "protected-target"},
		{"pipeline variable", `Get-Item ` + key + ` | Select-Object Length -PipelineVariable kept`, "protected-target"},
		{"writer without select", `Get-Item ` + key + ` | Add-Content C:\work\x.txt`, "protected-target"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var memo *TargetMemo
			got := memo.ActionCommandDecisionWithDialectAndGlobFacts(test.command, `C:\work`, `C:\Users\alice`, "powershell", nil)
			if got != test.want {
				t.Fatalf("decision = %q, want %q", got, test.want)
			}
		})
	}
}

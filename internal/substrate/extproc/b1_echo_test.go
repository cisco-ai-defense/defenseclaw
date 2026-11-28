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

package extproc

import "testing"

// TestB1CalloutNoInjectedRecordOnEchoHost: the callout leaves an echo host
// out of a binding without allow_echo, as the controller does, so it never
// records log.secret.injected for a request the value was not added to.
func TestB1CalloutNoInjectedRecordOnEchoHost(t *testing.T) {
	bs := compileBindings([]SecretBinding{
		{Name: "j45", Hosts: []string{"api.github.com", "httpbin.org", "echo.corp.example"}, Header: "Authorization"},
		{Name: "probe", Hosts: []string{"postman-echo.com"}, Header: "Authorization", AllowEcho: true},
	}, []string{"echo.corp.example"})
	for host, want := range map[string]int{"api.github.com": 1, "httpbin.org": 0, "echo.corp.example": 0, "postman-echo.com": 1} {
		if got := injectedSecrets(bs, host, "eng"); len(got) != want {
			t.Errorf("%s: %d injected, want %d", host, len(got), want)
		}
	}
}

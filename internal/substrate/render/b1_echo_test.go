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

package render

import (
	"slices"
	"strings"
	"testing"
)

// TestB1EchoHostBindingDropped: a secret bound to a host that returns the
// requests it gets (egressspec.EchoHosts or Settings.NoSwapHosts) is not
// added there (secret_echo_host, B1 D1-6) and opens no egress rule of its
// own; its other hosts keep the binding; inject.allow_echo keeps the echo.
func TestB1EchoHostBindingDropped(t *testing.T) {
	sec := func(name string, allow bool, hosts ...string) Secret {
		return Secret{Name: name, Source: "ate-secret://k8s.io/default/dc-secrets/" + name + "/token", Hosts: hosts,
			Header: "Authorization", Prefix: "Bearer ", Scope: ScopeShared, Profiles: []string{"*"}, AllowEcho: allow}
	}
	s := baseSettings()
	s.NoSwapHosts = []string{"echo.corp.example"}
	r, err := EgressPolicy(Input{Settings: s, Profile: Profile{Name: "eng"}, Secrets: []Secret{
		sec("j45", false, "api.github.com", "httpbin.org", "echo.corp.example"),
		sec("probe", true, "postman-echo.com"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var bound []string
	for _, b := range r.Bindings {
		bound = append(bound, b.Secret+"@"+b.Host)
	}
	slices.Sort(bound)
	if !slices.Equal(bound, []string{"j45@api.github.com", "probe@postman-echo.com"}) {
		t.Fatalf("bindings %v", bound)
	}
	var echo []string
	for _, d := range r.Dropped {
		if d.Reason == ReasonSecretEchoHost {
			echo = append(echo, d.Secret+"@"+d.Host+"="+d.Detail)
		}
	}
	slices.Sort(echo)
	if !slices.Equal(echo, []string{"j45@echo.corp.example=echo.corp.example", "j45@httpbin.org=httpbin.org"}) {
		t.Fatalf("echo drops %v", echo)
	}
	if p := r.Policy.String(); strings.Contains(p, "httpbin.org") || strings.Contains(p, "echo.corp.example") {
		t.Fatalf("a dropped echo binding opened egress: %s", p)
	}
}

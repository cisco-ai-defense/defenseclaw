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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestB1DoctorSecretEchoHost: the doctor row substrate.secret_echo_host
// fails, with the allow_echo fix, for an admin secret bound to an echo host
// after the upgrade (B1 D1-6); it warns for an allow_echo entry and passes
// otherwise.
func TestB1DoctorSecretEchoHost(t *testing.T) {
	sec := func(name string, allow bool, hosts ...string) config.SubstrateSecret {
		return config.SubstrateSecret{Name: name, Inject: config.SubstrateSecretInject{Hosts: hosts, Header: "Authorization", AllowEcho: allow}}
	}
	if c := SubstrateSecretEchoHostCheck([]config.SubstrateSecret{sec("gh", false, "api.github.com")}, nil); c.Status != "pass" {
		t.Fatalf("clean %+v", c)
	}
	c := SubstrateSecretEchoHostCheck([]config.SubstrateSecret{sec("j45", false, "httpbin.org", "eu.httpbin.org"), sec("gh", false, "echo.corp.example")},
		[]string{"echo.corp.example"})
	if c.ID != "substrate.secret_echo_host" || c.Status != "fail" || !strings.Contains(c.Detail, "j45 (httpbin.org, *.httpbin.org)") ||
		!strings.Contains(c.Detail, "gh (echo.corp.example)") || !strings.Contains(c.Fix, "inject.allow_echo: true") {
		t.Fatalf("echo %+v", c)
	}
	if c := SubstrateSecretEchoHostCheck([]config.SubstrateSecret{sec("probe", true, "postman-echo.com")}, nil); c.Status != "warn" {
		t.Fatalf("allow_echo %+v", c)
	}
}

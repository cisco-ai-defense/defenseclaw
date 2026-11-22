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

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0405 / B1 D1-6: an echo-host binding is dropped by the controller and
// failed by the doctor, so the start line is left only for a secret whose
// entry keeps the echo with inject.allow_echo; it names the hosts, never the
// source.
func TestSubstrateEchoHostWarningsGAP0405(t *testing.T) {
	secret := func(name string, allow bool, hosts ...string) config.SubstrateSecret {
		return config.SubstrateSecret{Name: name, Source: "ate-secret://k8s.io/default/ns/tok-" + name,
			Inject: config.SubstrateSecretInject{Hosts: hosts, Header: "Authorization", Prefix: "Bearer ", AllowEcho: allow}}
	}
	lines := substrateEchoHostWarnings([]config.SubstrateSecret{
		secret("github", true, "api.github.com"),
		secret("j45", true, "httpbin.org", "eu.httpbin.org", "httpbin.org"),
		secret("hooks", false, "*.pipedream.net"),
		secret("corp", true, "echo.corp.example"),
	}, []string{"echo.corp.example"})
	if len(lines) != 2 {
		t.Fatalf("%d warnings, want 2 (j45, corp): %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], "secret j45 is injected on httpbin.org, *.httpbin.org,") ||
		!strings.Contains(lines[0], "inject.allow_echo") || strings.Contains(lines[0], "ate-secret://") {
		t.Errorf("j45 warning %q", lines[0])
	}
	if !strings.Contains(lines[1], "secret corp is injected on echo.corp.example") {
		t.Errorf("corp warning %q", lines[1])
	}
	if got := substrateEchoHostWarnings(nil, nil); got != nil {
		t.Errorf("warnings with no secrets: %q", got)
	}
}

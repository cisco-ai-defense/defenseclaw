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
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestPolicyDigestReportsWhetherTheGatewayAppliedIt: the lifecycle result's
// policy block is applied only when the running gateway's /health reports
// the digest the installed config computes to.
func TestPolicyDigestReportsWhetherTheGatewayAppliedIt(t *testing.T) {
	reported := "sha256:aa"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"policy":{"effective_digest":"` + reported + `"}}`))
	}))
	defer server.Close()
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	cfg := &config.Config{}
	cfg.Gateway.APIBind = host
	cfg.Gateway.APIPort, _ = strconv.Atoi(port)
	if got := gatewayReportedPolicyDigest(cfg); got != reported {
		t.Fatalf("gateway reported digest = %q, want %q", got, reported)
	}

	for digest, applied := range map[string]bool{reported: true, "sha256:bb": false} {
		state, ok := enterprisePolicyFromDigest([]byte(
			`{"effective_digest":"` + digest + `","config_generation":4,"gateway_reported_digest":"` + reported + `"}`))
		if !ok || state.ConfigGeneration != 4 || state.Applied != applied {
			t.Fatalf("digest %s: state=%+v ok=%v, want applied=%v", digest, state, ok, applied)
		}
	}
	if _, ok := enterprisePolicyFromDigest([]byte(`{}`)); ok {
		t.Fatal("a report without a digest must not become a policy block")
	}
}

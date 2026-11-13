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
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const oldAdoptedMarkerLine = "# defenseclaw: adopted gateway token sha256=0000\n"

// R-TOK: the parent readiness credential is never the OpenClaw gateway
// token, in any 1.0.8 / 1.0.9 layout. With no separate master the child
// mints one and reports it through the running-token file.
func TestDaemonGatewayTokenNeverReturnsTheOpenClawToken(t *testing.T) {
	for _, tc := range []struct {
		name, dotenv, tokenEnv, want string
	}{
		{"only OPENCLAW_GATEWAY_TOKEN, token_env names it", "OPENCLAW_GATEWAY_TOKEN=oc-token\n", "OPENCLAW_GATEWAY_TOKEN", ""},
		{"both names hold the OpenClaw token", "DEFENSECLAW_GATEWAY_TOKEN=oc-token\nOPENCLAW_GATEWAY_TOKEN=oc-token\n" + oldAdoptedMarkerLine, "", ""},
		{"separate master", "DEFENSECLAW_GATEWAY_TOKEN=master-token\nOPENCLAW_GATEWAY_TOKEN=oc-token\n" + oldAdoptedMarkerLine, "OPENCLAW_GATEWAY_TOKEN", "master-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			if err := os.WriteFile(filepath.Join(home, ".env"), []byte(tc.dotenv), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
			t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
			cfg := config.DefaultConfig()
			cfg.Gateway.Token = ""
			cfg.Gateway.TokenEnv = tc.tokenEnv
			if got := daemonGatewayToken(cfg); got != tc.want {
				t.Fatalf("token = %q, want %q", got, tc.want)
			}
		})
	}
}

// Both credentials load from .env as saved; the old adoption comment hides
// neither, and the gateway token resolves to the separate master even when
// token_env still names OPENCLAW_GATEWAY_TOKEN.
func TestLoadDotEnvIntoOSKeepsBothGatewayCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	body := "DEFENSECLAW_GATEWAY_TOKEN=master-token\nOPENCLAW_GATEWAY_TOKEN=oc-token\n" + oldAdoptedMarkerLine
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	loadDotEnvIntoOS(path)
	if got := os.Getenv("OPENCLAW_GATEWAY_TOKEN"); got != "oc-token" {
		t.Fatalf("OPENCLAW_GATEWAY_TOKEN = %q, want oc-token", got)
	}
	gw := config.DefaultConfig().Gateway
	gw.TokenEnv = "OPENCLAW_GATEWAY_TOKEN"
	gw.OpenClawToken = "oc-token"
	if got := gw.ResolvedToken(); got != "master-token" {
		t.Fatalf("resolved token = %q, want master-token", got)
	}
}

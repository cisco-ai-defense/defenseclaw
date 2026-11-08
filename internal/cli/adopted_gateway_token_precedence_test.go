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
	"github.com/defenseclaw/defenseclaw/internal/envvars"
)

func editedGatewayTokenDotenv() string {
	return "DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n" +
		envvars.AdoptedGatewayTokenMarker("adopted") + "\n"
}

func TestDaemonGatewayTokenPrefersAnEditedSpellingOverTheAdoptedCopy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte(editedGatewayTokenDotenv()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	cfg := config.DefaultConfig()
	cfg.Gateway.Token = ""
	if got := daemonGatewayToken(cfg); got != "edited" {
		t.Fatalf("token = %q, want the edited token", got)
	}
}

func TestLoadDotEnvIntoOSLeavesOutTheAdoptedCopyOfAnEditedGatewayToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(editedGatewayTokenDotenv()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	loadDotEnvIntoOS(path)
	gw := config.DefaultConfig().Gateway
	if got := gw.ResolvedToken(); got != "edited" {
		t.Fatalf("resolved token = %q, want the edited token", got)
	}
}

func TestLoadDotEnvIntoOSKeepsAnUneditedAdoptedGatewayToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	body := "DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n" + envvars.AdoptedGatewayTokenMarker("adopted") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	loadDotEnvIntoOS(path)
	if got := os.Getenv("DEFENSECLAW_GATEWAY_TOKEN"); got != "adopted" {
		t.Fatalf("DEFENSECLAW_GATEWAY_TOKEN = %q, want adopted", got)
	}
}

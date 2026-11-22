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

package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// R-TOK: DEFENSECLAW_GATEWAY_TOKEN (the gateway token) and
// OPENCLAW_GATEWAY_TOKEN (the OpenClaw WebSocket credential) are separate
// credentials. The child gets both from .env as saved, a stale parent value
// is replaced, and the comment a 1.0.9 auth repair left in .env hides
// neither.
func TestChildEnvPassesBothGatewayCredentialsAsSaved(t *testing.T) {
	dir := t.TempDir()
	body := "DEFENSECLAW_GATEWAY_TOKEN=master-token\nOPENCLAW_GATEWAY_TOKEN=oc-token\n" +
		"# defenseclaw: adopted gateway token sha256=0000\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := envMap(New(dir).childEnv([]string{"PATH=/bin", "DEFENSECLAW_GATEWAY_TOKEN=stale-parent"}))
	if got["DEFENSECLAW_GATEWAY_TOKEN"] != "master-token" {
		t.Errorf("DEFENSECLAW_GATEWAY_TOKEN = %q, want master-token", got["DEFENSECLAW_GATEWAY_TOKEN"])
	}
	if got["OPENCLAW_GATEWAY_TOKEN"] != "oc-token" {
		t.Errorf("OPENCLAW_GATEWAY_TOKEN = %q, want oc-token", got["OPENCLAW_GATEWAY_TOKEN"])
	}
}

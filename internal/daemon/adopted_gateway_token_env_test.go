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

	"github.com/defenseclaw/defenseclaw/internal/envvars"
)

func TestChildEnvLeavesOutTheAdoptedCopyOfAnEditedGatewayToken(t *testing.T) {
	dir := t.TempDir()
	body := "DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n" +
		envvars.AdoptedGatewayTokenMarker("adopted") + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := envMap(New(dir).childEnv([]string{"PATH=/bin", "DEFENSECLAW_GATEWAY_TOKEN=stale-parent"}))
	if v, ok := got["DEFENSECLAW_GATEWAY_TOKEN"]; ok {
		t.Errorf("DEFENSECLAW_GATEWAY_TOKEN = %q, want it left out", v)
	}
	if got["OPENCLAW_GATEWAY_TOKEN"] != "edited" {
		t.Errorf("OPENCLAW_GATEWAY_TOKEN = %q, want the edited token", got["OPENCLAW_GATEWAY_TOKEN"])
	}
}

func TestChildEnvKeepsBothSpellingsOfAnUneditedAdoptedGatewayToken(t *testing.T) {
	dir := t.TempDir()
	body := "DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n" +
		envvars.AdoptedGatewayTokenMarker("adopted") + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := envMap(New(dir).childEnv([]string{"PATH=/bin"}))
	if got["DEFENSECLAW_GATEWAY_TOKEN"] != "adopted" || got["OPENCLAW_GATEWAY_TOKEN"] != "adopted" {
		t.Errorf("env = %v, want both spellings", got)
	}
}

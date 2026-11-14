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

//go:build !windows

package gateway

import (
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func runtimeKeysConfig(sb *config.SandboxAdminConfig) *config.Config {
	cfg := &config.Config{}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"eng": {Sandbox: sb}}
	return cfg
}

func TestSubstrateUnattendedAskFor(t *testing.T) {
	cfg := runtimeKeysConfig(nil)
	if got := SubstrateUnattendedAskFor(cfg, "eng"); got.Queue {
		t.Fatalf("default = %+v, want deny (D12)", got)
	}
	cfg.Substrate.Unattended.Asks = "queue"
	if got := SubstrateUnattendedAskFor(cfg, "eng"); !got.Queue || got.Timeout != config.DefaultSubstrateAskTimeout {
		t.Fatalf("cluster queue = %+v", got)
	}
	cfg = runtimeKeysConfig(&config.SandboxAdminConfig{UnattendedAsks: "queue", AskTimeout: "10m"})
	if got := SubstrateUnattendedAskFor(cfg, "eng"); !got.Queue || got.Timeout != 10*time.Minute {
		t.Fatalf("profile queue = %+v", got)
	}
	cfg.Substrate.Admin.UnattendedAsks = "deny"
	if got := SubstrateUnattendedAskFor(cfg, "eng"); got.Queue {
		t.Fatalf("substrate.admin deny must win: %+v", got)
	}
	// A floor that cannot be computed denies.
	cfg = runtimeKeysConfig(&config.SandboxAdminConfig{UnattendedAsks: "queue", Runtimes: []string{"substrate"}})
	cfg.Substrate.Admin.Runtimes = []string{"openshell"}
	if got := SubstrateUnattendedAskFor(cfg, "eng"); got.Queue {
		t.Fatalf("contradiction must deny: %+v", got)
	}
}

func TestSubstrateExposedValues(t *testing.T) {
	dir := t.TempDir()
	for name, v := range map[string]string{"db-password": "s3cr3t-value-123\n", "short": "abc"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := runtimeKeysConfig(&config.SandboxAdminConfig{ActorSecrets: []string{"db-password", "short", "missing"}})
	if SubstrateExposedValues(cfg, "") != nil {
		t.Fatal("no directory must give no check")
	}
	values := SubstrateExposedValues(cfg, dir)("eng")
	if len(values) != 1 || values["db-password"] != "s3cr3t-value-123" {
		t.Fatalf("values = %v", len(values))
	}
	if v := SubstrateExposedValues(cfg, dir)("other"); v != nil {
		t.Fatal("a profile without actor_secrets exposes nothing")
	}
	for _, body := range []string{`{"prompt":"s3cr3t-value-123"}`, `{"b64":"` + base64.StdEncoding.EncodeToString([]byte("s3cr3t-value-123")) + `"}`} {
		if name, ok := substrateExposedValueIn([]byte(body), values); !ok || name != "db-password" {
			t.Fatalf("missed in %q", body)
		}
	}
	quoted := map[string]string{"q": `a"b\c-12345`}
	if _, ok := substrateExposedValueIn([]byte(`{"p":"a\"b\\c-12345"}`), quoted); !ok {
		t.Fatal("a JSON-escaped value was missed")
	}
	if _, ok := substrateExposedValueIn([]byte(`{"prompt":"hello"}`), values); ok {
		t.Fatal("false match")
	}
}

// /llm refuses a model call that carries the actor's exposed value, and
// forwards the same call without it with the body intact.
func TestSubstrateLLMRefusesAnExposedValue(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "anthropic"), []byte("real-anthropic-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	var forwarded string
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		forwarded = string(b)
		_, _ = w.Write([]byte("ok"))
	})
	h, err := NewSubstrateLLMHandler(SubstrateLLMConfig{
		Providers: DefaultSubstrateLLMProviders(dir, "us-east-1"), Proxy: proxy,
		ExposedValues: func(profile string) map[string]string {
			if profile != "eng" {
				return nil
			}
			return map[string]string{"db-password": "s3cr3t-value-123"}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.LLM = h })
	rec := f.do(t, f.actor, http.MethodPost, "/llm/anthropic/v1/messages", "tok-alice", `{"messages":[{"content":"pw is s3cr3t-value-123"}]}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "exposed_secret_in_request") ||
		strings.Contains(rec.Body.String(), "s3cr3t") || forwarded != "" {
		t.Fatalf("exposed value: %d %s (forwarded %q)", rec.Code, rec.Body.String(), forwarded)
	}
	body := `{"messages":[{"content":"hello"}]}`
	rec = f.do(t, f.actor, http.MethodPost, "/llm/anthropic/v1/messages", "tok-alice", body)
	if rec.Code != http.StatusOK || forwarded != body {
		t.Fatalf("clean call: %d, forwarded %q", rec.Code, forwarded)
	}
}

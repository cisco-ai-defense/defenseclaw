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

//go:build openshell_integration

package image

// Live overlay build against a real Docker daemon and the digest-pinned
// community base. Opt-in:
//
//	DEFENSECLAW_E2E_DATA_DIR=<dir> \
//	DEFENSECLAW_E2E_IMAGE_REPO=e-defenseclaw-sandbox \
//	DEFENSECLAW_E2E_ANTHROPIC_URL=http://127.0.0.1:<mock> \
//	DEFENSECLAW_E2E_OPENAI_URL=http://127.0.0.1:<mock> \
//	go test -tags openshell_integration ./internal/openshell/image/ -run TestLiveOverlay -v -timeout 60m
//
// The mock URLs are the harness-spike servers (mock_anthropic.py with
// scripts-claude.json, mock_openai.py with scripts-codex.json): "write the
// marker" answers with one allowed shell tool call and "BLOCKME" with one the
// stand-in ingress denies; for Claude Code the probe repeats "write the
// marker" with hostile user and project settings planted. Without them the
// hook-fire probe is skipped.

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

func TestLiveOverlay(t *testing.T) {
	dataDir := os.Getenv("DEFENSECLAW_E2E_DATA_DIR")
	if dataDir == "" {
		t.Skip("set DEFENSECLAW_E2E_DATA_DIR to run the live overlay build")
	}
	repo := os.Getenv("DEFENSECLAW_E2E_IMAGE_REPO")
	if repo == "" {
		repo = "e-defenseclaw-sandbox"
	}
	ingress := 18971
	if v := os.Getenv("DEFENSECLAW_E2E_INGRESS_PORT"); v != "" {
		var err error
		if ingress, err = strconv.Atoi(v); err != nil {
			t.Fatal(err)
		}
	}
	b := &Builder{Docker: CLI{}, Store: NewStore(dataDir), Log: testLogWriter{t}}
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Minute)
	defer cancel()

	type scenario struct {
		spec  *harness.Spec
		env   map[string]string
		args  []string
		ready bool
	}
	anthropic := os.Getenv("DEFENSECLAW_E2E_ANTHROPIC_URL")
	openai := os.Getenv("DEFENSECLAW_E2E_OPENAI_URL")
	scenarios := []scenario{
		{
			spec:  harness.ClaudeCode,
			env:   map[string]string{"ANTHROPIC_BASE_URL": anthropic, "ANTHROPIC_API_KEY": "sk-ant-mock-0123456789abcdefghij"},
			args:  []string{"--output-format", "json"},
			ready: anthropic != "",
		},
		{
			spec: harness.Codex,
			env:  map[string]string{"OPENAI_API_KEY": "sk-mock-0123456789"},
			args: []string{
				"-c", `model_provider="mock"`, "-c", `model_providers.mock.name="mock"`,
				"-c", `model_providers.mock.base_url="` + openai + `/v1"`,
				"-c", `model_providers.mock.env_key="OPENAI_API_KEY"`, "-c", `model_providers.mock.wire_api="responses"`,
				// Codex sends its default model's tools in a "responses lite"
				// input item the mock does not read; an unknown model gets the
				// classic tools field.
				"-m", "mock-model",
			},
			ready: openai != "",
		},
	}
	for _, sc := range scenarios {
		t.Run(sc.spec.Name, func(t *testing.T) {
			spec := BuildSpec{
				Harness:            sc.spec,
				UID:                os.Getuid(),
				GID:                os.Getgid(),
				IngressPort:        ingress,
				DefenseClawVersion: "0.0.0-e2e",
				Repository:         repo,
			}
			rec, err := b.Build(ctx, spec, BuildOptions{})
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			pretty, _ := json.MarshalIndent(rec, "", "  ")
			t.Logf("built and verified:\n%s", pretty)
			if !sc.ready {
				t.Skip("mock LLM URL not set; hook-fire probe skipped")
			}
			c, err := b.Context(spec)
			if err != nil {
				t.Fatal(err)
			}
			verified, res, err := b.VerifyHooks(ctx, c, HookFireOptions{
				Env:             sc.env,
				Args:            sc.args,
				Prompt:          "write the marker",
				Block:           &BlockScenario{Prompt: "BLOCKME", Marker: "BLOCKME", SideEffect: "/tmp/blocked.txt"},
				ContainerPrefix: "e-hookfire",
			})
			report, _ := json.MarshalIndent(res, "", "  ")
			t.Logf("hook-fire result:\n%s", report)
			if err != nil {
				t.Fatal(err)
			}
			current, ok, err := b.Store.Current(c)
			if err != nil || !ok || current.Tag != rec.Tag || !verified.HookFireVerified {
				t.Fatalf("current = %+v %t %v after a passing hook-fire probe", current, ok, err)
			}
		})
	}
	report, err := b.Prune(ctx, PruneOptions{Repository: repo})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	t.Logf("prune: removed=%v kept=%v stale=%v", report.Removed, report.Kept, report.ForgottenStale)
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

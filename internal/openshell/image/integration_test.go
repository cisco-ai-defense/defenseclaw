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
//	go test -tags openshell_integration ./internal/openshell/image/ -run TestLiveOverlay -v -timeout 60m
//
// Build runs the hook-fire probe itself against the built-in mock LLM
// (allow, BLOCKME and, for Claude Code, hostile user and project settings)
// on the platform's default network, so no model or mock server is needed.
// DEFENSECLAW_E2E_HOOKFIRE_RELAY_SINK=<address> (for example the Linux
// docker0 gateway 172.17.0.1) additionally re-verifies each image in relay
// mode, the Docker Desktop default, with the sink bound on that address.

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
	relaySink := os.Getenv("DEFENSECLAW_E2E_HOOKFIRE_RELAY_SINK")

	for _, h := range []*harness.Spec{harness.ClaudeCode, harness.Codex} {
		t.Run(h.Name, func(t *testing.T) {
			spec := BuildSpec{
				Harness:            h,
				UID:                os.Getuid(),
				GID:                os.Getgid(),
				IngressPort:        ingress,
				DefenseClawVersion: "0.0.0-e2e",
				Repository:         repo,
			}
			rec, err := b.Build(ctx, spec, BuildOptions{HookFire: HookFireOptions{ContainerPrefix: "e-hookfire"}})
			pretty, _ := json.MarshalIndent(rec, "", "  ")
			t.Logf("build record:\n%s", pretty)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if !rec.HookFireVerified {
				t.Fatal("Build returned an image whose hooks were not verified")
			}
			current, ok, err := b.Current(spec)
			if err != nil || !ok || current.Tag != rec.Tag {
				t.Fatalf("current = %+v %t %v after a verified build", current, ok, err)
			}
			if relaySink == "" {
				return
			}
			c, err := b.Context(spec)
			if err != nil {
				t.Fatal(err)
			}
			verified, res, err := b.VerifyHooks(ctx, c, HookFireOptions{Network: HookFireNetworkRelay, SinkHost: relaySink, ContainerPrefix: "e-hookfire"})
			report, _ := json.MarshalIndent(res, "", "  ")
			t.Logf("relay-mode hook-fire result:\n%s", report)
			if err != nil || !verified.HookFireVerified {
				t.Fatalf("relay-mode VerifyHooks: %v", err)
			}
		})
	}
	report, err := b.Prune(ctx, PruneOptions{Repository: repo})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	t.Logf("prune: removed=%v kept=%v stale=%v unrecorded=%v foreign=%v", report.Removed, report.Kept, report.ForgottenStale, report.Unrecorded, report.Foreign)
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

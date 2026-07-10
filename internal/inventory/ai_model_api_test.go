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

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDetectLocalAPIModelsLemonadeInstalledAndLoaded(t *testing.T) {
	var device atomic.Value
	device.Store("gpu")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/models":
			_, _ = w.Write([]byte(`{
				"object":"list",
				"data":[{
					"id":"Qwen3-0.6B-GGUF",
					"owned_by":"lemonade",
					"checkpoint":"unsloth/Qwen3-0.6B-GGUF:Q4_0.gguf",
					"recipe":"llamacpp",
					"size":0.38,
					"downloaded":true
				}]
			}`))
		case "/v1/health":
			_, _ = fmt.Fprintf(w, `{
				"status":"ok",
				"version":"10.8.0",
				"all_models_loaded":[{
					"model_name":"Qwen3-0.6B-GGUF",
					"checkpoint":"unsloth/Qwen3-0.6B-GGUF:Q4_0.gguf",
					"type":"llm",
					"device":%q,
					"recipe":"llamacpp",
					"pid":4242,
					"pinned":true,
					"last_use":1732123456789,
					"loaded":true,
					"backend_alive":true,
					"backend_url":"http://127.0.0.1:8123/v1"
				}]
			}`, device.Load().(string))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	setLemonadeTestTarget(t, server.URL)

	svc := &ContinuousDiscoveryService{catalog: []AISignature{lemonadeAPITestSignature(server.URL)}}
	first, files, err := svc.detectLocalAPIModels(context.Background())
	if err != nil {
		t.Fatalf("detectLocalAPIModels: %v", err)
	}
	if files != 0 {
		t.Fatalf("files_scanned = %d, want 0 for HTTP probes", files)
	}
	if len(first) != 2 {
		t.Fatalf("signals = %d, want installed + loaded: %+v", len(first), first)
	}

	installed := findModelSignal(t, first, "model_api", "Qwen3-0.6B-GGUF")
	loaded := findModelSignal(t, first, "model_runtime", "Qwen3-0.6B-GGUF")
	if installed.Product != "Lemonade" || installed.Vendor != "AMD" || installed.Name != "Lemonade" {
		t.Fatalf("installed provider labels are dynamic: %+v", installed)
	}
	if installed.Model.Provider != "lemonade" || installed.Model.Status != "installed" {
		t.Fatalf("installed model = %+v", installed.Model)
	}
	if installed.Model.Format != "gguf" || installed.Model.Recipe != "llamacpp" || installed.Model.SizeBytes != 380_000_000 {
		t.Fatalf("installed metadata = %+v", installed.Model)
	}
	if loaded.Model.Status != "loaded" || loaded.Model.Modality != "llm" || loaded.Model.Device != "gpu" || !loaded.Model.Pinned {
		t.Fatalf("loaded metadata = %+v", loaded.Model)
	}
	if loaded.Runtime == nil || loaded.Runtime.PID != 4242 {
		t.Fatalf("loaded runtime = %+v", loaded.Runtime)
	}
	wantLastUse := time.UnixMilli(1732123456789).UTC()
	if loaded.LastActiveAt == nil || !loaded.LastActiveAt.Equal(wantLastUse) {
		t.Fatalf("last_active_at = %v, want %v", loaded.LastActiveAt, wantLastUse)
	}
	if installed.Fingerprint == loaded.Fingerprint {
		t.Fatal("installed and loaded detectors must have distinct fingerprints")
	}

	// Runtime metadata changes must retain identity but change evidence. The
	// ephemeral last_use timestamp itself is intentionally not part of the
	// hash; device/recipe/PID/pinned changes are.
	device.Store("gpu npu")
	second, _, err := svc.detectLocalAPIModels(context.Background())
	if err != nil {
		t.Fatalf("second detectLocalAPIModels: %v", err)
	}
	loadedAgain := findModelSignal(t, second, "model_runtime", "Qwen3-0.6B-GGUF")
	if loadedAgain.Fingerprint != loaded.Fingerprint {
		t.Fatalf("fingerprint changed with metadata: %q != %q", loadedAgain.Fingerprint, loaded.Fingerprint)
	}
	if loadedAgain.EvidenceHash == loaded.EvidenceHash {
		t.Fatal("evidence hash did not change with device metadata")
	}

	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), server.URL) || strings.Contains(string(raw), "backend_url") || strings.Contains(string(raw), "http://127.0.0.1:8123") {
		t.Fatalf("raw URL escaped model signals: %s", raw)
	}
}

func TestDetectLocalAPIModelsLemonadeFiltersCloudAndNotDownloaded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/health":
			_, _ = w.Write([]byte(`{"status":"ok","all_models_loaded":[]}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[
				{"id":"not-here","owned_by":"lemonade","downloaded":false,"recipe":"llamacpp"},
				{"id":"fireworks.remote","owned_by":"lemonade","downloaded":true,"recipe":"cloud"},
				{"id":"local-model","owned_by":"lemonade","downloaded":true,"recipe":"llamacpp"}
			]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	setLemonadeTestTarget(t, server.URL)

	svc := &ContinuousDiscoveryService{catalog: []AISignature{lemonadeAPITestSignature(server.URL)}}
	signals, _, err := svc.detectLocalAPIModels(context.Background())
	if err != nil {
		t.Fatalf("detectLocalAPIModels: %v", err)
	}
	if len(signals) != 1 || signals[0].Model == nil || signals[0].Model.ID != "local-model" {
		t.Fatalf("filtered signals = %+v", signals)
	}
}

func TestDetectLocalAPIModelsOllamaTagsAndPS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{
				"name":"qwen2.5:latest",
				"size":1234,
				"digest":"sha256:abc",
				"modified_at":"2026-07-01T00:00:00Z",
				"details":{"format":"gguf"}
			}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[{
				"model":"qwen2.5:latest",
				"size":1234,
				"size_vram":900,
				"expires_at":"2026-07-09T12:00:00Z",
				"details":{"format":"gguf"}
			}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	sig := AISignature{
		ID:             "ollama",
		Name:           "Ollama",
		Vendor:         "Ollama",
		Confidence:     0.9,
		LocalEndpoints: []string{server.URL + "/api/tags"},
	}
	svc := &ContinuousDiscoveryService{catalog: []AISignature{sig}}
	signals, _, err := svc.detectLocalAPIModels(context.Background())
	if err != nil {
		t.Fatalf("detectLocalAPIModels: %v", err)
	}
	if len(signals) != 2 {
		t.Fatalf("signals = %d, want 2: %+v", len(signals), signals)
	}
	installed := findModelSignal(t, signals, "model_api", "qwen2.5:latest")
	loaded := findModelSignal(t, signals, "model_runtime", "qwen2.5:latest")
	if installed.Product != "Ollama" || loaded.Product != "Ollama" {
		t.Fatalf("model ID leaked into product: installed=%q loaded=%q", installed.Product, loaded.Product)
	}
	if installed.Model.Format != "gguf" || installed.Model.SizeBytes != 1234 || installed.Model.Provider != "ollama" {
		t.Fatalf("installed = %+v", installed.Model)
	}
	if loaded.Model.Status != "loaded" || loaded.Model.SizeBytes != 1234 {
		t.Fatalf("loaded = %+v", loaded.Model)
	}
}

func TestDetectLocalAPIModelsLemonadeUsesRegularBearerAndIsNotEmitted(t *testing.T) {
	const adminToken = "admin-super-secret"
	const apiToken = "regular-super-secret"
	var authorized atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/live" {
			if r.Header.Get("Authorization") != "" {
				t.Error("liveness verification received a bearer token")
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+apiToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		authorized.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			_, _ = w.Write([]byte(`{"status":"ok","all_models_loaded":[]}`))
			return
		}
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"secured-model","owned_by":"lemonade","downloaded":true,"recipe":"llamacpp"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	setLemonadeTestTarget(t, server.URL)
	t.Setenv("LEMONADE_ADMIN_API_KEY", adminToken)
	t.Setenv("LEMONADE_API_KEY", apiToken)

	svc := &ContinuousDiscoveryService{catalog: []AISignature{lemonadeAPITestSignature(server.URL)}}
	signals, _, err := svc.detectLocalAPIModels(context.Background())
	if err != nil {
		t.Fatalf("detectLocalAPIModels: %v", err)
	}
	if authorized.Load() != 2 {
		t.Fatalf("authorized requests = %d, want health + models", authorized.Load())
	}
	if len(signals) != 1 {
		t.Fatalf("signals = %+v", signals)
	}
	raw, _ := json.Marshal(signals)
	if strings.Contains(string(raw), adminToken) || strings.Contains(string(raw), apiToken) {
		t.Fatalf("bearer token leaked: %s", raw)
	}
}

func TestDetectLocalAPIModelsLemonadeNeverSendsAdminBearer(t *testing.T) {
	const adminToken = "admin-super-secret"
	var authorization atomic.Value
	authorization.Store("")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization.Store(r.Header.Get("Authorization"))
		if r.URL.Path == "/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/health" {
			_, _ = w.Write([]byte(`{"status":"ok","all_models_loaded":[]}`))
			return
		}
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	setLemonadeTestTarget(t, server.URL)
	t.Setenv("LEMONADE_ADMIN_API_KEY", adminToken)
	t.Setenv("LEMONADE_API_KEY", "")

	svc := &ContinuousDiscoveryService{catalog: []AISignature{lemonadeAPITestSignature(server.URL)}}
	if _, _, err := svc.detectLocalAPIModels(context.Background()); err != nil {
		t.Fatalf("detectLocalAPIModels: %v", err)
	}
	if got := authorization.Load().(string); got != "" {
		t.Fatalf("admin bearer was sent to a regular metadata endpoint: %q", got)
	}
}

func TestDetectLocalAPIModelsLemonadeDoesNotSendBearerToUntrustedListener(t *testing.T) {
	var bearerRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			bearerRequests.Add(1)
		}
		if r.URL.Path == "/live" {
			// A listener can spoof the public liveness route. That alone must
			// not make an arbitrary catalog-pack origin credential-eligible.
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "not lemonade", http.StatusUnauthorized)
	}))
	defer server.Close()
	t.Setenv("LEMONADE_HOST", "")
	t.Setenv("LEMONADE_PORT", "")
	t.Setenv("LEMONADE_CACHE_DIR", t.TempDir())
	t.Setenv("LEMONADE_ADMIN_API_KEY", "")
	t.Setenv("LEMONADE_API_KEY", "regular-super-secret")

	svc := &ContinuousDiscoveryService{catalog: []AISignature{lemonadeAPITestSignature(server.URL)}}
	if _, _, err := svc.detectLocalAPIModels(context.Background()); err != nil {
		t.Fatalf("detectLocalAPIModels: %v", err)
	}
	if got := bearerRequests.Load(); got != 0 {
		t.Fatalf("sent bearer to %d requests for an untrusted Lemonade origin", got)
	}
}

func TestDetectLocalAPIModelsRejectsMalformedAndOversizedBodies(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"data":[`))
		}))
		defer server.Close()
		svc := &ContinuousDiscoveryService{catalog: []AISignature{openAIAPITestSignature(server.URL)}}
		signals, _, err := svc.detectLocalAPIModels(context.Background())
		if err == nil || len(signals) != 0 {
			t.Fatalf("signals=%+v err=%v, want parse error", signals, err)
		}
		if strings.Contains(err.Error(), server.URL) {
			t.Fatalf("error leaks raw URL: %v", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.FormatInt(maxLocalModelAPIResponseBytes+1, 10))
			_, _ = w.Write([]byte(strings.Repeat("x", int(maxLocalModelAPIResponseBytes+1))))
		}))
		defer server.Close()
		svc := &ContinuousDiscoveryService{catalog: []AISignature{openAIAPITestSignature(server.URL)}}
		signals, _, err := svc.detectLocalAPIModels(context.Background())
		if !errors.Is(err, errLocalModelAPIResponseTooLarge) || len(signals) != 0 {
			t.Fatalf("signals=%+v err=%v, want response-too-large", signals, err)
		}
	})
}

func TestDetectLocalAPIModelsHonorsContextCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()

	svc := &ContinuousDiscoveryService{catalog: []AISignature{openAIAPITestSignature(server.URL)}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := svc.detectLocalAPIModels(ctx)
		done <- err
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("detector ignored context cancellation")
	}
}

func TestDetectLocalAPIModelsCapsItemCountAndRejectsUnsafeIDs(t *testing.T) {
	models := make([]map[string]any, 0, maxLocalModelAPIItems+20)
	models = append(models,
		map[string]any{"id": "bad\ncontrol"},
		map[string]any{"id": strings.Repeat("x", maxLocalModelIDBytes+1)},
	)
	for i := 0; i < maxLocalModelAPIItems+20; i++ {
		models = append(models, map[string]any{"id": fmt.Sprintf("model-%03d", i)})
	}
	body, _ := json.Marshal(map[string]any{"object": "list", "data": models})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	svc := &ContinuousDiscoveryService{catalog: []AISignature{openAIAPITestSignature(server.URL)}}
	signals, _, err := svc.detectLocalAPIModels(context.Background())
	if err != nil {
		t.Fatalf("detectLocalAPIModels: %v", err)
	}
	if len(signals) != maxLocalModelAPIItems {
		t.Fatalf("signals = %d, want cap %d", len(signals), maxLocalModelAPIItems)
	}
	for _, signal := range signals {
		if signal.Model == nil || strings.ContainsRune(signal.Model.ID, '\n') || len(signal.Model.ID) > maxLocalModelIDBytes {
			t.Fatalf("unsafe model ID emitted: %+v", signal.Model)
		}
		if signal.Product != "Test OpenAI Server" || signal.Vendor != "Fixed Vendor" || signal.Component != nil {
			t.Fatalf("unbounded label cardinality: %+v", signal)
		}
	}
}

func TestDetectLocalAPIModelsReusesCapacityFromAbsentProviders(t *testing.T) {
	models := make([]map[string]string, 200)
	for i := range models {
		models[i] = map[string]string{"id": fmt.Sprintf("only-live-%03d", i)}
	}
	body, _ := json.Marshal(map[string]any{"object": "list", "data": models})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	catalog := make([]AISignature, 0, 7)
	for i := 0; i < 6; i++ {
		catalog = append(catalog, AISignature{
			ID:             fmt.Sprintf("absent-%d", i),
			Name:           fmt.Sprintf("Absent %d", i),
			LocalEndpoints: []string{"http://127.0.0.1:1/v1/models"},
		})
	}
	live := openAIAPITestSignature(server.URL)
	live.ID = "zz-live"
	catalog = append(catalog, live)
	svc := &ContinuousDiscoveryService{catalog: catalog}
	signals, _, outcome, err := svc.detectLocalAPIModelsWithOutcome(context.Background())
	if err != nil {
		t.Fatalf("detectLocalAPIModelsWithOutcome: %v", err)
	}
	if len(signals) != len(models) {
		t.Fatalf("live provider models = %d, want %d; unused absent-provider quota was not recycled", len(signals), len(models))
	}
	liveKey := localModelAPICoverageKey(buildLocalModelAPIProbes([]AISignature{live})[0])
	if !outcome.conclusive[liveKey] || outcome.deferred[liveKey] {
		t.Fatalf("live provider outcome = %+v, want conclusive", outcome)
	}
}

func TestDetectLocalAPIModelsSharesGlobalCapAcrossLiveProviders(t *testing.T) {
	makeServer := func(prefix string) *httptest.Server {
		models := make([]map[string]string, 200)
		for i := range models {
			models[i] = map[string]string{"id": fmt.Sprintf("%s-%03d", prefix, i)}
		}
		body, _ := json.Marshal(map[string]any{"object": "list", "data": models})
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
	}
	firstServer := makeServer("first")
	defer firstServer.Close()
	secondServer := makeServer("second")
	defer secondServer.Close()
	firstSig := openAIAPITestSignature(firstServer.URL)
	firstSig.ID, firstSig.Name = "first", "First"
	secondSig := openAIAPITestSignature(secondServer.URL)
	secondSig.ID, secondSig.Name = "second", "Second"
	svc := &ContinuousDiscoveryService{catalog: []AISignature{firstSig, secondSig}}

	signals, _, outcome, err := svc.detectLocalAPIModelsWithOutcome(context.Background())
	if err != nil {
		t.Fatalf("detectLocalAPIModelsWithOutcome: %v", err)
	}
	if len(signals) != maxLocalModelAPIItems {
		t.Fatalf("signals = %d, want cap %d", len(signals), maxLocalModelAPIItems)
	}
	counts := map[string]int{}
	for _, signal := range signals {
		counts[signal.SignatureID]++
	}
	if counts["first"] != maxLocalModelAPIItems/2 || counts["second"] != maxLocalModelAPIItems/2 {
		t.Fatalf("unfair live-provider allocation: %+v", counts)
	}
	for _, sig := range []AISignature{firstSig, secondSig} {
		key := localModelAPICoverageKey(buildLocalModelAPIProbes([]AISignature{sig})[0])
		if !outcome.deferred[key] || outcome.conclusive[key] {
			t.Fatalf("partially emitted provider %q outcome = %+v, want deferred", sig.ID, outcome)
		}
	}
}

func TestDetectLocalAPIModelsOutcomeDistinguishesExactAndTruncatedCaps(t *testing.T) {
	for _, tc := range []struct {
		name       string
		modelCount int
		conclusive bool
		deferred   bool
	}{
		{name: "exact cap is conclusive", modelCount: maxLocalModelAPIItems, conclusive: true},
		{name: "cap plus one is deferred", modelCount: maxLocalModelAPIItems + 1, deferred: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			models := make([]map[string]string, 0, tc.modelCount)
			for i := 0; i < tc.modelCount; i++ {
				models = append(models, map[string]string{"id": fmt.Sprintf("model-%03d", i)})
			}
			body, _ := json.Marshal(map[string]any{"object": "list", "data": models})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}))
			defer server.Close()

			sig := openAIAPITestSignature(server.URL)
			svc := &ContinuousDiscoveryService{catalog: []AISignature{sig}}
			signals, _, outcome, err := svc.detectLocalAPIModelsWithOutcome(context.Background())
			if err != nil {
				t.Fatalf("detectLocalAPIModelsWithOutcome: %v", err)
			}
			if len(signals) != maxLocalModelAPIItems {
				t.Fatalf("signals = %d, want %d", len(signals), maxLocalModelAPIItems)
			}
			probe := buildLocalModelAPIProbes([]AISignature{sig})[0]
			key := localModelAPICoverageKey(probe)
			if outcome.conclusive[key] != tc.conclusive || outcome.deferred[key] != tc.deferred {
				t.Fatalf("outcome conclusive=%v deferred=%v, want %v/%v", outcome.conclusive[key], outcome.deferred[key], tc.conclusive, tc.deferred)
			}
		})
	}
}

func TestDetectLocalAPIModelsAdvancesPastTruncatedItemWindow(t *testing.T) {
	models := make([]map[string]string, maxLocalModelAPIItems+1)
	for i := range models {
		models[i] = map[string]string{"id": fmt.Sprintf("paged-%03d", i)}
	}
	body, _ := json.Marshal(map[string]any{"object": "list", "data": models})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	svc := &ContinuousDiscoveryService{catalog: []AISignature{openAIAPITestSignature(server.URL)}}

	first, _, _, err := svc.detectLocalAPIModelsWithOutcome(context.Background())
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first) != maxLocalModelAPIItems {
		t.Fatalf("first page signals = %d, want %d", len(first), maxLocalModelAPIItems)
	}
	second, _, outcome, err := svc.detectLocalAPIModelsWithOutcome(context.Background())
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second) != 1 || second[0].Model == nil || second[0].Model.ID != "paged-256" {
		t.Fatalf("second page did not advance to final model: %+v", second)
	}
	probe := buildLocalModelAPIProbes(svc.catalog)[0]
	key := localModelAPICoverageKey(probe)
	if !outcome.conclusive[key] || outcome.deferred[key] {
		t.Fatalf("resumed EOF outcome = %+v, want conclusive completed cycle", outcome)
	}
	if got := len(outcome.cycleSeen[key]); got != len(models) {
		t.Fatalf("completed cycle membership = %d, want %d", got, len(models))
	}
	third, _, _, err := svc.detectLocalAPIModelsWithOutcome(context.Background())
	if err != nil {
		t.Fatalf("third page: %v", err)
	}
	if len(third) != maxLocalModelAPIItems {
		t.Fatalf("cursor reset page signals = %d, want %d", len(third), maxLocalModelAPIItems)
	}
	findModelSignal(t, third, "model_api", "paged-000")
	for _, signal := range third {
		if signal.Model != nil && signal.Model.ID == "paged-256" {
			t.Fatalf("cursor reset page unexpectedly retained final-window model: %+v", signal.Model)
		}
	}
}

func TestUpdateLocalModelAPICyclePrunesAndRejectsOrphanResume(t *testing.T) {
	svc := &ContinuousDiscoveryService{}
	if _, overflow := svc.updateLocalModelAPICycle(
		"orphan", false, true, map[string]struct{}{"suffix": {}}, []string{"suffix"}, true,
	); !overflow {
		t.Fatal("resumed page without prefix cycle was treated as conclusive")
	}

	if _, overflow := svc.updateLocalModelAPICycle(
		"cycle", true, true,
		map[string]struct{}{"first": {}, "retained": {}},
		[]string{"first", "retained"}, false,
	); overflow {
		t.Fatal("bounded first page unexpectedly overflowed")
	}
	seen, overflow := svc.updateLocalModelAPICycle(
		"cycle", false, true,
		map[string]struct{}{"retained": {}},
		[]string{"last"}, true,
	)
	if overflow {
		t.Fatal("bounded completed cycle unexpectedly overflowed")
	}
	if len(seen) != 2 {
		t.Fatalf("completed membership = %+v, want retained + last", seen)
	}
	if _, ok := seen["retained"]; !ok {
		t.Fatal("completed membership lost retained prior fingerprint")
	}
	if _, ok := seen["last"]; !ok {
		t.Fatal("completed membership lost final-page fingerprint")
	}
	if _, ok := seen["first"]; ok {
		t.Fatal("completed membership retained a fingerprint evicted from durable prior")
	}
}

func TestDetectLocalAPIModelsAdvancesEachLiveGroupAfterRoundRobinCap(t *testing.T) {
	makeServer := func(prefix string) *httptest.Server {
		models := make([]map[string]string, 300)
		for i := range models {
			models[i] = map[string]string{"id": fmt.Sprintf("%s-%03d", prefix, i)}
		}
		body, _ := json.Marshal(map[string]any{"object": "list", "data": models})
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
	}
	firstServer := makeServer("first")
	defer firstServer.Close()
	secondServer := makeServer("second")
	defer secondServer.Close()
	firstSig := openAIAPITestSignature(firstServer.URL)
	firstSig.ID, firstSig.Name = "first", "First"
	secondSig := openAIAPITestSignature(secondServer.URL)
	secondSig.ID, secondSig.Name = "second", "Second"
	svc := &ContinuousDiscoveryService{catalog: []AISignature{firstSig, secondSig}}
	discovered := map[string]bool{}
	for page := 0; page < 3; page++ {
		signals, _, _, err := svc.detectLocalAPIModelsWithOutcome(context.Background())
		if err != nil {
			t.Fatalf("page %d: %v", page+1, err)
		}
		for _, signal := range signals {
			discovered[signal.Model.ID] = true
		}
	}
	for _, prefix := range []string{"first", "second"} {
		for i := 0; i < 300; i++ {
			id := fmt.Sprintf("%s-%03d", prefix, i)
			if !discovered[id] {
				t.Fatalf("model %q was skipped by round-robin cursor paging", id)
			}
		}
	}
}

func TestDetectLocalAPIModelsDefersEndpointsBeyondRequestCap(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer server.Close()

	catalog := make([]AISignature, 0, maxLocalModelAPIEndpoints+1)
	for i := 0; i < maxLocalModelAPIEndpoints+1; i++ {
		catalog = append(catalog, AISignature{
			ID:             fmt.Sprintf("provider-%02d", i),
			Name:           fmt.Sprintf("Provider %02d", i),
			LocalEndpoints: []string{server.URL + "/v1/models"},
		})
	}
	svc := &ContinuousDiscoveryService{catalog: catalog}
	_, _, outcome, err := svc.detectLocalAPIModelsWithOutcome(context.Background())
	if err != nil {
		t.Fatalf("detectLocalAPIModelsWithOutcome: %v", err)
	}
	if got := requests.Load(); got != maxLocalModelAPIEndpoints {
		t.Fatalf("requests = %d, want cap %d", got, maxLocalModelAPIEndpoints)
	}
	probes := buildLocalModelAPIProbes(catalog)
	lastKey := localModelAPICoverageKey(probes[len(probes)-1])
	if !outcome.deferred[lastKey] || outcome.attempted[lastKey] || outcome.conclusive[lastKey] {
		t.Fatalf("endpoint beyond cap was not deferred: %+v", outcome)
	}

	_, _, rotatedOutcome, err := svc.detectLocalAPIModelsWithOutcome(context.Background())
	if err != nil {
		t.Fatalf("rotated detectLocalAPIModelsWithOutcome: %v", err)
	}
	if !rotatedOutcome.attempted[lastKey] || !rotatedOutcome.conclusive[lastKey] {
		t.Fatalf("endpoint beyond first-pass cap was not sampled on rotation: %+v", rotatedOutcome)
	}
}

func TestRotateLocalModelAPIProbesAlternatesOriginsWithoutSplittingOriginOrder(t *testing.T) {
	probes := []localModelAPIProbe{
		{providerKey: "first", origin: "http://127.0.0.1:1001", endpoint: "http://127.0.0.1:1001/v1/health"},
		{providerKey: "second", origin: "http://127.0.0.1:1002", endpoint: "http://127.0.0.1:1002/v1/models"},
		{providerKey: "first", origin: "http://127.0.0.1:1001", endpoint: "http://127.0.0.1:1001/v1/models"},
	}
	svc := &ContinuousDiscoveryService{}
	first := svc.rotateLocalModelAPIProbes(probes)
	if first[0].origin != probes[0].origin || first[1].origin != probes[0].origin {
		t.Fatalf("first pass did not preserve first origin probe order: %+v", first)
	}
	second := svc.rotateLocalModelAPIProbes(probes)
	if second[0].origin != probes[1].origin {
		t.Fatalf("second pass did not rotate to later origin: %+v", second)
	}
	if second[1].endpoint != probes[0].endpoint || second[2].endpoint != probes[2].endpoint {
		t.Fatalf("rotation split/reordered probes within origin: %+v", second)
	}
}

func TestParseOpenAIModelsBoundsRejectedItemCount(t *testing.T) {
	items := make([]json.RawMessage, maxLocalModelAPIDecodedItems+1)
	for i := range items {
		items[i] = json.RawMessage(`{}`)
	}
	body, err := json.Marshal(map[string]any{"object": "list", "data": items})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	observations, _, truncated, nextCursor, _, err := parseOpenAIModels(body, false, maxLocalModelAPIItems, 0)
	if err != nil {
		t.Fatalf("parseOpenAIModels: %v", err)
	}
	if len(observations) != 0 || !truncated {
		t.Fatalf("rejected-item bound = observations:%d truncated:%v", len(observations), truncated)
	}
	if nextCursor <= 0 {
		t.Fatal("rejected-item page did not advance its bounded decoder cursor")
	}
	observations, _, truncated, finalCursor, resumed, err := parseOpenAIModels(
		body, false, maxLocalModelAPIItems, nextCursor,
	)
	if err != nil || len(observations) != 0 || !truncated || !resumed || finalCursor != 0 {
		t.Fatalf("rejected-item second page = observations:%d truncated:%v cursor:%d resumed:%v err:%v",
			len(observations), truncated, finalCursor, resumed, err)
	}
}

func TestLocalModelAPILifecycleDistinguishesTransientFailureFromEmptyInventory(t *testing.T) {
	var mode atomic.Int32 // 0=present, 1=transient failure, 2=valid empty
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch mode.Load() {
		case 1:
			http.Error(w, "restarting", http.StatusServiceUnavailable)
		case 2:
			_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
		default:
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"stable-model"}]}`))
		}
	}))
	defer server.Close()

	sig := openAIAPITestSignature(server.URL)
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", IncludeNetworkDomains: true,
		HomeDir: t.TempDir(), ScanRoots: []string{t.TempDir()}, DataDir: t.TempDir(),
		MaxFilesPerScan: 20, MaxFileBytes: 64 << 10,
	}, []AISignature{sig}, nil, nil)

	first, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if got := findModelSignal(t, first.Signals, "model_api", "stable-model"); got.State != AIStateNew {
		t.Fatalf("first state = %q, want new", got.State)
	}

	mode.Store(1)
	failed, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("failure scan: %v", err)
	}
	if got := findModelSignal(t, failed.Signals, "model_api", "stable-model"); got.State != AIStateSeen {
		t.Fatalf("transient failure flapped model lifecycle: state=%q", got.State)
	}

	mode.Store(0)
	recovered, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("recovery scan: %v", err)
	}
	if got := findModelSignal(t, recovered.Signals, "model_api", "stable-model"); got.State != AIStateSeen {
		t.Fatalf("recovered state = %q, want seen", got.State)
	}

	mode.Store(2)
	empty, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("empty scan: %v", err)
	}
	if got := findModelSignal(t, empty.Signals, "model_api", "stable-model"); got.State != AIStateGone {
		t.Fatalf("valid empty inventory state = %q, want gone", got.State)
	}
}

func TestLocalModelAPILifecycleCompletesPagedInventoryBeforeMarkingRemoval(t *testing.T) {
	const (
		modelCount = maxLocalModelAPIItems + 44
		removedID  = "paged-010"
	)
	var removed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		models := make([]map[string]string, 0, modelCount)
		for i := 0; i < modelCount; i++ {
			id := fmt.Sprintf("paged-%03d", i)
			if removed.Load() && id == removedID {
				continue
			}
			models = append(models, map[string]string{"id": id})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": models})
	}))
	defer server.Close()

	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", IncludeNetworkDomains: true,
		HomeDir: t.TempDir(), ScanRoots: []string{t.TempDir()}, DataDir: t.TempDir(),
		MaxFilesPerScan: 20, MaxFileBytes: 64 << 10,
	}, []AISignature{openAIAPITestSignature(server.URL)}, nil, nil)

	firstPage, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("initial first page: %v", err)
	}
	if got := findModelSignal(t, firstPage.Signals, "model_api", removedID); got.State != AIStateNew {
		t.Fatalf("initial first-page state = %q, want new", got.State)
	}
	initialEOF, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("initial EOF page: %v", err)
	}
	if got := findModelSignal(t, initialEOF.Signals, "model_api", "paged-020"); got.State != AIStateSeen {
		t.Fatalf("initial earlier-page survivor state = %q, want seen", got.State)
	}
	findModelSignal(t, initialEOF.Signals, "model_api", "paged-299")

	removed.Store(true)
	deletionFirstPage, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("deletion first page: %v", err)
	}
	if got := findModelSignal(t, deletionFirstPage.Signals, "model_api", removedID); got.State != AIStateSeen {
		t.Fatalf("partial deletion cycle marked removal early: state=%q", got.State)
	}

	deletionEOF, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("deletion EOF page: %v", err)
	}
	if got := findModelSignal(t, deletionEOF.Signals, "model_api", removedID); got.State != AIStateGone {
		t.Fatalf("completed deletion cycle state = %q, want gone", got.State)
	}
	if got := findModelSignal(t, deletionEOF.Signals, "model_api", "paged-020"); got.State != AIStateSeen {
		t.Fatalf("earlier-page survivor state = %q, want seen", got.State)
	}
	if got := findModelSignal(t, deletionEOF.Signals, "model_api", "paged-299"); got.State != AIStateSeen {
		t.Fatalf("EOF-page survivor state = %q, want seen", got.State)
	}
	if deletionEOF.Summary.GoneSignals != 1 {
		t.Fatalf("gone signals = %d, want exactly removed model", deletionEOF.Summary.GoneSignals)
	}
}

func TestRunScanCancellationDoesNotPersistPartialModelInventory(t *testing.T) {
	var block atomic.Bool
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if block.Load() {
			select {
			case <-started:
			default:
				close(started)
			}
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"durable-model"}]}`))
	}))
	defer server.Close()

	sig := openAIAPITestSignature(server.URL)
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", IncludeNetworkDomains: true,
		HomeDir: t.TempDir(), ScanRoots: []string{t.TempDir()}, DataDir: t.TempDir(),
		MaxFilesPerScan: 20, MaxFileBytes: 64 << 10,
	}, []AISignature{sig}, nil, nil)
	first, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	durable := findModelSignal(t, first.Signals, "model_api", "durable-model")

	block.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, runErr := svc.runScan(ctx, true, "test-cancel")
		done <- runErr
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("cancelled scan did not reach model endpoint")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan err = %v, want context.Canceled", err)
	}
	stored, err := svc.store.Load()
	if err != nil {
		t.Fatalf("load durable state: %v", err)
	}
	got, ok := stored.Signals[durable.Fingerprint]
	if !ok || got.Model == nil || got.Model.ID != "durable-model" || got.State == AIStateGone {
		t.Fatalf("cancelled scan overwrote durable inventory: %+v", stored.Signals)
	}
}

func TestDetectLocalAPIModelsDeduplicatesLemonadeCompatibilityEndpoints(t *testing.T) {
	var ollamaRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/health":
			_, _ = w.Write([]byte(`{"status":"ok","all_models_loaded":[]}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"shared-model","owned_by":"lemonade","downloaded":true,"recipe":"llamacpp"}]}`))
		case "/api/tags", "/api/ps":
			ollamaRequests.Add(1)
			_, _ = w.Write([]byte(`{"models":[{"name":"shared-model"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	setLemonadeTestTarget(t, server.URL)

	ollama := AISignature{
		ID:             "ollama",
		Name:           "Ollama",
		Vendor:         "Ollama",
		LocalEndpoints: []string{server.URL + "/api/tags"},
	}
	svc := &ContinuousDiscoveryService{catalog: []AISignature{ollama, lemonadeAPITestSignature(server.URL)}}
	signals, _, err := svc.detectLocalAPIModels(context.Background())
	if err != nil {
		t.Fatalf("detectLocalAPIModels: %v", err)
	}
	if ollamaRequests.Load() != 0 {
		t.Fatalf("queried %d compatibility endpoints after Lemonade identification", ollamaRequests.Load())
	}
	if len(signals) != 1 || signals[0].Product != "Lemonade" || signals[0].Model.ID != "shared-model" {
		t.Fatalf("deduplicated signals = %+v", signals)
	}
}

func TestLocalEndpointsForSignatureAddsLemonadePresenceAndConfiguredPorts(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("LEMONADE_PORT", "32124")
	t.Setenv("LEMONADE_HOST", "127.0.0.1")
	t.Setenv("LEMONADE_CACHE_DIR", "")
	configDir := filepath.Join(tmp, ".cache", "lemonade")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(`{"host":"localhost","port":32125}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	endpoints := localEndpointsForSignature(AISignature{ID: "lemonade", Name: "Lemonade"})
	for _, want := range []string{
		"http://127.0.0.1:13305/live",
		"http://127.0.0.1:32124/v1/models",
		"http://127.0.0.1:32124/api/v1/models",
		"http://127.0.0.1:32125/v1/health",
		"http://127.0.0.1:32125/api/v1/health",
	} {
		if !containsString(endpoints, want) {
			t.Fatalf("missing %q in %+v", want, endpoints)
		}
	}
	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "example.com") {
			t.Fatalf("non-loopback endpoint emitted: %q", endpoint)
		}
	}
}

func lemonadeAPITestSignature(baseURL string) AISignature {
	return AISignature{
		ID:         "lemonade",
		Name:       "Lemonade",
		Vendor:     "AMD",
		Confidence: 0.95,
		LocalEndpoints: []string{
			baseURL + "/v1/models",
			baseURL + "/v1/health",
		},
	}
}

func openAIAPITestSignature(baseURL string) AISignature {
	return AISignature{
		ID:             "test-openai-server",
		Name:           "Test OpenAI Server",
		Vendor:         "Fixed Vendor",
		Confidence:     0.8,
		LocalEndpoints: []string{baseURL + "/v1/models"},
	}
}

func setLemonadeTestTarget(t *testing.T, rawURL string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	t.Setenv("LEMONADE_HOST", u.Hostname())
	t.Setenv("LEMONADE_PORT", u.Port())
	// Keep a developer's real Lemonade credentials/config from influencing
	// deterministic test requests.
	t.Setenv("LEMONADE_ADMIN_API_KEY", "")
	t.Setenv("LEMONADE_API_KEY", "")
	t.Setenv("LEMONADE_CACHE_DIR", t.TempDir())
}

func findModelSignal(t *testing.T, signals []AISignal, detector, id string) AISignal {
	t.Helper()
	for _, signal := range signals {
		if signal.Detector == detector && signal.Model != nil && signal.Model.ID == id {
			return signal
		}
	}
	t.Fatalf("missing detector=%q model=%q in %+v", detector, id, signals)
	return AISignal{}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

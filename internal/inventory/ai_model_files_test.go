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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectModelFilesFindsFormatsWithoutDynamicProductLabels(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	writeModelTestFile(t, filepath.Join(root, "models", "mistral.gguf"), strings.Repeat("g", 64))
	writeModelTestFile(t, filepath.Join(root, "models", "legacy.ggml"), "ggml")
	writeModelTestFile(t, filepath.Join(root, "weights", "model.safetensors"), "safe")
	writeModelTestFile(t, filepath.Join(root, "onnx", "encoder.onnx"), "onnx")
	writeModelTestFile(t, filepath.Join(root, "models", "mobile.tflite"), "tflite")
	writeModelTestFile(t, filepath.Join(root, "models", "weights.pt"), "torch")
	writeModelTestFile(t, filepath.Join(root, "random.bin"), "not necessarily a model")
	writeModelTestFile(t, filepath.Join(root, "notes.pt"), "not necessarily a model")
	if err := os.MkdirAll(filepath.Join(root, "Vision.mlpackage"), 0o700); err != nil {
		t.Fatalf("mkdir mlpackage: %v", err)
	}

	svc := newModelFileTestService(t, home, root, 100, false)
	signals, files, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	if files != 7 {
		t.Fatalf("matching files = %d, want 7", files)
	}
	if len(signals) != 7 {
		t.Fatalf("signals = %d, want 7: %+v", len(signals), signals)
	}

	wantFormats := map[string]string{
		"mistral": "gguf", "legacy": "ggml", "model": "safetensors",
		"encoder": "onnx", "mobile": "tflite", "weights": "pt", "Vision": "coreml",
	}
	for id, format := range wantFormats {
		signal := findLocalModelSignal(t, signals, id)
		if signal.Model.Format != format || signal.Model.Status != "installed" {
			t.Errorf("model %q = %+v, want format=%q installed", id, signal.Model, format)
		}
		if signal.Product != "Local Model Artifact" || signal.Vendor != "Local" || signal.Component != nil {
			t.Errorf("model %q leaked dynamic metric labels: %+v", id, signal)
		}
		if signal.Category != SignalLocalModel || signal.Detector != "model_file" {
			t.Errorf("model %q category/detector = %q/%q", id, signal.Category, signal.Detector)
		}
		if signal.LastActiveAt != nil {
			t.Errorf("installed model %q incorrectly treated file mtime as runtime activity: %v", id, signal.LastActiveAt)
		}
		for _, evidence := range signal.Evidence {
			if evidence.RawPath != "" {
				t.Errorf("model %q leaked raw path: %+v", id, evidence)
			}
			if evidence.PathHash == "" || evidence.Basename == "" {
				t.Errorf("model %q missing sanitized path evidence: %+v", id, evidence)
			}
		}
	}
	for _, signal := range signals {
		if signal.Model.ID == "random" || signal.Model.ID == "notes" {
			t.Fatalf("generic binary/checkpoint outside a model context was detected: %+v", signal.Model)
		}
	}
}

func TestDetectModelFilesAggregatesHuggingFaceAndMLXShards(t *testing.T) {
	home := t.TempDir()
	hub := filepath.Join(home, ".cache", "huggingface", "hub")
	mlxDir := filepath.Join(hub, "models--mlx-community--Qwen3-0.6B", "snapshots", "abc")
	writeModelTestFile(t, filepath.Join(mlxDir, "model-00001-of-00002.safetensors"), strings.Repeat("a", 10))
	writeModelTestFile(t, filepath.Join(mlxDir, "model-00002-of-00002.safetensors"), strings.Repeat("b", 20))
	hfDir := filepath.Join(hub, "models--sentence-transformers--all-MiniLM", "snapshots", "def")
	writeModelTestFile(t, filepath.Join(hfDir, "model.safetensors"), strings.Repeat("c", 30))

	svc := newModelFileTestService(t, home, home, 100, false)
	signals, files, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	if files != 3 {
		t.Fatalf("matching files = %d, want 3", files)
	}
	if len(signals) != 2 {
		t.Fatalf("signals = %d, want 2 aggregated models: %+v", len(signals), signals)
	}
	mlx := findLocalModelSignal(t, signals, "mlx-community/Qwen3-0.6B")
	if mlx.Model.Format != "mlx" || mlx.Model.Provider != "mlx" || mlx.Model.SizeBytes != 30 {
		t.Fatalf("MLX aggregate = %+v", mlx.Model)
	}
	if len(mlx.Evidence) != 2 {
		t.Fatalf("MLX evidence rows = %d, want 2", len(mlx.Evidence))
	}
	hf := findLocalModelSignal(t, signals, "sentence-transformers/all-MiniLM")
	if hf.Model.Format != "safetensors" || hf.Model.Provider != "huggingface" || hf.Model.SizeBytes != 30 {
		t.Fatalf("Hugging Face aggregate = %+v", hf.Model)
	}
}

func TestDetectModelFilesHashesShardsBeyondDisplayedEvidenceCap(t *testing.T) {
	root := t.TempDir()
	modelDir := filepath.Join(root, "models", "large-sharded-model")
	for i := 1; i <= 9; i++ {
		writeModelTestFile(t, filepath.Join(modelDir, fmt.Sprintf("model-%05d-of-00009.safetensors", i)), strings.Repeat("x", i))
	}

	svc := newModelFileTestService(t, t.TempDir(), root, 20, false)
	first, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("first detectModelFiles: %v", err)
	}
	before := findLocalModelSignal(t, first, "large-sharded-model")
	if len(before.Evidence) != maxModelArtifactEvidence {
		t.Fatalf("display evidence = %d, want cap %d", len(before.Evidence), maxModelArtifactEvidence)
	}

	writeModelTestFile(t, filepath.Join(modelDir, "model-00009-of-00009.safetensors"), strings.Repeat("changed", 7))
	second, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("second detectModelFiles: %v", err)
	}
	after := findLocalModelSignal(t, second, "large-sharded-model")
	if after.Fingerprint != before.Fingerprint {
		t.Fatal("aggregate identity changed when a shard changed")
	}
	if after.EvidenceHash == before.EvidenceHash || after.Model.SizeBytes == before.Model.SizeBytes {
		t.Fatalf("ninth-shard change was not reflected: before=%+v after=%+v", before.Model, after.Model)
	}
	if len(after.Evidence) != maxModelArtifactEvidence {
		t.Fatalf("display evidence grew beyond cap: %d", len(after.Evidence))
	}
}

func TestDetectModelFilesFindsOllamaManifestAndBoundsBlobFallback(t *testing.T) {
	home := t.TempDir()
	store := filepath.Join(home, ".ollama", "models")
	manifest := filepath.Join(store, "manifests", "registry.ollama.ai", "library", "llama3", "latest")
	writeModelTestFile(t, manifest, `{"schemaVersion":2,"layers":[{"digest":"sha256:abc"}]}`)
	blob := filepath.Join(store, "blobs", "sha256-abc")
	writeModelTestFile(t, blob, strings.Repeat("x", 128))
	if err := os.Chmod(blob, 0); err != nil {
		t.Fatalf("chmod blob: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blob, 0o600) })

	svc := newModelFileTestService(t, home, home, 100, false)
	first, files, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	if files != 2 {
		t.Fatalf("matching entries = %d, want manifest + bounded blob fallback", files)
	}
	manifestSignal := findLocalModelSignal(t, first, "llama3:latest")
	if manifestSignal.Model.Format != "ollama" || manifestSignal.Model.Provider != "ollama" {
		t.Fatalf("manifest model = %+v", manifestSignal.Model)
	}
	blobSignal := findLocalModelSignal(t, first, "Ollama blob cache")
	if blobSignal.Model.Format != "ollama-blob" || len(blobSignal.Evidence) != 1 {
		t.Fatalf("blob fallback = %+v evidence=%+v", blobSignal.Model, blobSignal.Evidence)
	}

	// A bounded manifest metadata change keeps identity stable and changes the
	// evidence hash. The unreadable model blob itself is never opened.
	writeModelTestFile(t, manifest, `{"schemaVersion":2,"layers":[{"digest":"sha256:def"}]}`)
	second, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("second detectModelFiles: %v", err)
	}
	manifestAgain := findLocalModelSignal(t, second, "llama3:latest")
	if manifestAgain.Fingerprint != manifestSignal.Fingerprint {
		t.Fatal("manifest fingerprint changed with metadata")
	}
	if manifestAgain.EvidenceHash == manifestSignal.EvidenceHash {
		t.Fatal("manifest evidence hash did not change with content")
	}
}

func TestDetectModelFilesUsesLemonadeExtraModelsDir(t *testing.T) {
	home := t.TempDir()
	cache := t.TempDir()
	extra := t.TempDir()
	t.Setenv("LEMONADE_CACHE_DIR", cache)
	writeModelTestFile(t, filepath.Join(cache, "config.json"), `{"models_dir":"auto","extra_models_dir":`+quoteJSON(extra)+`}`)
	writeModelTestFile(t, filepath.Join(extra, "private-model.gguf"), "gguf")

	svc := newModelFileTestServiceWithoutEnvReset(t, home, home, 100, false)
	signals, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	model := findLocalModelSignal(t, signals, "private-model")
	if model.Model.Provider != "lemonade" || model.Model.Format != "gguf" {
		t.Fatalf("Lemonade extra-dir model = %+v", model.Model)
	}
}

func TestDetectModelFilesHonorsLimitsCancellationAndRawPathOptIn(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	for i := 0; i < 8; i++ {
		writeModelTestFile(t, filepath.Join(root, "models", string(rune('a'+i))+".gguf"), "model")
	}
	svc := newModelFileTestService(t, home, root, 2, true)
	signals, files, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	if files != 2 || len(signals) != 2 {
		t.Fatalf("limit result files=%d signals=%d, want 2/2", files, len(signals))
	}
	for _, signal := range signals {
		if len(signal.Evidence) != 1 || signal.Evidence[0].RawPath == "" {
			t.Fatalf("raw-path opt-in not honored: %+v", signal.Evidence)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := svc.detectModelFiles(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled detector err = %v, want context.Canceled", err)
	}
}

func TestDetectModelFilesFingerprintStableEvidenceChanges(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	path := filepath.Join(root, "model.gguf")
	writeModelTestFile(t, path, "one")
	svc := newModelFileTestService(t, home, root, 10, false)
	first, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("first detectModelFiles: %v", err)
	}
	before := findLocalModelSignal(t, first, "model")
	writeModelTestFile(t, path, "a different size")
	second, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("second detectModelFiles: %v", err)
	}
	after := findLocalModelSignal(t, second, "model")
	if before.Fingerprint != after.Fingerprint {
		t.Fatalf("fingerprint changed: %q != %q", before.Fingerprint, after.Fingerprint)
	}
	if before.EvidenceHash == after.EvidenceHash {
		t.Fatal("evidence hash did not change after artifact metadata changed")
	}
}

func TestDetectModelFilesUsesParentForGenericWeightsAndKeepsStandaloneModelNames(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	writeModelTestFile(t, filepath.Join(root, "models", "Qwen3", "model.safetensors"), "weights")
	writeModelTestFile(t, filepath.Join(root, "models", "model-7b.gguf"), "gguf")

	svc := newModelFileTestService(t, home, root, 20, false)
	signals, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	if got := findLocalModelSignal(t, signals, "Qwen3"); got.Model.Format != "safetensors" {
		t.Fatalf("generic parent model = %+v", got.Model)
	}
	if got := findLocalModelSignal(t, signals, "model-7b"); got.Model.Format != "gguf" {
		t.Fatalf("standalone model-* artifact was treated as a shard: %+v", got.Model)
	}
}

func TestDetectModelFilesFollowsSymlinkedStoreRoot(t *testing.T) {
	target := t.TempDir()
	writeModelTestFile(t, filepath.Join(target, "external-model.gguf"), "gguf")
	link := filepath.Join(t.TempDir(), "models-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	svc := newModelFileTestService(t, t.TempDir(), link, 20, false)
	signals, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	findLocalModelSignal(t, signals, "external-model")
}

func TestDetectModelFilesDeduplicatesHuggingFaceSnapshotTargetsForSize(t *testing.T) {
	home := t.TempDir()
	hub := filepath.Join(home, ".cache", "huggingface", "hub")
	blob := filepath.Join(hub, "blobs", "sha256-abc")
	writeModelTestFile(t, blob, strings.Repeat("x", 17))
	modelDir := filepath.Join(hub, "models--org--shared", "snapshots")
	for _, revision := range []string{"one", "two"} {
		path := filepath.Join(modelDir, revision, "model.safetensors")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir snapshot: %v", err)
		}
		if err := os.Symlink(blob, path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}

	svc := newModelFileTestService(t, home, home, 20, false)
	signals, files, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	if files != 2 {
		t.Fatalf("matching snapshot entries = %d, want 2", files)
	}
	model := findLocalModelSignal(t, signals, "org/shared")
	if model.Model.SizeBytes != 17 || len(model.Evidence) != 1 {
		t.Fatalf("duplicate snapshot target inflated aggregate: model=%+v evidence=%+v", model.Model, model.Evidence)
	}
}

func TestDetectModelFilesDeduplicatesSnapshotTargetsAcrossCursorPages(t *testing.T) {
	home := t.TempDir()
	hub := filepath.Join(home, ".cache", "huggingface", "hub")
	blob := filepath.Join(hub, "blobs", "sha256-page-shared")
	writeModelTestFile(t, blob, strings.Repeat("x", 17))
	modelDir := filepath.Join(hub, "models--org--paged-shared", "snapshots")
	for _, revision := range []string{"one", "two"} {
		path := filepath.Join(modelDir, revision, "model.safetensors")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir snapshot: %v", err)
		}
		if err := os.Symlink(blob, path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}

	svc := newModelFileTestService(t, home, home, 1, false)
	if _, _, err := svc.detectModelFiles(context.Background()); err != nil {
		t.Fatalf("first page: %v", err)
	}
	second, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	model := findLocalModelSignal(t, second, "org/paged-shared")
	if model.Model.SizeBytes != 17 || len(model.Evidence) != 1 {
		t.Fatalf("cross-page alias inflated aggregate: model=%+v evidence=%+v", model.Model, model.Evidence)
	}
}

func TestDetectModelFilesRejectsMalformedOllamaManifest(t *testing.T) {
	home := t.TempDir()
	manifest := filepath.Join(home, ".ollama", "models", "manifests", "registry.ollama.ai", "library", "llama3", "latest")
	writeModelTestFile(t, manifest, "not-json")

	svc := newModelFileTestService(t, home, home, 20, false)
	signals, files, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	if files != 0 || len(signals) != 0 {
		t.Fatalf("malformed manifest was inventoried: files=%d signals=%+v", files, signals)
	}
}

func TestDetectModelFilesDefersUnreadableOllamaManifestRoot(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, ".ollama", "models", "manifests", "registry.ollama.ai", "library", "llama3", "latest")
	writeModelTestFile(t, manifest, strings.Repeat("x", int(maxOllamaManifestBytes)+1))

	svc := newModelFileTestService(t, t.TempDir(), root, 20, false)
	signals, files, outcome, err := svc.detectModelFilesWithOutcome(context.Background())
	if err == nil {
		t.Fatal("oversized manifest did not surface a partial-scan error")
	}
	if files != 0 || len(signals) != 0 {
		t.Fatalf("oversized manifest was inventoried: files=%d signals=%+v", files, signals)
	}
	resolvedRoot, resolveErr := filepath.EvalSymlinks(root)
	if resolveErr != nil {
		t.Fatalf("resolve root: %v", resolveErr)
	}
	rootKey := hashPath(filepath.Clean(resolvedRoot))
	if !outcome.attempted[rootKey] || !outcome.deferred[rootKey] || outcome.conclusive[rootKey] {
		t.Fatalf("manifest I/O outcome = %+v, want attempted+deferred", outcome)
	}
}

func TestDetectModelFilesRotatesRootsUnderGlobalMatchCap(t *testing.T) {
	firstRoot := t.TempDir()
	secondRoot := t.TempDir()
	writeModelTestFile(t, filepath.Join(firstRoot, "a.gguf"), "a")
	writeModelTestFile(t, filepath.Join(firstRoot, "b.gguf"), "b")
	writeModelTestFile(t, filepath.Join(secondRoot, "later.gguf"), "later")
	for _, name := range []string{"HF_HOME", "OLLAMA_MODELS", "LM_STUDIO_HOME", "FLM_MODEL_PATH"} {
		t.Setenv(name, "")
	}
	t.Setenv("HF_HUB_CACHE", firstRoot)
	t.Setenv("LEMONADE_CACHE_DIR", filepath.Join(t.TempDir(), "empty-lemonade-cache"))
	svc := newModelFileTestServiceWithoutEnvReset(t, t.TempDir(), secondRoot, 1, false)

	first, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("first detectModelFiles: %v", err)
	}
	if len(first) != 1 || first[0].Model.ID == "later" {
		t.Fatalf("first root was not sampled first: %+v", first)
	}
	second, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("second detectModelFiles: %v", err)
	}
	findLocalModelSignal(t, second, "later")
}

func TestDetectModelFilesCursorAdvancesAcrossIrrelevantVisitPage(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < minModelFileVisitsPerRoot+50; i++ {
		writeModelTestFile(t, filepath.Join(root, fmt.Sprintf("prefix-%05d.txt", i)), "not a model")
	}
	writeModelTestFile(t, filepath.Join(root, "zz-model.gguf"), "model")
	svc := newModelFileTestService(t, t.TempDir(), root, 1, false)

	first, _, outcome, err := svc.detectModelFilesWithOutcome(context.Background())
	if err != nil {
		t.Fatalf("first detectModelFilesWithOutcome: %v", err)
	}
	if len(first) != 0 {
		t.Fatalf("first visit page unexpectedly reached model: %+v", first)
	}
	rootPath, resolveErr := filepath.EvalSymlinks(root)
	if resolveErr != nil {
		t.Fatalf("resolve root: %v", resolveErr)
	}
	if !outcome.deferred[hashPath(rootPath)] {
		t.Fatalf("first visit page outcome = %+v, want deferred", outcome)
	}

	second, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("second detectModelFiles: %v", err)
	}
	findLocalModelSignal(t, second, "zz-model")
}

func TestModelFileLifecycleCarriesSignalsAcrossIncompleteRoot(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	data := t.TempDir()
	for _, name := range []string{"HF_HUB_CACHE", "HF_HOME", "OLLAMA_MODELS", "LM_STUDIO_HOME", "FLM_MODEL_PATH"} {
		t.Setenv(name, "")
	}
	t.Setenv("LEMONADE_CACHE_DIR", filepath.Join(t.TempDir(), "empty-lemonade-cache"))
	writeModelTestFile(t, filepath.Join(root, "b.gguf"), "b")
	svc := newTestContinuousDiscoveryServiceWithOptions(t, AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", HomeDir: home, ScanRoots: []string{root},
		DataDir: data, MaxFilesPerScan: 1, MaxFileBytes: 64 << 10,
	}, nil, nil, nil)

	first, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if got := findLocalModelSignal(t, first.Signals, "b"); got.State != AIStateNew {
		t.Fatalf("first b state = %q, want new", got.State)
	} else if got.LastActiveAt != nil {
		t.Fatalf("installed file model has last_active_at = %v, want nil", got.LastActiveAt)
	}

	writeModelTestFile(t, filepath.Join(root, "a.gguf"), "a")
	second, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if got := findLocalModelSignal(t, second.Signals, "b"); got.State != AIStateSeen {
		t.Fatalf("b was not carried across capped root: %+v", got)
	}
	third, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("third scan: %v", err)
	}
	if got := findLocalModelSignal(t, third.Signals, "b"); got.State != AIStateSeen {
		t.Fatalf("cursor did not revisit b after a was inserted before it: %+v", got)
	}

	if err := os.Remove(filepath.Join(root, "b.gguf")); err != nil {
		t.Fatalf("remove b: %v", err)
	}
	fourth, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("fourth scan: %v", err)
	}
	if got := findLocalModelSignal(t, fourth.Signals, "b"); got.State != AIStateGone {
		t.Fatalf("b state after conclusive removal = %q, want gone", got.State)
	}
}

func TestModelFileLifecycleUsesCycleWideShardAggregate(t *testing.T) {
	root := t.TempDir()
	modelDir := filepath.Join(root, "models", "sharded")
	for i := 1; i <= 3; i++ {
		writeModelTestFile(t, filepath.Join(modelDir, fmt.Sprintf("model-%05d-of-00003.safetensors", i)), strings.Repeat("x", i))
	}
	for _, name := range []string{"HF_HUB_CACHE", "HF_HOME", "OLLAMA_MODELS", "LM_STUDIO_HOME", "FLM_MODEL_PATH"} {
		t.Setenv(name, "")
	}
	t.Setenv("LEMONADE_CACHE_DIR", filepath.Join(t.TempDir(), "empty-lemonade-cache"))
	svc := newTestContinuousDiscoveryServiceWithOptions(t, AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", HomeDir: t.TempDir(), ScanRoots: []string{root},
		DataDir: t.TempDir(), MaxFilesPerScan: 2, MaxFileBytes: 64 << 10,
	}, nil, nil, nil)

	first, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if got := findLocalModelSignal(t, first.Signals, "sharded"); got.State != AIStateNew {
		t.Fatalf("first partial state = %q, want new", got.State)
	}
	second, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	full := findLocalModelSignal(t, second.Signals, "sharded")
	if full.Model.SizeBytes != 6 {
		t.Fatalf("cycle-wide shard size = %d, want 6", full.Model.SizeBytes)
	}

	third, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("third scan: %v", err)
	}
	if got := findLocalModelSignal(t, third.Signals, "sharded"); got.State != AIStateSeen || got.EvidenceHash != full.EvidenceHash {
		t.Fatalf("partial next-cycle page flapped full aggregate: %+v", got)
	}
	fourth, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("fourth scan: %v", err)
	}
	if got := findLocalModelSignal(t, fourth.Signals, "sharded"); got.State != AIStateSeen || got.EvidenceHash != full.EvidenceHash {
		t.Fatalf("unchanged full cycle state/hash = %q/%q, want seen/%q", got.State, got.EvidenceHash, full.EvidenceHash)
	}

	writeModelTestFile(t, filepath.Join(modelDir, "model-00003-of-00003.safetensors"), strings.Repeat("changed", 3))
	if _, err := svc.runScan(context.Background(), true, "test"); err != nil {
		t.Fatalf("fifth scan: %v", err)
	}
	sixth, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("sixth scan: %v", err)
	}
	if got := findLocalModelSignal(t, sixth.Signals, "sharded"); got.State != AIStateChanged {
		t.Fatalf("completed changed shard cycle state = %q, want changed", got.State)
	}
}

func newModelFileTestService(t *testing.T, home, root string, limit int, rawPaths bool) *ContinuousDiscoveryService {
	t.Helper()
	for _, name := range []string{"HF_HUB_CACHE", "HF_HOME", "OLLAMA_MODELS", "LM_STUDIO_HOME", "FLM_MODEL_PATH"} {
		t.Setenv(name, "")
	}
	t.Setenv("LEMONADE_CACHE_DIR", filepath.Join(t.TempDir(), "empty-lemonade-cache"))
	return newModelFileTestServiceWithoutEnvReset(t, home, root, limit, rawPaths)
}

func newModelFileTestServiceWithoutEnvReset(t *testing.T, home, root string, limit int, rawPaths bool) *ContinuousDiscoveryService {
	t.Helper()
	return &ContinuousDiscoveryService{opts: normalizeAIDiscoveryOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", HomeDir: home, ScanRoots: []string{root},
		DataDir: t.TempDir(), MaxFilesPerScan: limit, MaxFileBytes: 64 << 10,
		StoreRawLocalPaths: rawPaths,
	})}
}

func writeModelTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func findLocalModelSignal(t *testing.T, signals []AISignal, id string) AISignal {
	t.Helper()
	for _, signal := range signals {
		if signal.Model != nil && signal.Model.ID == id {
			return signal
		}
	}
	t.Fatalf("model %q missing from %+v", id, signals)
	return AISignal{}
}

func quoteJSON(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

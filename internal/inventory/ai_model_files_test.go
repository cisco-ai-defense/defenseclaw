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
	"runtime"
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
	writeModelTestFile(t, filepath.Join(root, "models", "falcon.pt"), "torch")
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
		"encoder": "onnx", "mobile": "tflite", "falcon": "pt", "Vision": "coreml",
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

func TestConfiguredHuggingFaceAmbiguousArtifactsUseRepositoryIdentity(t *testing.T) {
	root := t.TempDir()
	paths := map[string]string{
		"acme/speech-model": filepath.Join(
			root, "models--acme--speech-model", "snapshots", "revision-a", "model.onnx",
		),
		// A repository tail named "model" is valid Hugging Face identity even
		// though the same standalone word is intentionally rejected as a generic
		// filesystem artifact identity.
		"acme/model": filepath.Join(
			root, "models--acme--model", "snapshots", "revision-b", "model.tflite",
		),
	}
	for id, path := range paths {
		writeModelTestFile(t, path, id)
	}

	svc := newModelFileTestService(t, t.TempDir(), root, 100, false)
	signals, files, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	if files != len(paths) {
		t.Fatalf("matching files = %d, want %d", files, len(paths))
	}
	for id, path := range paths {
		signal := findUniqueLocalModelSignal(t, signals, id)
		if signal.Model.Provider != "huggingface" {
			t.Fatalf("configured Hugging Face model %q provider = %q", id, signal.Model.Provider)
		}
		_, admittedIdentity, ok := modelArtifactFormat(path, modelScanRoot{path: root, provider: "filesystem"})
		if !ok {
			t.Fatalf("configured Hugging Face artifact %q was rejected", id)
		}
		if admittedIdentity == nil || admittedIdentity.id != signal.Model.ID || !admittedIdentity.trusted {
			t.Fatalf("shared identity for %q = %+v, emitted=%q", id, admittedIdentity, signal.Model.ID)
		}
	}
	if modelLikeArtifactIdentity("acme/model") {
		t.Fatal("generic identity policy unexpectedly trusted repository-tail model without Hugging Face context")
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

func TestDetectModelFilesProgressesPastRecurringErrorInBroadRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".ollama", "models")
	manifest := filepath.Join(root, "manifests", "registry.ollama.ai", "library", "llama3", "latest")
	writeModelTestFile(t, manifest, strings.Repeat("x", int(maxOllamaManifestBytes)+1))
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("mkdir broad root: %v", err)
	}
	for i := 0; i < minModelFileVisitsPerRoot+80; i++ {
		path := filepath.Join(root, fmt.Sprintf("n%04d.txt", i))
		if err := os.WriteFile(path, []byte("noise"), 0o600); err != nil {
			t.Fatalf("write filler %d: %v", i, err)
		}
	}
	writeModelTestFile(t, filepath.Join(root, "z-later.gguf"), "later")

	svc := newModelFileTestService(t, t.TempDir(), root, 1, false)
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	resolvedRoot = filepath.Clean(resolvedRoot)
	first, _, firstOutcome, firstErr := svc.detectModelFilesWithOutcome(context.Background())
	if firstErr == nil {
		t.Fatal("first page did not report its oversized manifest")
	}
	if len(first) != 0 || svc.modelFileCursor(resolvedRoot) == "" {
		t.Fatalf("first page did not preserve forward progress: signals=%+v cursor=%q", first, svc.modelFileCursor(resolvedRoot))
	}

	second, _, secondOutcome, secondErr := svc.detectModelFilesWithOutcome(context.Background())
	if secondErr == nil {
		t.Fatal("tainted resumed cycle was reported as complete")
	}
	findLocalModelSignal(t, second, "z-later")
	rootKey := hashPath(resolvedRoot)
	if !firstOutcome.deferred[rootKey] || !secondOutcome.deferred[rootKey] || secondOutcome.conclusive[rootKey] {
		t.Fatalf("errored broad-root outcomes were not deferred: first=%+v second=%+v", firstOutcome, secondOutcome)
	}
	if cursor := svc.modelFileCursor(resolvedRoot); cursor != "" {
		t.Fatalf("completed tainted cycle did not reset cursor: %q", cursor)
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

func TestModelFileLifecycleKeepsSpecializedOwnershipAcrossRootRotation(t *testing.T) {
	home := t.TempDir()
	modelDir := filepath.Join(home, ".lmstudio", "models", "Qwen", "Qwen3-4B")
	writeModelTestFile(t, filepath.Join(modelDir, "Qwen3-4B-Q4_K_M.gguf"), "model")
	for _, name := range []string{"HF_HUB_CACHE", "HF_HOME", "OLLAMA_MODELS", "LM_STUDIO_HOME", "FLM_MODEL_PATH"} {
		t.Setenv(name, "")
	}
	t.Setenv("LEMONADE_CACHE_DIR", filepath.Join(t.TempDir(), "empty-lemonade-cache"))
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", HomeDir: home, ScanRoots: []string{home},
		DataDir: t.TempDir(), MaxFilesPerScan: 100, MaxFileBytes: 64 << 10,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)

	firstReport, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	first := findLocalModelSignal(t, firstReport.Signals, "Qwen3-4B-Q4_K_M")
	if first.State != AIStateNew || first.Model.Provider != "lmstudio" || first.Product != "LM Studio" {
		t.Fatalf("first specialized model ownership = %+v", first)
	}

	secondReport, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	second := findLocalModelSignal(t, secondReport.Signals, "Qwen3-4B-Q4_K_M")
	if second.State != AIStateSeen || second.Model.Provider != first.Model.Provider ||
		second.Product != first.Product || second.EvidenceHash != first.EvidenceHash ||
		second.WorkspaceHash != first.WorkspaceHash {
		t.Fatalf("root rotation changed specialized ownership: first=%+v second=%+v", first, second)
	}
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
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", HomeDir: home, ScanRoots: []string{root},
		DataDir: data, MaxFilesPerScan: 1, MaxFileBytes: 64 << 10,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)

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
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", HomeDir: t.TempDir(), ScanRoots: []string{root},
		DataDir: t.TempDir(), MaxFilesPerScan: 2, MaxFileBytes: 64 << 10,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)

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

func TestEnhancedModelDiscoveryFindsUnknownMacOSApplicationModels(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS application scopes are only assigned on darwin")
	}
	home := t.TempDir()
	writeModelTestFile(t, filepath.Join(
		home, "Library", "Application Support", "superwhisper", "models", "whisper-large-v3.onnx",
	), "speech")
	writeModelTestFile(t, filepath.Join(
		home, "Library", "Application Support", "superwhisper", "models", "silero_vad.onnx",
	), "vad")
	writeModelTestFile(t, filepath.Join(
		home, "Library", "Application Support", "com.meetily.ai", "models", "Qwen3.5-4B-Q4_K_M.gguf",
	), "qwen")
	writeModelTestFile(t, filepath.Join(
		home, "Library", "Application Support", "com.meetily.ai", "models", "parakeet-tdt-0.6b-v3-int8.onnx",
	), "parakeet")
	writeModelTestFile(t, filepath.Join(
		home, "Library", "Containers", "app.cotypist.Cotypist", "Data", "Library", "Application Support",
		"Models", "gemma-3-4b-it-Q4_K_M.gguf",
	), "gemma")

	svc := newModelFileModeTestService(t, "enhanced", home, []string{home}, 100)
	signals, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}

	whisper := findLocalModelSignal(t, signals, "whisper-large-v3")
	if whisper.Model.OwnerApplication != "Superwhisper" || whisper.Model.Modality != localModelModalitySpeech ||
		whisper.Model.Relevance != localModelRelevanceSupporting {
		t.Fatalf("Superwhisper classification = %+v", whisper.Model)
	}
	vad := findLocalModelSignal(t, signals, "silero_vad")
	if vad.Model.OwnerApplication != "Superwhisper" || vad.Model.Modality != localModelModalityAudio {
		t.Fatalf("Superwhisper VAD classification = %+v", vad.Model)
	}
	qwen := findLocalModelSignal(t, signals, "Qwen3.5-4B-Q4_K_M")
	if qwen.Model.OwnerApplication != "Meetily" || qwen.Model.Modality != localModelModalityGenerative ||
		qwen.Model.Relevance != localModelRelevancePrimary || qwen.Model.DiscoveryConfidence == nil ||
		*qwen.Model.DiscoveryConfidence < 0.9 {
		t.Fatalf("Meetily Qwen classification = %+v", qwen.Model)
	}
	parakeet := findLocalModelSignal(t, signals, "parakeet-tdt-0.6b-v3-int8")
	if parakeet.Model.OwnerApplication != "Meetily" || parakeet.Model.Modality != localModelModalitySpeech {
		t.Fatalf("Meetily Parakeet classification = %+v", parakeet.Model)
	}
	gemma := findLocalModelSignal(t, signals, "gemma-3-4b-it-Q4_K_M")
	if gemma.Model.OwnerApplication != "Cotypist" || gemma.Model.Modality != localModelModalityGenerative ||
		gemma.Model.Relevance != localModelRelevancePrimary {
		t.Fatalf("Cotypist classification = %+v", gemma.Model)
	}
}

func TestPassiveModelDiscoverySkipsBroadHomeButKeepsKnownStores(t *testing.T) {
	home := t.TempDir()
	unknownPath := filepath.Join(home, "Library", "Application Support", "unknown.app", "models", "private.gguf")
	writeModelTestFile(t, unknownPath, "unknown")
	knownStore := filepath.Join(home, "explicit-hf-cache")
	writeModelTestFile(t, filepath.Join(
		knownStore, "models--org--known", "snapshots", "revision", "model.safetensors",
	), "known")
	t.Setenv("HF_HUB_CACHE", knownStore)
	for _, name := range []string{"HF_HOME", "OLLAMA_MODELS", "LM_STUDIO_HOME", "FLM_MODEL_PATH"} {
		t.Setenv(name, "")
	}
	t.Setenv("LEMONADE_CACHE_DIR", filepath.Join(t.TempDir(), "empty-lemonade-cache"))

	passive := newModelFileModeTestServiceWithoutEnvReset(t, "passive", home, []string{home}, 100)
	passiveSignals, _, err := passive.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("passive detectModelFiles: %v", err)
	}
	findLocalModelSignal(t, passiveSignals, "org/known")
	for _, signal := range passiveSignals {
		if signal.Model != nil && signal.Model.ID == "private" {
			t.Fatalf("passive broad-home scan found unknown app model: %+v", signal.Model)
		}
	}
	narrowPassive := newModelFileModeTestServiceWithoutEnvReset(
		t, "passive", home, []string{filepath.Dir(filepath.Dir(unknownPath))}, 100,
	)
	narrowSignals, _, err := narrowPassive.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("passive narrow-root detectModelFiles: %v", err)
	}
	findLocalModelSignal(t, narrowSignals, "private")

	if runtime.GOOS == "darwin" {
		enhanced := newModelFileModeTestServiceWithoutEnvReset(t, "enhanced", home, []string{home}, 100)
		enhancedSignals, _, err := enhanced.detectModelFiles(context.Background())
		if err != nil {
			t.Fatalf("enhanced detectModelFiles: %v", err)
		}
		findUniqueLocalModelSignal(t, enhancedSignals, "private")
	}
}

func TestModelArtifactFormatsRequireContextForAmbiguousContainers(t *testing.T) {
	root := t.TempDir()
	writeModelTestFile(t, filepath.Join(root, "standalone-gguf.gguf"), "gguf")
	writeModelTestFile(t, filepath.Join(root, "standalone-safetensors.safetensors"), "safe")
	writeModelTestFile(t, filepath.Join(root, "random.onnx"), "onnx")
	writeModelTestFile(t, filepath.Join(root, "random.tflite"), "tflite")
	writeModelTestFile(t, filepath.Join(root, "random.bin"), "bin")
	writeModelTestFile(t, filepath.Join(root, "models", "encoder.onnx"), "encoder")
	writeModelTestFile(t, filepath.Join(root, "runtime", "model.tflite"), "model")
	writeModelTestFile(t, filepath.Join(root, "models", "runtime", "model.tflite"), "model")
	writeModelTestFile(t, filepath.Join(root, "models", "weights.bin"), "weights")
	writeModelTestFile(t, filepath.Join(root, "models", "llama-3", "weights.bin"), "llama")
	writeModelTestFile(t, filepath.Join(root, "models", "speech-recognizer", "model.onnx"), "speech")
	writeModelTestFile(t, filepath.Join(root, "models", "1486C03D0DA33B08", "model.onnx"), "opaque")
	writeModelTestFile(t, filepath.Join(root, "models", "2025.8.8.1141", "weights.bin"), "version")
	writeModelTestFile(t, filepath.Join(root, "models", "v2026.2.12.1554", "weights.bin"), "prefixed-version")
	writeModelTestFile(t, filepath.Join(root, "models", "version-2026.2.12", "weights.bin"), "long-prefixed-version")
	writeModelTestFile(t, filepath.Join(root, "metadata-backed", "acme-encoder.onnx"), "artifact")
	writeModelTestFile(t, filepath.Join(root, "metadata-backed", "config.json"), `{}`)

	svc := newModelFileTestService(t, t.TempDir(), root, 100, false)
	signals, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	for _, id := range []string{
		"standalone-gguf", "standalone-safetensors", "encoder", "llama-3", "speech-recognizer", "acme-encoder",
	} {
		findUniqueLocalModelSignal(t, signals, id)
	}
	for _, signal := range signals {
		if signal.Model == nil {
			continue
		}
		switch signal.Model.ID {
		case "random", "runtime", "weights", "1486C03D0DA33B08", "2025.8.8.1141",
			"v2026.2.12.1554", "version-2026.2.12":
			t.Fatalf("ambiguous artifact without context and identity was detected: %+v", signal.Model)
		}
	}
	if got := findUniqueLocalModelSignal(t, signals, "encoder"); got.Evidence[0].MatchKind != MatchKindHeuristic ||
		got.Model.DiscoveryConfidence == nil ||
		findUniqueLocalModelSignal(t, signals, "standalone-gguf").Model.DiscoveryConfidence == nil ||
		*got.Model.DiscoveryConfidence >= *findUniqueLocalModelSignal(t, signals, "standalone-gguf").Model.DiscoveryConfidence {
		t.Fatalf("ambiguous evidence was not downgraded: %+v", got)
	}
}

func TestModelLikeArtifactIdentityRejectsOpaqueAndGenericIDs(t *testing.T) {
	for _, tc := range []struct {
		identity string
		want     bool
	}{
		{identity: "whisper-large-v3", want: true},
		{identity: "parakeet-tdt-0.6b-v3-int8", want: true},
		{identity: "mobile-bert", want: true},
		{identity: "llama-3", want: true},
		{identity: "speech-recognizer", want: true},
		{identity: "whisper-v3", want: true},
		{identity: "qwen2.5", want: true},
		{identity: "versioned-encoder", want: true},
		{identity: "vocoder-v2", want: true},
		{identity: "model"},
		{identity: "weights"},
		{identity: "runtime"},
		{identity: "1486C03D0DA33B08"},
		{identity: "23D9FB1AEA22CDBB"},
		{identity: "255003A8CCD5FE13"},
		{identity: "28FCB9A336B951C4"},
		{identity: "2B9B8928CB720A25"},
		{identity: "2025.8.8.1141"},
		{identity: "2026.2.12.1554"},
		{identity: "v2026.2.12.1554"},
		{identity: "V2026_02_12"},
		{identity: "version-2026.2.12"},
		{identity: "version 2"},
		{identity: "1486c03d-0da3-3b08"},
	} {
		t.Run(tc.identity, func(t *testing.T) {
			if got := modelLikeArtifactIdentity(tc.identity); got != tc.want {
				t.Fatalf("modelLikeArtifactIdentity(%q) = %t, want %t", tc.identity, got, tc.want)
			}
		})
	}
}

func TestAmbiguousModelAdmissionSuppressesObservedChromePayloadIDs(t *testing.T) {
	root := t.TempDir()
	observed := map[string]string{
		"1486C03D0DA33B08": filepath.Join("Google", "Chrome", "optimization_guide_model_store", "45", "E6DC4029A1E4B4C1", "1486C03D0DA33B08", "model.tflite"),
		"23D9FB1AEA22CDBB": filepath.Join("Google", "Chrome", "optimization_guide_model_store", "2", "E6DC4029A1E4B4C1", "23D9FB1AEA22CDBB", "model.tflite"),
		"255003A8CCD5FE13": filepath.Join("Google", "Chrome", "optimization_guide_model_store", "9", "E6DC4029A1E4B4C1", "255003A8CCD5FE13", "model.tflite"),
		"28FCB9A336B951C4": filepath.Join("Google", "Chrome", "optimization_guide_model_store", "13", "E6DC4029A1E4B4C1", "28FCB9A336B951C4", "model.tflite"),
		"2B9B8928CB720A25": filepath.Join("Google", "Chrome", "optimization_guide_model_store", "26", "E6DC4029A1E4B4C1", "2B9B8928CB720A25", "model.tflite"),
		"2025.8.8.1141":    filepath.Join("Google", "Chrome", "OptGuideOnDeviceModel", "2025.8.8.1141", "weights.bin"),
		"2026.2.12.1554":   filepath.Join("Google", "Chrome", "OptGuideOnDeviceClassifierModel", "2026.2.12.1554", "weights.bin"),
	}
	for id, relative := range observed {
		writeModelTestFile(t, filepath.Join(root, relative), id)
	}

	writeModelTestFile(t, filepath.Join(root, "superwhisper", "models", "whisper-large-v3.onnx"), "speech")
	writeModelTestFile(t, filepath.Join(root, "meetily", "models", "parakeet-tdt-0.6b-v3-int8.onnx"), "speech")
	writeModelTestFile(t, filepath.Join(root, "cotypist", "Models", "gemma-3-4b-it-Q4_K_M.gguf"), "llm")
	writeModelTestFile(t, filepath.Join(root, "models", "mobile-bert.tflite"), "mobile")
	writeModelTestFile(t, filepath.Join(root, "models", "llama-3", "weights.bin"), "llm")
	writeModelTestFile(t, filepath.Join(
		root, "Google", "Chrome", "optimization_guide_model_store", "opaque", "named-cache-model.gguf",
	), "high-signal")

	svc := newModelFileTestService(t, t.TempDir(), root, 100, false)
	signals, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	for _, id := range []string{
		"whisper-large-v3", "parakeet-tdt-0.6b-v3-int8", "gemma-3-4b-it-Q4_K_M",
		"mobile-bert", "llama-3", "named-cache-model",
	} {
		findUniqueLocalModelSignal(t, signals, id)
	}
	for _, signal := range signals {
		if signal.Model == nil {
			continue
		}
		if _, noisy := observed[signal.Model.ID]; noisy {
			t.Fatalf("observed Chrome payload %q was admitted: %+v", signal.Model.ID, signal.Model)
		}
	}

	for id, relative := range observed {
		format, _, ok := modelArtifactFormat(
			filepath.Join(root, relative), modelScanRoot{path: root, specialized: true},
		)
		if !ok || (format != "tflite" && format != "bin") {
			t.Fatalf("specialized store rejected %q: format=%q ok=%t", id, format, ok)
		}
	}
}

func TestSuppressedAmbiguousModelTransitionsPriorRowToGone(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	data := t.TempDir()
	const noisyID = "1486C03D0DA33B08"
	writeModelTestFile(t, filepath.Join(
		root, "Google", "Chrome", "optimization_guide_model_store", "45", "E6DC4029A1E4B4C1", noisyID, "model.tflite",
	), "chrome")
	for _, name := range []string{"HF_HOME", "OLLAMA_MODELS", "LM_STUDIO_HOME", "FLM_MODEL_PATH"} {
		t.Setenv(name, "")
	}
	t.Setenv("LEMONADE_CACHE_DIR", filepath.Join(t.TempDir(), "empty-lemonade-cache"))
	t.Setenv("HF_HUB_CACHE", root)
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", HomeDir: home, ScanRoots: []string{root},
		DataDir: data, MaxFilesPerScan: 100, MaxFileBytes: 64 << 10,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)

	first, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("specialized first scan: %v", err)
	}
	if got := findLocalModelSignal(t, first.Signals, noisyID); got.State != AIStateNew {
		t.Fatalf("seed model state = %q, want new", got.State)
	}

	// Removing the specialized-store context exercises upgrade behavior: the
	// same conclusive root is now governed by strict enhanced-root admission.
	t.Setenv("HF_HUB_CACHE", "")
	second, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("strict second scan: %v", err)
	}
	if got := findLocalModelSignal(t, second.Signals, noisyID); got.State != AIStateGone {
		t.Fatalf("suppressed prior model state = %q, want gone", got.State)
	}

	third, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("third scan: %v", err)
	}
	for _, signal := range third.Signals {
		if signal.Detector == "model_file" && signal.Model != nil && signal.Model.ID == noisyID {
			t.Fatalf("suppressed prior model persisted after gone transition: %+v", signal)
		}
	}
}

func TestModelMetadataSidecarLookupIsMemoizedPerRootAndDirectory(t *testing.T) {
	rootPath := t.TempDir()
	dir := filepath.Join(rootPath, "models", "metadata-backed")
	writeModelTestFile(t, filepath.Join(dir, "config.json"), `{}`)
	root := modelScanRoot{path: rootPath, metadataSidecars: make(map[string]bool)}
	for _, name := range []string{"encoder.onnx", "decoder.onnx"} {
		if !hasModelMetadataSidecar(filepath.Join(dir, name), root) {
			t.Fatalf("metadata sidecar was not found for %s", name)
		}
	}
	if got := len(root.metadataSidecars); got != 1 {
		t.Fatalf("metadata sidecar cache entries = %d, want 1", got)
	}
}

func TestEnhancedModelDiscoverySuppressesChromePayloadsAndRetainsWebexModel(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS application scopes are only assigned on darwin")
	}
	home := t.TempDir()
	writeModelTestFile(t, filepath.Join(
		home, "Library", "Caches", "com.google.Chrome", "OptimizationGuidePredictionModels", "123", "model.tflite",
	), "chrome")
	writeModelTestFile(t, filepath.Join(
		home, "Library", "Application Support", "Cisco", "Webex", "models", "speech_encoder.onnx",
	), "webex")
	writeModelTestFile(t, filepath.Join(
		home, "Library", "Caches", "com.google.Chrome", "Code Cache", "models", "noise.onnx",
	), "noise")

	svc := newModelFileModeTestService(t, "enhanced", home, []string{home}, 100)
	signals, _, err := svc.detectModelFiles(context.Background())
	if err != nil {
		t.Fatalf("detectModelFiles: %v", err)
	}
	webex := findLocalModelSignal(t, signals, "speech_encoder")
	if webex.Model.OwnerApplication != "Webex" || webex.Model.Modality != localModelModalitySpeech ||
		webex.Model.Relevance != localModelRelevanceEmbedded {
		t.Fatalf("Webex embedded classification = %+v", webex.Model)
	}
	for _, signal := range signals {
		if signal.Model != nil && (signal.Model.ID == "123" || signal.Model.ID == "noise") {
			t.Fatalf("known browser cache payload was detected: %+v", signal.Model)
		}
	}
}

func TestEnhancedMacOSRootsBoundAppResourcesAndClassifyBundles(t *testing.T) {
	home := t.TempDir()
	for i := 0; i < maxMacOSAppResourceRoots+3; i++ {
		if err := os.MkdirAll(filepath.Join(home, "Applications", fmt.Sprintf("App%03d.app", i)), 0o700); err != nil {
			t.Fatalf("mkdir app bundle: %v", err)
		}
	}
	roots := enhancedMacOSModelScanRoots(home, false, maxMacOSAppResourceRoots)
	if len(roots) != 4+maxMacOSAppResourceRoots {
		t.Fatalf("enhanced macOS roots = %d, want %d", len(roots), 4+maxMacOSAppResourceRoots)
	}
	if limited := enhancedMacOSModelScanRoots(home, false, 3); len(limited) != 7 {
		t.Fatalf("enhanced macOS roots with three-app budget = %d, want 7", len(limited))
	}
	if limited := macOSApplicationResourceScanRoots(home, false, 3); len(limited) != 3 {
		t.Fatalf("bounded app-resource roots = %d, want 3", len(limited))
	}
	for _, root := range roots {
		if strings.HasPrefix(root.path, "/System/Applications") {
			t.Fatalf("system application resources were admitted: %+v", root)
		}
	}
	var resourceRoot modelScanRoot
	foundResourceRoot := false
	for _, root := range roots {
		if root.scope == modelScanScopeAppResources {
			resourceRoot = root
			foundResourceRoot = true
			break
		}
	}
	if !foundResourceRoot {
		t.Fatalf("app-resource root missing from %+v", roots)
	}
	if runtime.GOOS == "darwin" {
		expectedOwner := resourceRoot.owner
		if expectedOwner == "" {
			t.Fatalf("app-resource root has no owner: %+v", resourceRoot)
		}
		modelPath := filepath.Join(resourceRoot.path, "Models", "vision_encoder.mlmodel")
		writeModelTestFile(t, modelPath, "coreml")
		svc := newModelFileModeTestService(t, "enhanced", home, []string{home}, 100)
		candidate, ok := svc.modelArtifactCandidate(modelPath, resourceRoot, "coreml", false, "", nil)
		if !ok || candidate.owner != expectedOwner || candidate.modality != localModelModalityVision ||
			candidate.relevance != localModelRelevanceEmbedded {
			t.Fatalf("app resource classification = %+v, ok=%v", candidate, ok)
		}
	}
}

func TestModelRootRotationDistributesLargeRootSets(t *testing.T) {
	const (
		roots         = 516
		priorityRoots = 7
	)
	genericRoots := roots - priorityRoots
	seen := make(map[int]bool, roots)
	seenGeneric := make(map[int]bool, genericRoots)
	lastPrioritySequence := int64(-1)
	for sequence := uint64(0); sequence < uint64(2*genericRoots); sequence++ {
		start := modelRootRotationStart(sequence, roots, priorityRoots)
		if start < 0 || start >= roots {
			t.Fatalf("rotation start %d outside 0..%d", start, roots-1)
		}
		seen[start] = true
		if sequence%2 == 0 {
			want := int((sequence / 2) % priorityRoots)
			if start != want {
				t.Fatalf("priority sequence %d started at %d, want %d", sequence, start, want)
			}
			if lastPrioritySequence >= 0 && int64(sequence)-lastPrioritySequence > 2 {
				t.Fatalf("priority root start gap exceeded two scans: last=%d current=%d", lastPrioritySequence, sequence)
			}
			lastPrioritySequence = int64(sequence)
		} else {
			if start < priorityRoots {
				t.Fatalf("generic sequence %d started at priority root %d", sequence, start)
			}
			seenGeneric[start] = true
		}
	}
	if len(seen) != roots {
		t.Fatalf("rotation visited %d/%d roots", len(seen), roots)
	}
	if len(seenGeneric) != genericRoots {
		t.Fatalf("rotation visited %d/%d generic roots", len(seenGeneric), genericRoots)
	}
	if modelRootRotationStart(0, roots, priorityRoots) != 0 {
		t.Fatal("first scan did not preserve known-store-first ordering")
	}

	ordered, priorityCount := prioritizeModelScanRoots([]modelScanRoot{
		{path: "enhanced-a"}, {path: "known-a", specialized: true},
		{path: "enhanced-b"}, {path: "known-b", specialized: true},
	})
	if priorityCount != 2 || ordered[0].path != "known-a" || ordered[1].path != "known-b" {
		t.Fatalf("specialized roots were not stably prioritized: count=%d roots=%+v", priorityCount, ordered)
	}
	if got := modelRootVisitLimit(modelScanRoot{scope: modelScanScopeApplicationSupport}, 4000, 64_000); got != 16_000 {
		t.Fatalf("application-support visit limit = %d, want 16000", got)
	}
	if got := modelRootVisitLimit(modelScanRoot{scope: modelScanScopeCache}, 4000, 64_000); got != 4000 {
		t.Fatalf("cache visit limit = %d, want 4000", got)
	}
	if got := modelRootVisitLimit(modelScanRoot{scope: modelScanScopeContainer}, 4000, 6000); got != 6000 {
		t.Fatalf("container visit limit ignored global cap: %d", got)
	}
}

func TestModelFileErrorsReachBoundedPrivacySafeDiagnostics(t *testing.T) {
	home := t.TempDir()
	manifest := filepath.Join(home, ".ollama", "models", "manifests", "registry.ollama.ai", "library", "llama3", "latest")
	writeModelTestFile(t, manifest, strings.Repeat("x", int(maxOllamaManifestBytes)+1))
	for _, name := range []string{"HF_HUB_CACHE", "HF_HOME", "OLLAMA_MODELS", "LM_STUDIO_HOME", "FLM_MODEL_PATH"} {
		t.Setenv(name, "")
	}
	t.Setenv("LEMONADE_CACHE_DIR", filepath.Join(t.TempDir(), "empty-lemonade-cache"))
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", HomeDir: home, ScanRoots: []string{home},
		DataDir: t.TempDir(), MaxFilesPerScan: 100, MaxFileBytes: 64 << 10,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	report, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if report.Summary.Result != "partial" || report.Summary.DetectorErrors["model_file"] == "" {
		t.Fatalf("model-file error not surfaced: %+v", report.Summary)
	}
	perRoot := 0
	for key, detail := range report.Summary.DetectorErrors {
		if strings.HasPrefix(key, "model_file:") {
			perRoot++
		}
		if strings.Contains(key, home) || strings.Contains(detail, home) || strings.Contains(detail, manifest) {
			t.Fatalf("diagnostic leaked raw path: %q=%q", key, detail)
		}
	}
	if perRoot == 0 {
		t.Fatalf("per-root model-file diagnostic missing: %+v", report.Summary.DetectorErrors)
	}

	many := make(map[string]string)
	for i := 0; i < maxModelRootDiagnostics+7; i++ {
		many[hashValue(fmt.Sprintf("root-%03d", i))] = modelRootAccessErrorDetail(
			modelScanRoot{scope: modelScanScopeContainer}, os.ErrPermission,
		)
	}
	bounded := boundedModelRootDiagnostics(many)
	if len(bounded) != maxModelRootDiagnostics+1 || bounded["additional_roots"] == "" {
		t.Fatalf("bounded diagnostics = %+v", bounded)
	}
}

func TestValidateModelFileClassificationMetadata(t *testing.T) {
	valid := AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "model-classification"},
		Signals: []AISignal{{
			Category: SignalLocalModel,
			Model: &LocalModelInfo{
				ID: "private", Status: "installed", OwnerApplication: "Meetily",
				Modality: localModelModalityGenerative, Relevance: localModelRelevancePrimary,
				DiscoveryConfidence: modelDiscoveryConfidence(0.95),
			},
		}},
	}
	if err := ValidateSanitizedAIDiscoveryReport(valid); err != nil {
		t.Fatalf("valid classification rejected: %v", err)
	}
	badOwner := cloneAIDiscoveryReport(valid)
	badOwner.Signals[0].Model.OwnerApplication = "/Users/private/Meetily"
	if err := ValidateSanitizedAIDiscoveryReport(badOwner); err == nil {
		t.Fatal("path-shaped owner_application accepted")
	}
	badRelevance := cloneAIDiscoveryReport(valid)
	badRelevance.Signals[0].Model.Relevance = "noise"
	if err := ValidateSanitizedAIDiscoveryReport(badRelevance); err == nil {
		t.Fatal("unsupported relevance accepted")
	}
	for _, tc := range []struct {
		name    string
		value   float64
		wantErr bool
	}{
		{name: "zero", value: 0},
		{name: "one", value: 1},
		{name: "negative", value: -0.01, wantErr: true},
		{name: "above_one", value: 1.1, wantErr: true},
	} {
		t.Run("confidence_"+tc.name, func(t *testing.T) {
			report := cloneAIDiscoveryReport(valid)
			report.Signals[0].Model.DiscoveryConfidence = modelDiscoveryConfidence(tc.value)
			err := ValidateSanitizedAIDiscoveryReport(report)
			if (err != nil) != tc.wantErr {
				t.Fatalf("discovery confidence %v validation error = %v, wantErr=%t", tc.value, err, tc.wantErr)
			}
		})
	}
}

func TestEmbeddedModelOwnerUsesWordBoundaries(t *testing.T) {
	for _, tc := range []struct {
		owner string
		want  bool
	}{
		{owner: "Microsoft Edge", want: true},
		{owner: "com.microsoft.edge", want: true},
		{owner: "Chrome Helper", want: true},
		{owner: "Sledgehammer", want: false},
		{owner: "Knowledge", want: false},
		{owner: "Slackline", want: false},
	} {
		t.Run(tc.owner, func(t *testing.T) {
			if got := embeddedModelOwner(tc.owner); got != tc.want {
				t.Fatalf("embeddedModelOwner(%q) = %t, want %t", tc.owner, got, tc.want)
			}
		})
	}
}

func newModelFileModeTestService(t *testing.T, mode, home string, roots []string, limit int) *ContinuousDiscoveryService {
	t.Helper()
	for _, name := range []string{"HF_HUB_CACHE", "HF_HOME", "OLLAMA_MODELS", "LM_STUDIO_HOME", "FLM_MODEL_PATH"} {
		t.Setenv(name, "")
	}
	t.Setenv("LEMONADE_CACHE_DIR", filepath.Join(t.TempDir(), "empty-lemonade-cache"))
	return newModelFileModeTestServiceWithoutEnvReset(t, mode, home, roots, limit)
}

func newModelFileModeTestServiceWithoutEnvReset(t *testing.T, mode, home string, roots []string, limit int) *ContinuousDiscoveryService {
	t.Helper()
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: mode, HomeDir: home, ScanRoots: roots,
		DataDir: t.TempDir(), MaxFilesPerScan: limit, MaxFileBytes: 64 << 10,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	return svc
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

func findUniqueLocalModelSignal(t *testing.T, signals []AISignal, id string) AISignal {
	t.Helper()
	var matches []AISignal
	for _, signal := range signals {
		if signal.Model != nil && signal.Model.ID == id {
			matches = append(matches, signal)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("model %q matched %d signals, want exactly one: %+v", id, len(matches), signals)
	}
	return matches[0]
}

func quoteJSON(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

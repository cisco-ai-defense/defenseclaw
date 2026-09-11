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

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/benchmarks/internal/benchmark"
)

const defaultSeed int64 = 741983

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "benchmark:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		writeUsage(stderr)
		return errors.New("a subcommand is required")
	}
	switch args[0] {
	case "run":
		return runBenchmark(args[1:], stdout)
	case "score":
		return scoreBenchmark(args[1:], stdout)
	case "compare":
		return compareBenchmark(args[1:], stdout)
	case "validate":
		return validateBenchmark(args[1:], stdout)
	case "inventory":
		return inventoryBenchmark(args[1:], stdout)
	case "verify":
		return verifyBenchmark(args[1:], stdout)
	case "help", "-h", "--help":
		writeUsage(stdout)
		return nil
	default:
		writeUsage(stderr)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runBenchmark(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	corpusPath := flags.String("corpus", "benchmarks/fixtures/smoke.jsonl", "normalized JSONL corpus")
	truthCorpusPath := flags.String("truth-corpus", "", "optional row-aligned truth overlay used only for scoring")
	normalizationManifestPath := flags.String("normalization-manifest", "", "normalization manifest (inferred beside corpus when present)")
	lockPath := flags.String("dataset-lock", "benchmarks/datasets.lock.json", "dataset lock")
	repoRoot := flags.String("repo-root", ".", "DefenseClaw repository root")
	policyRoot := flags.String("policy-root", "policies/guardrail", "profile policy root, relative to repository root unless absolute")
	dataDir := flags.String("data-dir", "", "external benchmark data root")
	outputDir := flags.String("output", "outputs/benchmarks/run", "output directory")
	runID := flags.String("run-id", "", "stable run identifier")
	profilesCSV := flags.String("profiles", "default,permissive,strict", "comma-separated profiles")
	seed := flags.Int64("seed", defaultSeed, "bootstrap seed")
	gate := flags.Bool("gate", false, "enforce smoke expectations")
	evaluateOutOfScope := flags.Bool("evaluate-out-of-scope", false, "emit detector diagnostics for candidate rows without scoring them")
	skillBinary := flags.String("skill-binary", "", "skill scanner binary")
	pluginBinary := flags.String("plugin-binary", "", "plugin scanner binary")
	mcpBinary := flags.String("mcp-binary", "", "MCP scanner binary")
	mcpYARARules := flags.String("mcp-yara-rules", "", "custom MCP YARA rules directory; replaces scanner-bundled rules")
	if err := flags.Parse(args); err != nil {
		return err
	}

	corpusData, cases, lockData, _, err := loadInputs(*corpusPath, *lockPath)
	if err != nil {
		return err
	}
	normalizationData, err := readNormalizationManifest(*normalizationManifestPath, *corpusPath)
	if err != nil {
		return err
	}
	scoreCases := cases
	truthCorpusSHA256 := ""
	if *truthCorpusPath != "" {
		truthData, truthCases, _, _, err := loadInputs(*truthCorpusPath, *lockPath)
		if err != nil {
			return fmt.Errorf("load truth corpus: %w", err)
		}
		if err := benchmark.ValidateTruthOverlay(cases, truthCases); err != nil {
			return err
		}
		scoreCases = truthCases
		truthCorpusSHA256 = benchmark.SHA256Hex(truthData)
	}
	profiles, err := parseProfiles(*profilesCSV)
	if err != nil {
		return err
	}
	commit, dirty := gitState(*repoRoot)
	if *runID == "" {
		short := commit
		if len(short) > 12 {
			short = short[:12]
		}
		*runID = short + "-" + time.Now().UTC().Format("20060102T150405Z")
	}
	runner := benchmark.Runner{
		RepoRoot:           *repoRoot,
		PolicyRoot:         *policyRoot,
		DataDir:            firstNonEmpty(*dataDir, os.Getenv("BENCHMARK_DATA_DIR")),
		RunID:              *runID,
		Profiles:           profiles,
		SkillBinary:        *skillBinary,
		PluginBinary:       *pluginBinary,
		MCPBinary:          *mcpBinary,
		MCPYARARulesDir:    *mcpYARARules,
		EvaluateOutOfScope: *evaluateOutOfScope,
	}
	// A truth overlay may promote independently adjudicated rows from the
	// source corpus's pending out-of-scope state into the scored population.
	// ValidateTruthOverlay above guarantees that payload and provenance fields
	// are unchanged, so evaluate the overlay-aligned cases as well as scoring
	// them. Otherwise the runner emits not_applicable for every newly finalized
	// row and silently produces an empty benchmark.
	predictions, policyDigests, err := runner.Run(context.Background(), scoreCases)
	if err != nil {
		return err
	}
	if *gate {
		if err := benchmark.ValidateSmokePredictions(cases, predictions); err != nil {
			return err
		}
	}
	summary, err := benchmark.Score(scoreCases, predictions, *seed)
	if err != nil {
		return err
	}
	environment := benchmark.Environment{
		RunID:             *runID,
		CaseCount:         len(cases),
		PredictionCount:   len(predictions),
		DefenseClawCommit: commit,
		Dirty:             dirty,
		GOOS:              runtime.GOOS,
		GOARCH:            runtime.GOARCH,
		GoVersion:         runtime.Version(),
		PythonVersion:     pythonVersion(),
		Profiles:          profiles,
		PolicyRoot:        filepath.Clean(*policyRoot),
		CorpusSHA256:      benchmark.SHA256Hex(corpusData),
		TruthCorpusSHA256: truthCorpusSHA256,
		DatasetLockSHA256: benchmark.SHA256Hex(lockData),
		PolicyDigests:     policyDigests,
		Command:           append([]string{"defenseclaw-benchmark", "run"}, args...),
		Seed:              *seed,
	}
	classificationDigest, err := benchmark.ClassificationSHA256(predictions)
	if err != nil {
		return err
	}
	environment.ClassificationSHA256 = classificationDigest
	var corpusManifest benchmark.CorpusManifest
	if *truthCorpusPath == "" {
		corpusManifest, err = benchmark.BuildCorpusManifest(cases, environment.CorpusSHA256, normalizationData)
	} else {
		corpusManifest, err = benchmark.BuildCorpusManifestWithTruth(
			cases,
			scoreCases,
			environment.CorpusSHA256,
			environment.TruthCorpusSHA256,
			normalizationData,
		)
	}
	if err != nil {
		return err
	}
	if err := writeOutputs(*repoRoot, *policyRoot, *outputDir, lockData, scoreCases, predictions, summary, environment, corpusManifest); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "benchmark run %s: %d cases, %d predictions -> %s\n", *runID, len(cases), len(predictions), *outputDir)
	return err
}

func scoreBenchmark(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("score", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	corpusPath := flags.String("corpus", "", "normalized JSONL corpus")
	predictionPath := flags.String("predictions", "", "prediction JSONL")
	outputPath := flags.String("output", "", "results JSON path or stdout when empty")
	seed := flags.Int64("seed", defaultSeed, "bootstrap seed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" || *predictionPath == "" {
		return errors.New("score requires --corpus and --predictions")
	}
	cases, err := readCases(*corpusPath)
	if err != nil {
		return err
	}
	predictions, err := readPredictions(*predictionPath)
	if err != nil {
		return err
	}
	summary, err := benchmark.Score(cases, predictions, *seed)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *outputPath == "" {
		_, err = stdout.Write(data)
		return err
	}
	return atomicWrite(*outputPath, data)
}

func compareBenchmark(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	corpusPath := flags.String("corpus", "", "normalized JSONL corpus")
	truthCorpusPath := flags.String("truth-corpus", "", "optional row-aligned truth overlay used for comparison metrics")
	baselinePath := flags.String("baseline-predictions", "", "baseline prediction JSONL")
	candidatePath := flags.String("candidate-predictions", "", "candidate prediction JSONL")
	outputPath := flags.String("output", "", "comparison JSON path or stdout when empty")
	seed := flags.Int64("seed", defaultSeed, "paired bootstrap seed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" || *baselinePath == "" || *candidatePath == "" {
		return errors.New("compare requires --corpus, --baseline-predictions, and --candidate-predictions")
	}
	cases, err := readCases(*corpusPath)
	if err != nil {
		return err
	}
	comparisonCases := cases
	truthCorpusSHA256 := ""
	if *truthCorpusPath != "" {
		truthData, err := os.ReadFile(*truthCorpusPath)
		if err != nil {
			return fmt.Errorf("read truth corpus: %w", err)
		}
		truthCases, err := benchmark.LoadCases(bytes.NewReader(truthData))
		if err != nil {
			return fmt.Errorf("load truth corpus: %w", err)
		}
		if err := benchmark.ValidateTruthOverlay(cases, truthCases); err != nil {
			return err
		}
		comparisonCases = truthCases
		truthCorpusSHA256 = benchmark.SHA256Hex(truthData)
	}
	baseline, err := readPredictions(*baselinePath)
	if err != nil {
		return fmt.Errorf("read baseline predictions: %w", err)
	}
	candidate, err := readPredictions(*candidatePath)
	if err != nil {
		return fmt.Errorf("read candidate predictions: %w", err)
	}
	comparison, err := benchmark.CompareRuns(comparisonCases, baseline, candidate, *seed)
	if err != nil {
		return err
	}
	corpusData, err := os.ReadFile(*corpusPath)
	if err != nil {
		return fmt.Errorf("read corpus for digest: %w", err)
	}
	comparison.CorpusSHA256 = benchmark.SHA256Hex(corpusData)
	comparison.TruthCorpusSHA256 = truthCorpusSHA256
	data, err := json.MarshalIndent(comparison, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *outputPath == "" {
		_, err = stdout.Write(data)
		return err
	}
	return atomicWrite(*outputPath, data)
}

func validateBenchmark(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	corpusPath := flags.String("corpus", "benchmarks/fixtures/smoke.jsonl", "normalized JSONL corpus")
	lockPath := flags.String("dataset-lock", "benchmarks/datasets.lock.json", "dataset lock")
	if err := flags.Parse(args); err != nil {
		return err
	}
	_, cases, _, lock, err := loadInputs(*corpusPath, *lockPath)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "validated %d cases and %d locked datasets\n", len(cases), len(lock.Datasets))
	return err
}

func inventoryBenchmark(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("inventory", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	repoRoot := flags.String("repo-root", ".", "DefenseClaw repository root")
	policyRoot := flags.String("policy-root", "policies/guardrail", "profile policy root, relative to repository root unless absolute")
	outputPath := flags.String("output", "", "output JSON path or stdout when empty")
	if err := flags.Parse(args); err != nil {
		return err
	}
	inventory, err := benchmark.BuildInventoryWithPolicyRoot(*repoRoot, *policyRoot)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *outputPath == "" {
		_, err = stdout.Write(data)
		return err
	}
	return atomicWrite(*outputPath, data)
}

func verifyBenchmark(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	outputDir := flags.String("output", "outputs/benchmarks/smoke", "benchmark output directory")
	publication := flags.Bool("publication", false, "require clean publication provenance")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := benchmark.VerifyOutput(*outputDir, *publication); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "verified benchmark output %s\n", *outputDir)
	return err
}

func loadInputs(corpusPath, lockPath string) ([]byte, []benchmark.Case, []byte, benchmark.DatasetLock, error) {
	corpusData, err := os.ReadFile(corpusPath)
	if err != nil {
		return nil, nil, nil, benchmark.DatasetLock{}, fmt.Errorf("read corpus: %w", err)
	}
	cases, err := benchmark.LoadCases(bytes.NewReader(corpusData))
	if err != nil {
		return nil, nil, nil, benchmark.DatasetLock{}, err
	}
	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, nil, nil, benchmark.DatasetLock{}, fmt.Errorf("read dataset lock: %w", err)
	}
	lock, err := benchmark.ParseDatasetLock(lockData)
	if err != nil {
		return nil, nil, nil, benchmark.DatasetLock{}, err
	}
	known := make(map[string]benchmark.DatasetSpec, len(lock.Datasets))
	for _, dataset := range lock.Datasets {
		known[dataset.ID] = dataset
	}
	for _, benchmarkCase := range cases {
		dataset, ok := known[benchmarkCase.Source.Dataset]
		if !ok {
			return nil, nil, nil, benchmark.DatasetLock{}, fmt.Errorf("case %q references dataset %q absent from lock", benchmarkCase.ID, benchmarkCase.Source.Dataset)
		}
		if !dataset.Enabled {
			return nil, nil, nil, benchmark.DatasetLock{}, fmt.Errorf("case %q references disabled dataset %q", benchmarkCase.ID, dataset.ID)
		}
		if benchmarkCase.Source.Revision != dataset.Revision || benchmarkCase.Source.License != dataset.License ||
			benchmarkCase.Source.Redistribution != dataset.Redistribution {
			return nil, nil, nil, benchmark.DatasetLock{}, fmt.Errorf("case %q provenance differs from dataset lock", benchmarkCase.ID)
		}
	}
	return corpusData, cases, lockData, lock, nil
}

func readCases(path string) ([]benchmark.Case, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return benchmark.LoadCases(file)
}

func readPredictions(path string) ([]benchmark.Prediction, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	predictions, loadErr := benchmark.LoadPredictions(file)
	closeErr := file.Close()
	if loadErr != nil {
		return nil, loadErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return predictions, nil
}

func readNormalizationManifest(explicitPath, corpusPath string) ([]byte, error) {
	path := explicitPath
	if path == "" {
		extension := filepath.Ext(corpusPath)
		path = strings.TrimSuffix(corpusPath, extension) + ".manifest.json"
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if explicitPath == "" {
			// Label-application manifests intentionally share the corpus sidecar
			// naming convention but are not normalization manifests. Do not feed
			// one into the strict normalization decoder merely because it sits
			// beside an adjudicated corpus.
			var shape map[string]json.RawMessage
			if json.Unmarshal(data, &shape) != nil || shape["datasets"] == nil ||
				shape["cases"] == nil || shape["counts"] == nil ||
				shape["output_sha256"] == nil {
				return nil, nil
			}
		}
		return data, nil
	}
	if explicitPath == "" && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return nil, fmt.Errorf("read normalization manifest: %w", err)
}

func writeOutputs(
	repoRoot string,
	policyRoot string,
	outputDir string,
	lockData []byte,
	cases []benchmark.Case,
	predictions []benchmark.Prediction,
	summary benchmark.Summary,
	environment benchmark.Environment,
	corpusManifest benchmark.CorpusManifest,
) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	var predictionBuffer bytes.Buffer
	if err := benchmark.WritePredictions(&predictionBuffer, predictions); err != nil {
		return err
	}
	resultData, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	resultData = append(resultData, '\n')
	environmentData, err := json.MarshalIndent(environment, "", "  ")
	if err != nil {
		return err
	}
	environmentData = append(environmentData, '\n')
	var markdown bytes.Buffer
	if err := benchmark.WriteMarkdown(&markdown, summary, environment); err != nil {
		return err
	}
	var summaryCSV bytes.Buffer
	if err := benchmark.WriteSummaryCSV(&summaryCSV, summary); err != nil {
		return err
	}
	var coverageCSV bytes.Buffer
	if err := benchmark.WriteCoverageCSV(&coverageCSV, cases, predictions); err != nil {
		return err
	}
	inventory, err := benchmark.BuildInventoryWithPolicyRoot(repoRoot, policyRoot)
	if err != nil {
		return err
	}
	inventoryData, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return err
	}
	inventoryData = append(inventoryData, '\n')
	corpusManifestData, err := json.MarshalIndent(corpusManifest, "", "  ")
	if err != nil {
		return err
	}
	corpusManifestData = append(corpusManifestData, '\n')

	files := map[string][]byte{
		"classification.sha256": []byte(environment.ClassificationSHA256 + "\n"),
		"corpus-manifest.json":  corpusManifestData,
		"predictions.jsonl":     predictionBuffer.Bytes(),
		"results.json":          resultData,
		"summary.csv":           summaryCSV.Bytes(),
		"coverage.csv":          coverageCSV.Bytes(),
		"environment.json":      environmentData,
		"datasets.lock.json":    lockData,
		"inventory.json":        inventoryData,
		"methodology.md":        markdown.Bytes(),
	}
	names := make([]string, 0, len(files))
	for name, data := range files {
		if err := atomicWrite(filepath.Join(outputDir, name), data); err != nil {
			return err
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var checksums strings.Builder
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		fmt.Fprintf(&checksums, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	return atomicWrite(filepath.Join(outputDir, "checksums.txt"), []byte(checksums.String()))
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".benchmark-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(tempPath)
	}
	if err := file.Chmod(0o644); err != nil {
		cleanup()
		return err
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return nil
}

func parseProfiles(value string) ([]string, error) {
	seen := make(map[string]struct{})
	var profiles []string
	for _, raw := range strings.Split(value, ",") {
		profile := strings.ToLower(strings.TrimSpace(raw))
		if profile == "" {
			continue
		}
		if err := benchmark.ValidateProfile(profile); err != nil {
			return nil, err
		}
		if _, exists := seen[profile]; exists {
			continue
		}
		seen[profile] = struct{}{}
		profiles = append(profiles, profile)
	}
	if len(profiles) == 0 {
		return nil, errors.New("at least one profile is required")
	}
	return profiles, nil
}

func gitState(repoRoot string) (string, bool) {
	commit := "unknown"
	if output, err := exec.Command("git", "-C", repoRoot, "rev-parse", "HEAD").Output(); err == nil {
		commit = strings.TrimSpace(string(output))
	}
	dirty := true
	if output, err := exec.Command("git", "-C", repoRoot, "status", "--porcelain").Output(); err == nil {
		dirty = len(bytes.TrimSpace(output)) != 0
	}
	return commit, dirty
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func pythonVersion() string {
	for _, name := range []string{"python3", "python"} {
		output, err := exec.Command(name, "--version").CombinedOutput()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return "unavailable"
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: defenseclaw-benchmark <run|score|compare|validate|inventory|verify> [flags]")
}

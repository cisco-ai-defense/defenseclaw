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
	"compress/gzip"
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
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/benchmarks/internal/benchmark"
)

const defaultSeed int64 = 741983

var (
	buildCommit string
	buildDirty  string
)

var fullGitCommitPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

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
	optInPolicyRoot := flags.String("opt-in-policy-root", "policies/guardrail-use-cases", "opt-in policy-pack root, relative to repository root unless absolute")
	dataDir := flags.String("data-dir", "", "external benchmark data root")
	outputDir := flags.String("output", "outputs/benchmarks/run", "output directory")
	runID := flags.String("run-id", "", "stable run identifier")
	profilesCSV := flags.String("profiles", "default,permissive,strict", "comma-separated profiles")
	optInPacksCSV := flags.String("opt-in-packs", "", "comma-separated named opt-in policy packs, evaluated with balanced posture")
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
	commit, dirty := gitStateForRun(*repoRoot)
	binaryRevision, binaryModified := runningBinaryVCSForRun()
	if err := validateRunBinaryProvenance(commit, dirty, binaryRevision, binaryModified); err != nil {
		return err
	}

	corpusSHA256, cases, lockData, _, err := loadInputs(*corpusPath, *lockPath)
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
		truthSHA256, truthCases, _, _, err := loadInputs(*truthCorpusPath, *lockPath)
		if err != nil {
			return fmt.Errorf("load truth corpus: %w", err)
		}
		if err := benchmark.ValidateTruthOverlay(cases, truthCases); err != nil {
			return err
		}
		scoreCases = truthCases
		truthCorpusSHA256 = truthSHA256
	}
	profiles, err := parseProfiles(*profilesCSV)
	if err != nil {
		return err
	}
	optInPacks, err := parseOptInPolicyPacks(*optInPacksCSV)
	if err != nil {
		return err
	}
	policyLabels := append([]string(nil), profiles...)
	var policyPostures map[string]string
	optInPolicyRootMetadata := ""
	if len(optInPacks) > 0 {
		policyPostures = make(map[string]string, len(profiles)+len(optInPacks))
		for _, profile := range profiles {
			policyPostures[profile] = profile
		}
		for _, name := range optInPacks {
			label, labelErr := benchmark.OptInPolicyLabel(name)
			if labelErr != nil {
				return labelErr
			}
			policyLabels = append(policyLabels, label)
			policyPostures[label] = "default"
		}
		optInPolicyRootMetadata = filepath.Clean(*optInPolicyRoot)
	}
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
		OptInPolicyRoot:    *optInPolicyRoot,
		DataDir:            firstNonEmpty(*dataDir, os.Getenv("BENCHMARK_DATA_DIR")),
		RunID:              *runID,
		Profiles:           profiles,
		OptInPolicyPacks:   optInPacks,
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
		RunID:                   *runID,
		CaseCount:               len(cases),
		PredictionCount:         len(predictions),
		DefenseClawCommit:       commit,
		Dirty:                   dirty,
		BinaryProvenanceVersion: benchmark.BinaryProvenanceSchemaVersion,
		BinaryVCSRevision:       binaryRevision,
		BinaryVCSModified:       binaryModified,
		GOOS:                    runtime.GOOS,
		GOARCH:                  runtime.GOARCH,
		GoVersion:               runtime.Version(),
		PythonVersion:           pythonVersion(),
		Profiles:                policyLabels,
		PolicyRoot:              filepath.Clean(*policyRoot),
		OptInPolicyPacks:        optInPacks,
		OptInPolicyRoot:         optInPolicyRootMetadata,
		PolicyPostures:          policyPostures,
		CorpusSHA256:            corpusSHA256,
		TruthCorpusSHA256:       truthCorpusSHA256,
		DatasetLockSHA256:       benchmark.SHA256Hex(lockData),
		PolicyDigests:           policyDigests,
		Command:                 append([]string{"defenseclaw-benchmark", "run"}, args...),
		Seed:                    *seed,
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
		truthCases, err := readCases(*truthCorpusPath)
		if err != nil {
			return fmt.Errorf("load truth corpus: %w", err)
		}
		if err := benchmark.ValidateTruthOverlay(cases, truthCases); err != nil {
			return err
		}
		comparisonCases = truthCases
		truthCorpusSHA256, err = corpusSHA256(*truthCorpusPath)
		if err != nil {
			return fmt.Errorf("digest truth corpus: %w", err)
		}
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
	corpusSHA256, err := corpusSHA256(*corpusPath)
	if err != nil {
		return fmt.Errorf("digest corpus: %w", err)
	}
	comparison.CorpusSHA256 = corpusSHA256
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
	normalizationManifestPath := flags.String("normalization-manifest", "", "optional normalization manifest to validate against the corpus")
	if err := flags.Parse(args); err != nil {
		return err
	}
	corpusSHA256, cases, _, lock, err := loadInputs(*corpusPath, *lockPath)
	if err != nil {
		return err
	}
	normalizationData, err := readNormalizationManifest(*normalizationManifestPath, *corpusPath)
	if err != nil {
		return err
	}
	if len(normalizationData) > 0 {
		if _, err := benchmark.BuildCorpusManifest(cases, corpusSHA256, normalizationData); err != nil {
			return err
		}
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

func loadInputs(corpusPath, lockPath string) (string, []benchmark.Case, []byte, benchmark.DatasetLock, error) {
	corpusSHA256, err := corpusSHA256(corpusPath)
	if err != nil {
		return "", nil, nil, benchmark.DatasetLock{}, fmt.Errorf("digest corpus: %w", err)
	}
	cases, err := readCases(corpusPath)
	if err != nil {
		return "", nil, nil, benchmark.DatasetLock{}, err
	}
	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		return "", nil, nil, benchmark.DatasetLock{}, fmt.Errorf("read dataset lock: %w", err)
	}
	lock, err := benchmark.ParseDatasetLock(lockData)
	if err != nil {
		return "", nil, nil, benchmark.DatasetLock{}, err
	}
	known := make(map[string]benchmark.DatasetSpec, len(lock.Datasets))
	for _, dataset := range lock.Datasets {
		known[dataset.ID] = dataset
	}
	for _, benchmarkCase := range cases {
		dataset, ok := known[benchmarkCase.Source.Dataset]
		if !ok {
			return "", nil, nil, benchmark.DatasetLock{}, fmt.Errorf("case %q references dataset %q absent from lock", benchmarkCase.ID, benchmarkCase.Source.Dataset)
		}
		if !dataset.Enabled {
			return "", nil, nil, benchmark.DatasetLock{}, fmt.Errorf("case %q references disabled dataset %q", benchmarkCase.ID, dataset.ID)
		}
		if benchmarkCase.Source.Revision != dataset.Revision || benchmarkCase.Source.License != dataset.License ||
			benchmarkCase.Source.Redistribution != dataset.Redistribution {
			return "", nil, nil, benchmark.DatasetLock{}, fmt.Errorf("case %q provenance differs from dataset lock", benchmarkCase.ID)
		}
	}
	return corpusSHA256, cases, lockData, lock, nil
}

func readCases(path string) ([]benchmark.Case, error) {
	reader, closeReader, err := openCorpusReader(path)
	if err != nil {
		return nil, err
	}
	cases, loadErr := benchmark.LoadCases(reader)
	closeErr := closeReader()
	if loadErr != nil {
		return nil, loadErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return cases, nil
}

func corpusSHA256(path string) (string, error) {
	reader, closeReader, err := openCorpusReader(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, reader)
	closeErr := closeReader()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func openCorpusReader(path string) (io.Reader, func() error, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if !strings.HasSuffix(strings.ToLower(path), ".gz") {
		return file, file.Close, nil
	}
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("open gzip corpus: %w", err)
	}
	return gzipReader, func() error {
		gzipErr := gzipReader.Close()
		fileErr := file.Close()
		if gzipErr != nil {
			return gzipErr
		}
		return fileErr
	}, nil
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
		if strings.EqualFold(filepath.Ext(corpusPath), ".gz") {
			corpusPath = strings.TrimSuffix(corpusPath, filepath.Ext(corpusPath))
		}
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

func parseOptInPolicyPacks(value string) ([]string, error) {
	seen := make(map[string]struct{})
	var packs []string
	for _, raw := range strings.Split(value, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if err := benchmark.ValidateOptInPolicyPack(name); err != nil {
			return nil, err
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		packs = append(packs, name)
	}
	return packs, nil
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

var gitStateForRun = gitState
var runningBinaryVCSForRun = runningBinaryVCS

func runningBinaryVCS() (string, *bool) {
	info, ok := debug.ReadBuildInfo()
	if ok {
		revision, modified := binaryVCSSettings(info.Settings)
		if revision != "" || modified != nil {
			return revision, modified
		}
	}
	return linkedBinaryVCS(buildCommit, buildDirty)
}

func binaryVCSSettings(settings []debug.BuildSetting) (string, *bool) {
	var revision string
	var modified *bool
	for _, setting := range settings {
		switch setting.Key {
		case "vcs.revision":
			revision = strings.TrimSpace(setting.Value)
		case "vcs.modified":
			value, err := strconv.ParseBool(strings.TrimSpace(setting.Value))
			if err == nil {
				modified = &value
			}
		}
	}
	return revision, modified
}

func linkedBinaryVCS(revision, modifiedValue string) (string, *bool) {
	revision = strings.TrimSpace(revision)
	modified, err := strconv.ParseBool(strings.TrimSpace(modifiedValue))
	if err != nil {
		return revision, nil
	}
	return revision, &modified
}

func validateRunBinaryProvenance(commit string, repoDirty bool, binaryRevision string, binaryModified *bool) error {
	if !fullGitCommitPattern.MatchString(commit) {
		return fmt.Errorf("benchmark run requires a full 40-hex selected repository commit")
	}
	if repoDirty {
		return fmt.Errorf("benchmark run requires a clean selected repository worktree")
	}
	if !fullGitCommitPattern.MatchString(binaryRevision) || binaryModified == nil {
		return fmt.Errorf("benchmark run requires embedded binary VCS provenance; build with -buildvcs=true")
	}
	if *binaryModified {
		return fmt.Errorf("benchmark run requires an unmodified benchmark binary")
	}
	if !strings.EqualFold(commit, binaryRevision) {
		return fmt.Errorf(
			"benchmark binary revision %q differs from selected clean repository commit %q",
			binaryRevision,
			commit,
		)
	}
	return nil
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

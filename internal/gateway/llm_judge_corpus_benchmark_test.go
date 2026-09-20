// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// This benchmark deliberately lives in package gateway (rather than a parallel
// Python prompt implementation) so it exercises the same LLMJudge methods,
// rule-pack prompts, Bifrost provider, JSON parsing, severity mapping, and
// verdict merging as the runtime. It is opt-in because it invokes a real model.

type corpusJudgeCase struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"id"`
	Surface       string `json:"surface"`
	Source        struct {
		Dataset string `json:"dataset"`
	} `json:"source"`
	Payload corpusJudgePayload `json:"payload"`
	Truth   struct {
		SourceTruth         string `json:"source_truth"`
		DeterministicTruth  string `json:"deterministic_truth"`
		ExpectedDisposition string `json:"expected_disposition"`
		LabelConfidence     string `json:"label_confidence"`
	} `json:"truth"`
	Strata struct {
		Campaign     string `json:"campaign"`
		Domain       string `json:"domain"`
		SplitGroup   string `json:"split_group"`
		TrajectoryID string `json:"trajectory_id"`
	} `json:"strata"`
}

type corpusJudgePayload struct {
	Direction string          `json:"direction"`
	Content   string          `json:"content"`
	ToolName  string          `json:"tool_name"`
	Command   string          `json:"command"`
	Argv      []string        `json:"argv"`
	Args      json.RawMessage `json:"args"`
	Events    []struct {
		ToolName string          `json:"tool_name"`
		Command  string          `json:"command"`
		Argv     []string        `json:"argv"`
		Args     json.RawMessage `json:"args"`
		Outcome  string          `json:"outcome"`
	} `json:"events"`
}

type judgeBenchmarkInvocation struct {
	LatencyMS        float64 `json:"latency_ms"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	RequestSHA256    string  `json:"request_sha256"`
	JSONMode         bool    `json:"json_mode"`
	Error            bool    `json:"error"`
}

type judgeBenchmarkProvider struct {
	delegate LLMProvider
	mu       sync.Mutex
	records  []judgeBenchmarkInvocation
}

type judgeBenchmarkCollectorKey struct{}

type judgeBenchmarkCollector struct {
	mu      sync.Mutex
	records []judgeBenchmarkInvocation
}

func (c *judgeBenchmarkCollector) append(record judgeBenchmarkInvocation) {
	c.mu.Lock()
	c.records = append(c.records, record)
	c.mu.Unlock()
}

func (c *judgeBenchmarkCollector) snapshot() []judgeBenchmarkInvocation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]judgeBenchmarkInvocation(nil), c.records...)
}

func (p *judgeBenchmarkProvider) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	started := time.Now()
	resp, err := p.delegate.ChatCompletion(ctx, req)
	record := judgeBenchmarkInvocation{
		LatencyMS:     float64(time.Since(started).Microseconds()) / 1000,
		RequestSHA256: judgeBenchmarkRequestSHA256(req),
		JSONMode:      judgeBenchmarkUsesJSONMode(req.ResponseFormat),
		Error:         err != nil,
	}
	if resp != nil && resp.Usage != nil {
		record.PromptTokens = resp.Usage.PromptTokens
		record.CompletionTokens = resp.Usage.CompletionTokens
		record.TotalTokens = resp.Usage.TotalTokens
	}
	p.mu.Lock()
	p.records = append(p.records, record)
	p.mu.Unlock()
	if collector, ok := ctx.Value(judgeBenchmarkCollectorKey{}).(*judgeBenchmarkCollector); ok {
		collector.append(record)
	}
	return resp, err
}

func judgeBenchmarkUsesJSONMode(responseFormat json.RawMessage) bool {
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(responseFormat, &envelope); err != nil {
		return false
	}
	return envelope.Type == "json_object" || envelope.Type == "json_schema"
}

func (p *judgeBenchmarkProvider) ChatCompletionStream(
	ctx context.Context,
	req *ChatRequest,
	chunkCb func(StreamChunk),
) (*ChatUsage, error) {
	return p.delegate.ChatCompletionStream(ctx, req, chunkCb)
}

func (p *judgeBenchmarkProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.records)
}

func judgeBenchmarkRequestSHA256(req *ChatRequest) string {
	data, _ := json.Marshal(struct {
		Model          string          `json:"model"`
		Messages       []ChatMessage   `json:"messages"`
		MaxTokens      *int            `json:"max_tokens"`
		Temperature    *float64        `json:"temperature"`
		ResponseFormat json.RawMessage `json:"response_format"`
		Fallbacks      []string        `json:"fallbacks"`
		ExtraParams    map[string]any  `json:"extra_params"`
	}{req.Model, req.Messages, req.MaxTokens, req.Temperature, req.ResponseFormat, req.Fallbacks, req.ExtraParams})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// judgeBenchmarkContractProvider never invokes a model. It returns a clean
// response generated from the request's strict JSON schema so resume checks can
// reconstruct the exact production requests for a corpus row. This catches
// prompt, schema, token-limit, temperature, and provider-parameter changes
// before old and new results are silently mixed in one output file.
type judgeBenchmarkContractProvider struct{}

func (judgeBenchmarkContractProvider) ChatCompletion(_ context.Context, req *ChatRequest) (*ChatResponse, error) {
	content, err := judgeBenchmarkCleanSchemaResponse(req.ResponseFormat)
	if err != nil {
		return nil, err
	}
	return &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Content: content}}}}, nil
}

func (judgeBenchmarkContractProvider) ChatCompletionStream(
	context.Context,
	*ChatRequest,
	func(StreamChunk),
) (*ChatUsage, error) {
	return nil, errors.New("benchmark contract provider does not stream")
}

func judgeBenchmarkCleanSchemaResponse(responseFormat json.RawMessage) (string, error) {
	var envelope struct {
		JSONSchema struct {
			Schema map[string]interface{} `json:"schema"`
		} `json:"json_schema"`
	}
	if err := json.Unmarshal(responseFormat, &envelope); err != nil {
		return "", fmt.Errorf("parse benchmark response schema: %w", err)
	}
	if len(envelope.JSONSchema.Schema) == 0 {
		return "{}", nil
	}
	value, err := judgeBenchmarkCleanSchemaValue(envelope.JSONSchema.Schema, "")
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal benchmark schema response: %w", err)
	}
	return string(data), nil
}

func judgeBenchmarkCleanSchemaValue(schema map[string]interface{}, propertyName string) (interface{}, error) {
	typeName, _ := schema["type"].(string)
	switch typeName {
	case "object":
		properties, _ := schema["properties"].(map[string]interface{})
		required, _ := schema["required"].([]interface{})
		result := make(map[string]interface{}, len(required))
		for _, rawName := range required {
			name, ok := rawName.(string)
			if !ok {
				return nil, fmt.Errorf("benchmark schema has non-string required property")
			}
			rawChild, ok := properties[name]
			if !ok {
				return nil, fmt.Errorf("benchmark schema missing required property %q", name)
			}
			child, ok := rawChild.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("benchmark schema property %q is not an object", name)
			}
			value, err := judgeBenchmarkCleanSchemaValue(child, name)
			if err != nil {
				return nil, err
			}
			result[name] = value
		}
		return result, nil
	case "array":
		return []interface{}{}, nil
	case "boolean":
		return false, nil
	case "string":
		if values, ok := schema["enum"].([]interface{}); ok {
			for _, preferred := range []string{"none", "weak_signal", "NONE", "false_positive"} {
				for _, value := range values {
					if value == preferred {
						return preferred, nil
					}
				}
			}
			if len(values) > 0 {
				if value, ok := values[0].(string); ok {
					return value, nil
				}
			}
		}
		switch propertyName {
		case "signal_strength":
			return "weak_signal", nil
		case "severity":
			return "NONE", nil
		case "verdict":
			return "false_positive", nil
		default:
			return "", nil
		}
	default:
		return nil, fmt.Errorf("benchmark schema property %q has unsupported type %q", propertyName, typeName)
	}
}

type corpusJudgePrediction struct {
	SchemaVersion       string   `json:"schema_version"`
	CaseID              string   `json:"case_id"`
	Dataset             string   `json:"dataset"`
	Surface             string   `json:"surface"`
	Campaign            string   `json:"campaign,omitempty"`
	Domain              string   `json:"domain,omitempty"`
	FamilyID            string   `json:"family_id,omitempty"`
	SourceTruth         string   `json:"source_truth"`
	DeterministicTruth  string   `json:"deterministic_truth,omitempty"`
	ExpectedDisposition string   `json:"expected_disposition"`
	LabelConfidence     string   `json:"label_confidence,omitempty"`
	Model               string   `json:"model"`
	Action              string   `json:"action"`
	Severity            string   `json:"severity"`
	Detected            bool     `json:"detected"`
	JudgeFailed         bool     `json:"judge_failed"`
	FindingIDs          []string `json:"finding_ids,omitempty"`
	DecisionCount       int      `json:"decision_count"`
	DetectedDecisions   int      `json:"detected_decision_count"`
	BlockedDecisions    int      `json:"blocked_decision_count"`
	InvocationCount     int      `json:"invocation_count"`
	ProviderErrorCount  int      `json:"provider_error_count"`
	JSONModeCount       int      `json:"json_mode_count"`
	PromptTokens        int64    `json:"prompt_tokens"`
	CompletionTokens    int64    `json:"completion_tokens"`
	TotalTokens         int64    `json:"total_tokens"`
	ProviderLatencyMS   float64  `json:"provider_latency_ms"`
	EndToEndLatencyMS   float64  `json:"end_to_end_latency_ms"`
	RequestSHA256       []string `json:"request_sha256,omitempty"`
}

type corpusJudgeMetadata struct {
	SchemaVersion   string    `json:"schema_version"`
	GeneratedAt     time.Time `json:"generated_at"`
	Corpus          string    `json:"corpus"`
	CorpusSHA256    string    `json:"corpus_sha256"`
	Model           string    `json:"model"`
	BaseURL         string    `json:"base_url"`
	RulePack        string    `json:"rule_pack"`
	CaseCount       int       `json:"case_count"`
	InvocationCount int       `json:"invocation_count"`
	WallClockMS     float64   `json:"wall_clock_ms"`
	Temperature     float64   `json:"temperature"`
	ResponseFormat  string    `json:"response_format"`
	ProductionPath  string    `json:"production_path"`
	Concurrency     int       `json:"concurrency"`
	BedrockRegion   string    `json:"bedrock_region,omitempty"`
	BedrockAuthMode string    `json:"bedrock_auth_mode,omitempty"`
}

func TestLLMJudgeDeterministicCorpus(t *testing.T) {
	if os.Getenv("GUARDRAIL_BENCHMARK_LLM") != "1" {
		t.Skip("set GUARDRAIL_BENCHMARK_LLM=1 to run the production-path LLM judge benchmark")
	}
	corpusPath := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_CORPUS"))
	outputPath := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_OUTPUT"))
	model := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_MODEL"))
	if corpusPath == "" || outputPath == "" || model == "" {
		t.Fatal("DEFENSECLAW_JUDGE_BENCHMARK_CORPUS, _OUTPUT, and _MODEL are required")
	}
	baseURL := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_BASE_URL"))
	if baseURL == "" {
		baseURL = "http://127.0.0.1:11434"
	}
	rulePackPath := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_RULE_PACK"))
	rulePack, err := guardrail.LoadRulePack(rulePackPath)
	if err != nil {
		t.Fatalf("load rule pack: %v", err)
	}
	if !strings.Contains(model, "/") {
		model = "ollama/" + model
	}
	concurrency := benchmarkConcurrency(t)

	cases, corpusData, err := readCorpusJudgeCases(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.JudgeConfig{
		Enabled: true, Injection: true, PII: true, PIIPrompt: true,
		PIICompletion: true, Exfil: true, ToolInjection: true,
		Timeout: 120, AdjudicationTimeout: 120,
	}
	llm := benchmarkLLMConfig(model, baseURL)
	judge := NewLLMJudge(cfg, llm, "", rulePack, nil)
	if judge == nil {
		t.Fatal("production LLM judge failed to initialize")
	}
	recorder := &judgeBenchmarkProvider{delegate: judge.provider}
	judge.provider = recorder

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		t.Fatal(err)
	}
	startIndex := 0
	priorInvocations := 0
	priorWallClockMS := float64(0)
	openFlags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	if os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_RESUME") == "1" {
		prior, readErr := readCorpusJudgePredictions(outputPath)
		if readErr != nil {
			t.Fatalf("resume prior predictions: %v", readErr)
		}
		if os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_RETRY_FAILURES") == "1" {
			prefix := successfulCorpusJudgePrefix(prior)
			if len(prefix) != len(prior) {
				if err := writeCorpusJudgePredictions(outputPath, prefix); err != nil {
					t.Fatalf("repair failed prediction suffix: %v", err)
				}
				t.Logf("judge benchmark retry: removed %d failed suffix rows", len(prior)-len(prefix))
				prior = prefix
			}
		}
		if len(prior) > len(cases) {
			t.Fatalf("resume output has %d rows for %d cases", len(prior), len(cases))
		}
		for index := range prior {
			if prior[index].CaseID != cases[index].ID || prior[index].Model != model {
				t.Fatalf("resume output row %d does not match corpus/model", index+1)
			}
			if err := validateCorpusJudgeResumeContract(t.Context(), judge, model, cases[index], prior[index]); err != nil {
				t.Fatalf("resume output row %d: %v", index+1, err)
			}
			priorInvocations += prior[index].InvocationCount
			priorWallClockMS += prior[index].EndToEndLatencyMS
		}
		startIndex = len(prior)
		if startIndex > 0 {
			openFlags = os.O_CREATE | os.O_APPEND | os.O_WRONLY
			t.Logf("judge benchmark resume: %d/%d cases, %d prior model calls", startIndex, len(cases), priorInvocations)
		}
	}
	output, err := os.OpenFile(outputPath, openFlags, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(output)
	runStarted := time.Now()
	type indexedPrediction struct {
		index      int
		prediction corpusJudgePrediction
	}
	jobs := make(chan int, concurrency)
	results := make(chan indexedPrediction, concurrency)
	var workers sync.WaitGroup
	for range concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				results <- indexedPrediction{
					index:      index,
					prediction: runCorpusJudgeCase(t.Context(), judge, recorder, model, cases[index]),
				}
			}
		}()
	}
	go func() {
		for index := startIndex; index < len(cases); index++ {
			jobs <- index
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()

	// Preserve corpus order on disk so resume remains a validated prefix even
	// when provider calls complete out of order. The small pending map is also
	// what lets a completed contiguous prefix survive an interrupted large run.
	next := startIndex
	pending := make(map[int]corpusJudgePrediction, concurrency)
	var encodeErr error
	for result := range results {
		pending[result.index] = result.prediction
		for encodeErr == nil {
			prediction, ok := pending[next]
			if !ok {
				break
			}
			if err := encoder.Encode(prediction); err != nil {
				encodeErr = err
				break
			}
			delete(pending, next)
			next++
			if next%10 == 0 || next == len(cases) {
				t.Logf("judge benchmark progress: %d/%d cases, %d model calls", next, len(cases), recorder.count())
			}
		}
	}
	if encodeErr != nil {
		_ = output.Close()
		t.Fatal(encodeErr)
	}
	if next != len(cases) {
		_ = output.Close()
		t.Fatalf("judge benchmark completed %d/%d ordered cases", next, len(cases))
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(corpusData)
	metadata := corpusJudgeMetadata{
		SchemaVersion: "1", GeneratedAt: time.Now().UTC(), Corpus: corpusPath,
		CorpusSHA256: hex.EncodeToString(digest[:]), Model: model, BaseURL: llm.BaseURL,
		RulePack: rulePackPath, CaseCount: len(cases), InvocationCount: priorInvocations + recorder.count(),
		WallClockMS: priorWallClockMS + float64(time.Since(runStarted).Microseconds())/1000,
		Temperature: 0, ResponseFormat: "json_schema",
		ProductionPath: "gateway.LLMJudge.RunJudges/RunToolJudge via Bifrost",
		Concurrency:    concurrency,
	}
	if llm.Bedrock != nil {
		metadata.BedrockRegion = llm.Bedrock.Region
		metadata.BedrockAuthMode = llm.Bedrock.AuthMode
	}
	metadataData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	metadataPath := outputPath + ".meta.json"
	if err := os.WriteFile(metadataPath, append(metadataData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func benchmarkLLMConfig(model, baseURL string) config.LLMConfig {
	llm := config.LLMConfig{
		Model:      model,
		BaseURL:    baseURL,
		APIKeyEnv:  strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_API_KEY_ENV")),
		Timeout:    120,
		MaxRetries: 1,
	}
	provider, _ := splitModel(model)
	if strings.EqualFold(provider, "bedrock") || strings.EqualFold(provider, "amazon-bedrock") {
		llm.BaseURL = ""
		llm.Bedrock = &config.BedrockKeyConfig{
			Region:          strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_REGION")),
			AuthMode:        strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_AUTH_MODE")),
			ProfileName:     strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_PROFILE")),
			AccessKeyEnv:    firstNonEmpty(strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_ACCESS_KEY_ENV")), "AWS_ACCESS_KEY_ID"),
			SecretKeyEnv:    firstNonEmpty(strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_SECRET_KEY_ENV")), "AWS_SECRET_ACCESS_KEY"),
			SessionTokenEnv: firstNonEmpty(strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_SESSION_TOKEN_ENV")), "AWS_SESSION_TOKEN"),
		}
	}
	return llm
}

func TestBenchmarkLLMConfigBedrock(t *testing.T) {
	t.Setenv("DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_REGION", "us-east-1")
	t.Setenv("DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_AUTH_MODE", "profile")
	t.Setenv("DEFENSECLAW_JUDGE_BENCHMARK_BEDROCK_PROFILE", "judge-benchmark")
	llm := benchmarkLLMConfig("bedrock/google.gemma-3-12b-it", "http://127.0.0.1:11434")
	if llm.BaseURL != "" {
		t.Fatalf("Bedrock benchmark retained local base URL %q", llm.BaseURL)
	}
	if llm.Bedrock == nil || llm.Bedrock.Region != "us-east-1" || llm.Bedrock.AuthMode != "profile" || llm.Bedrock.ProfileName != "judge-benchmark" {
		t.Fatalf("unexpected Bedrock benchmark config: %+v", llm.Bedrock)
	}
}

func benchmarkConcurrency(t *testing.T) int {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv("DEFENSECLAW_JUDGE_BENCHMARK_CONCURRENCY"))
	if raw == "" {
		return 1
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 64 {
		t.Fatalf("DEFENSECLAW_JUDGE_BENCHMARK_CONCURRENCY must be an integer from 1 through 64, got %q", raw)
	}
	return value
}

func readCorpusJudgePredictions(path string) ([]corpusJudgePrediction, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var predictions []corpusJudgePrediction
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var prediction corpusJudgePrediction
		if err := json.Unmarshal(scanner.Bytes(), &prediction); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		if prediction.SchemaVersion != "1" || prediction.CaseID == "" || prediction.Model == "" {
			return nil, fmt.Errorf("%s:%d: invalid prediction identity", path, lineNumber)
		}
		predictions = append(predictions, prediction)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return predictions, nil
}

func successfulCorpusJudgePrefix(predictions []corpusJudgePrediction) []corpusJudgePrediction {
	for index := range predictions {
		if predictions[index].JudgeFailed || predictions[index].ProviderErrorCount > 0 {
			return predictions[:index]
		}
	}
	return predictions
}

func validateCorpusJudgeResumeContract(
	ctx context.Context,
	judge *LLMJudge,
	model string,
	benchmarkCase corpusJudgeCase,
	prior corpusJudgePrediction,
) error {
	contractJudge := &LLMJudge{
		cfg: judge.cfg, model: judge.model, providerName: judge.providerName, rp: judge.rp,
	}
	recorder := &judgeBenchmarkProvider{delegate: judgeBenchmarkContractProvider{}}
	contractJudge.provider = recorder
	expected := runCorpusJudgeCase(ctx, contractJudge, recorder, model, benchmarkCase).RequestSHA256
	actual := append([]string(nil), prior.RequestSHA256...)
	// Sort because request ordering for concurrent text judges is not
	// semantically meaningful. The hashes resulting multiset still pins every
	// exact request and its invocation count.
	sort.Strings(expected)
	sort.Strings(actual)
	if len(expected) > 0 && len(actual) == 0 {
		return errors.New("missing request_sha256 values; restart without DEFENSECLAW_JUDGE_BENCHMARK_RESUME")
	}
	if !equalCorpusJudgeStrings(actual, expected) {
		return errors.New("benchmark request contract changed; restart without DEFENSECLAW_JUDGE_BENCHMARK_RESUME")
	}
	return nil
}

func equalCorpusJudgeStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func writeCorpusJudgePredictions(path string, predictions []corpusJudgePrediction) error {
	temporary := path + ".repair.tmp"
	output, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	for index := range predictions {
		if err := encoder.Encode(predictions[index]); err != nil {
			_ = output.Close()
			_ = os.Remove(temporary)
			return err
		}
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func TestReadCorpusJudgePredictionsForResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "predictions.jsonl")
	data := "{\"schema_version\":\"1\",\"case_id\":\"case-1\",\"model\":\"ollama/test\",\"invocation_count\":2,\"end_to_end_latency_ms\":12.5}\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	predictions, err := readCorpusJudgePredictions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(predictions) != 1 || predictions[0].CaseID != "case-1" || predictions[0].InvocationCount != 2 {
		t.Fatalf("unexpected resume predictions: %+v", predictions)
	}
}

func TestSuccessfulCorpusJudgePrefixDropsFirstFailureAndSuffix(t *testing.T) {
	predictions := []corpusJudgePrediction{
		{CaseID: "good"},
		{CaseID: "failed", JudgeFailed: true, ProviderErrorCount: 1},
		{CaseID: "later"},
	}
	prefix := successfulCorpusJudgePrefix(predictions)
	if len(prefix) != 1 || prefix[0].CaseID != "good" {
		t.Fatalf("unexpected successful prefix: %+v", prefix)
	}
}

func TestValidateCorpusJudgeResumeContract(t *testing.T) {
	judge := &LLMJudge{
		cfg: &config.JudgeConfig{
			Enabled: true, ToolInjection: true, Timeout: 5,
		},
		model: "ollama/test",
	}
	benchmarkCase := corpusJudgeCase{SchemaVersion: "1", ID: "case-1", Surface: "action"}
	benchmarkCase.Payload.ToolName = "shell"
	benchmarkCase.Payload.Command = "git status --short"

	contractJudge := &LLMJudge{cfg: judge.cfg, model: judge.model, rp: judge.rp}
	recorder := &judgeBenchmarkProvider{delegate: judgeBenchmarkContractProvider{}}
	contractJudge.provider = recorder
	prior := runCorpusJudgeCase(t.Context(), contractJudge, recorder, judge.model, benchmarkCase)
	if len(prior.RequestSHA256) != 1 {
		t.Fatalf("contract request hashes = %v, want one", prior.RequestSHA256)
	}
	if err := validateCorpusJudgeResumeContract(t.Context(), judge, judge.model, benchmarkCase, prior); err != nil {
		t.Fatalf("unchanged request contract rejected: %v", err)
	}

	prior.RequestSHA256[0] = strings.Repeat("0", 64)
	if err := validateCorpusJudgeResumeContract(t.Context(), judge, judge.model, benchmarkCase, prior); err == nil ||
		!strings.Contains(err.Error(), "request contract changed") {
		t.Fatalf("stale request contract error = %v", err)
	}

	emptyCase := corpusJudgeCase{SchemaVersion: "1", ID: "empty-case", Surface: "action"}
	emptyCase.Payload.ToolName = "shell"
	emptyPrior := corpusJudgePrediction{SchemaVersion: "1", CaseID: "empty-case", Model: judge.model}
	if err := validateCorpusJudgeResumeContract(t.Context(), judge, judge.model, emptyCase, emptyPrior); err != nil {
		t.Fatalf("legitimate zero-invocation resume rejected: %v", err)
	}
}

func TestJudgeBenchmarkCleanSchemaResponse(t *testing.T) {
	content, err := judgeBenchmarkCleanSchemaResponse(judgeResponseFormat("tool_injection"))
	if err != nil {
		t.Fatal(err)
	}
	parsedTool := parseJudgeJSON(content)
	if parsedTool == nil || len(parsedTool) != len(toolInjectionCategories) {
		t.Fatalf("tool clean response = %s", content)
	}
	for category := range toolInjectionCategories {
		if parsedTool[category] != "none" {
			t.Fatalf("tool clean category %q = %#v", category, parsedTool[category])
		}
	}

	content, err = judgeBenchmarkCleanSchemaResponse(judgeResponseFormat("injection"))
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseJudgeJSON(content)
	if parsed == nil || len(parsed) != len(injectionCategories) {
		t.Fatalf("injection clean response = %s", content)
	}
}

func readCorpusJudgeCases(path string) ([]corpusJudgeCase, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var cases []corpusJudgeCase
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	seen := make(map[string]struct{})
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var benchmarkCase corpusJudgeCase
		if err := json.Unmarshal(scanner.Bytes(), &benchmarkCase); err != nil {
			return nil, nil, fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		if benchmarkCase.SchemaVersion != "1" || strings.TrimSpace(benchmarkCase.ID) == "" {
			return nil, nil, fmt.Errorf("%s:%d: invalid case identity", path, lineNumber)
		}
		if _, exists := seen[benchmarkCase.ID]; exists {
			return nil, nil, fmt.Errorf("%s:%d: duplicate case ID %q", path, lineNumber, benchmarkCase.ID)
		}
		seen[benchmarkCase.ID] = struct{}{}
		cases = append(cases, benchmarkCase)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	if len(cases) == 0 {
		return nil, nil, errors.New("corpus is empty")
	}
	return cases, data, nil
}

func runCorpusJudgeCase(
	ctx context.Context,
	judge *LLMJudge,
	recorder *judgeBenchmarkProvider,
	model string,
	benchmarkCase corpusJudgeCase,
) corpusJudgePrediction {
	collector := &judgeBenchmarkCollector{}
	ctx = context.WithValue(ctx, judgeBenchmarkCollectorKey{}, collector)
	started := time.Now()
	var verdict *ScanVerdict
	var decisions []*ScanVerdict
	switch benchmarkCase.Surface {
	case "action":
		verdict = judge.RunToolJudge(ctx, benchmarkCase.Payload.ToolName, corpusJudgeToolArgs(
			benchmarkCase.Payload.Args, benchmarkCase.Payload.Command, benchmarkCase.Payload.Argv,
		))
		decisions = []*ScanVerdict{verdict}
	case "stateful":
		// Production hook contexts carry an authenticated connector session ID.
		// Use a case-unique ID so the benchmark exercises the same bounded
		// per-session history without allowing context to cross trajectories.
		ctx = ContextWithSessionID(ctx, benchmarkCase.ID)
		judge.ResetToolJudgeSession(benchmarkCase.ID)
		if strings.TrimSpace(benchmarkCase.Payload.Content) != "" {
			judge.ObserveSessionPrompt(ctx, benchmarkCase.Payload.Content)
		}
		verdicts := make([]*ScanVerdict, 0, len(benchmarkCase.Payload.Events))
		for _, event := range benchmarkCase.Payload.Events {
			verdicts = append(verdicts, judge.RunToolJudge(ctx, event.ToolName, corpusJudgeToolArgs(
				event.Args, event.Command, event.Argv,
			)))
		}
		decisions = verdicts
		verdict = mergeJudgeVerdicts(verdicts)
	case "text", "e2e":
		direction := benchmarkCase.Payload.Direction
		if direction == "" {
			direction = "prompt"
		}
		verdict = judge.RunJudges(ctx, direction, benchmarkCase.Payload.Content, "")
		decisions = []*ScanVerdict{verdict}
	default:
		verdict = errorVerdict("llm-judge-unsupported-surface")
		decisions = []*ScanVerdict{verdict}
	}
	endToEndMS := float64(time.Since(started).Microseconds()) / 1000
	records := collector.snapshot()
	prediction := corpusJudgePrediction{
		SchemaVersion: "1", CaseID: benchmarkCase.ID, Dataset: benchmarkCase.Source.Dataset,
		Surface: benchmarkCase.Surface, Campaign: benchmarkCase.Strata.Campaign,
		Domain: benchmarkCase.Strata.Domain, FamilyID: firstNonEmpty(
			benchmarkCase.Strata.TrajectoryID, benchmarkCase.Strata.SplitGroup,
		),
		SourceTruth:         benchmarkCase.Truth.SourceTruth,
		DeterministicTruth:  benchmarkCase.Truth.DeterministicTruth,
		ExpectedDisposition: benchmarkCase.Truth.ExpectedDisposition,
		LabelConfidence:     benchmarkCase.Truth.LabelConfidence, Model: model,
		Action: verdict.Action, Severity: verdict.Severity,
		Detected:    verdict.Severity != "NONE" && verdict.Action != "allow",
		JudgeFailed: verdict.JudgeFailed, FindingIDs: append([]string(nil), verdict.Findings...),
		DecisionCount: len(decisions), InvocationCount: len(records), EndToEndLatencyMS: endToEndMS,
	}
	for _, decision := range decisions {
		if decision == nil {
			continue
		}
		if decision.Severity != "NONE" && decision.Action != "allow" {
			prediction.DetectedDecisions++
		}
		if decision.Action == "block" {
			prediction.BlockedDecisions++
		}
	}
	for _, record := range records {
		prediction.ProviderLatencyMS += record.LatencyMS
		prediction.PromptTokens += record.PromptTokens
		prediction.CompletionTokens += record.CompletionTokens
		prediction.TotalTokens += record.TotalTokens
		prediction.RequestSHA256 = append(prediction.RequestSHA256, record.RequestSHA256)
		if record.JSONMode {
			prediction.JSONModeCount++
		}
		if record.Error {
			prediction.ProviderErrorCount++
		}
	}
	prediction.ProviderLatencyMS = float64(int64(prediction.ProviderLatencyMS*1000)) / 1000
	prediction.EndToEndLatencyMS = float64(int64(prediction.EndToEndLatencyMS*1000)) / 1000
	sort.Strings(prediction.FindingIDs)
	return prediction
}

func corpusJudgeToolArgs(args json.RawMessage, command string, argv []string) string {
	trimmed := strings.TrimSpace(string(args))
	if trimmed != "" && trimmed != "null" && trimmed != "{}" {
		return trimmed
	}
	payload := make(map[string]interface{})
	if command != "" {
		payload["command"] = command
	}
	if len(argv) > 0 {
		payload["argv"] = argv
	}
	if len(payload) == 0 {
		return "{}"
	}
	data, _ := json.Marshal(payload)
	return string(data)
}

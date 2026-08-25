// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package training

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// EvalConfig holds configuration for LLM-as-judge evaluation.
type EvalConfig struct {
	EvalFilePath  string  // path to eval JSONL (from extractor)
	LocalEndpoint string  // http://127.0.0.1:8090 (llama-server)
	LocalModel    string  // model name for local inference
	JudgeEndpoint string  // http://127.0.0.1:11434 or frontier API
	JudgeModel    string  // model to use as judge
	JudgeAPIKey   string  // API key for judge (empty if local)
	EvalPrompts   int     // max prompts to evaluate (0 = all)
	Threshold     float64 // promotion threshold (e.g., 0.90)
}

// EvalResult contains the results of LLM-as-judge evaluation.
type EvalResult struct {
	ScoreLocal    float64
	ScoreFrontier float64
	Ratio         float64
	Passed        bool
	PromptsEval   int
	Errors        int
}

// openAIChatRequest represents a request to the OpenAI-compatible chat completion API.
type openAIChatRequest struct {
	Model    string                   `json:"model"`
	Messages []map[string]interface{} `json:"messages"`
}

// openAIChatResponse represents a response from the OpenAI-compatible chat completion API.
type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// judgeScores represents the JSON response from the judge model.
type judgeScores struct {
	ScoreA float64 `json:"score_a"`
	ScoreB float64 `json:"score_b"`
}

const judgePromptTemplate = `Rate these two responses on accuracy, helpfulness, and completeness (1-10 scale).

Question: %s

Response A: %s

Response B: %s

Return ONLY valid JSON with this format: {"score_a": N, "score_b": N}
Do not include any other text or explanation.`

// Evaluate runs the LLM-as-judge comparison between local model and frontier responses.
func Evaluate(ctx context.Context, cfg EvalConfig) (*EvalResult, error) {
	// Validate configuration
	if cfg.EvalFilePath == "" {
		return nil, fmt.Errorf("eval file path is required")
	}
	if cfg.LocalEndpoint == "" {
		return nil, fmt.Errorf("local endpoint is required")
	}
	if cfg.LocalModel == "" {
		return nil, fmt.Errorf("local model is required")
	}
	if cfg.JudgeEndpoint == "" {
		return nil, fmt.Errorf("judge endpoint is required")
	}
	if cfg.JudgeModel == "" {
		return nil, fmt.Errorf("judge model is required")
	}
	if cfg.Threshold < 0 || cfg.Threshold > 1 {
		return nil, fmt.Errorf("threshold must be between 0 and 1, got %.2f", cfg.Threshold)
	}

	// Open eval file
	f, err := os.Open(cfg.EvalFilePath)
	if err != nil {
		return nil, fmt.Errorf("open eval file: %w", err)
	}
	defer f.Close()

	// Read JSONL entries
	scanner := bufio.NewScanner(f)
	var entries []JSONLEntry
	for scanner.Scan() {
		var entry JSONLEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("parse JSONL entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read eval file: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries found in eval file")
	}

	// Limit number of prompts to evaluate
	promptCount := len(entries)
	if cfg.EvalPrompts > 0 && cfg.EvalPrompts < promptCount {
		promptCount = cfg.EvalPrompts
		entries = entries[:promptCount]
	}

	// Evaluate each prompt
	var totalScoreLocal, totalScoreFrontier float64
	var errors int

	for i, entry := range entries {
		// Get local model response
		localResponse, err := callChatCompletion(ctx, cfg.LocalEndpoint, cfg.LocalModel, "", []map[string]interface{}{
			{"role": "user", "content": entry.Prompt},
		})
		if err != nil {
			errors++
			fmt.Fprintf(os.Stderr, "Error getting local response for prompt %d: %v\n", i+1, err)
			continue
		}

		// Use frontier response from JSONL
		frontierResponse := entry.Response

		// Get judge scores
		judgePrompt := fmt.Sprintf(judgePromptTemplate, entry.Prompt, localResponse, frontierResponse)
		judgeResponse, err := callChatCompletion(ctx, cfg.JudgeEndpoint, cfg.JudgeModel, cfg.JudgeAPIKey, []map[string]interface{}{
			{"role": "user", "content": judgePrompt},
		})
		if err != nil {
			errors++
			fmt.Fprintf(os.Stderr, "Error getting judge response for prompt %d: %v\n", i+1, err)
			continue
		}

		// Parse judge scores
		scoreA, scoreB, err := parseJudgeScores(judgeResponse)
		if err != nil {
			errors++
			fmt.Fprintf(os.Stderr, "Error parsing judge scores for prompt %d: %v\n", i+1, err)
			continue
		}

		totalScoreLocal += scoreA
		totalScoreFrontier += scoreB
	}

	// Calculate results
	successfulEvals := promptCount - errors
	if successfulEvals == 0 {
		return nil, fmt.Errorf("no successful evaluations completed")
	}

	avgScoreLocal := totalScoreLocal / float64(successfulEvals)
	avgScoreFrontier := totalScoreFrontier / float64(successfulEvals)
	ratio := 0.0
	if avgScoreFrontier > 0 {
		ratio = avgScoreLocal / avgScoreFrontier
	}

	return &EvalResult{
		ScoreLocal:    avgScoreLocal,
		ScoreFrontier: avgScoreFrontier,
		Ratio:         ratio,
		Passed:        ratio >= cfg.Threshold,
		PromptsEval:   successfulEvals,
		Errors:        errors,
	}, nil
}

// callChatCompletion makes a request to an OpenAI-compatible chat completion endpoint.
func callChatCompletion(ctx context.Context, endpoint, model, apiKey string, messages []map[string]interface{}) (string, error) {
	// Prepare request
	reqBody := openAIChatRequest{
		Model:    model,
		Messages: messages,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	// Create HTTP request
	url := endpoint
	if !strings.HasSuffix(url, "/v1/chat/completions") {
		url = strings.TrimSuffix(url, "/") + "/v1/chat/completions"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var chatResp openAIChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	return chatResp.Choices[0].Message.Content, nil
}

// parseJudgeScores extracts score_a and score_b from the judge model's JSON response.
func parseJudgeScores(response string) (float64, float64, error) {
	// Try to find JSON in the response (handle cases where model adds extra text)
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")

	if start == -1 || end == -1 || end < start {
		return 0, 0, fmt.Errorf("no JSON object found in response")
	}

	jsonStr := response[start : end+1]

	var scores judgeScores
	if err := json.Unmarshal([]byte(jsonStr), &scores); err != nil {
		return 0, 0, fmt.Errorf("unmarshal judge scores: %w", err)
	}

	// Validate scores are in reasonable range
	if scores.ScoreA < 0 || scores.ScoreA > 10 {
		return 0, 0, fmt.Errorf("score_a out of range: %.2f", scores.ScoreA)
	}
	if scores.ScoreB < 0 || scores.ScoreB > 10 {
		return 0, 0, fmt.Errorf("score_b out of range: %.2f", scores.ScoreB)
	}

	return scores.ScoreA, scores.ScoreB, nil
}

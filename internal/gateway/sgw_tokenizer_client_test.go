// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeSGWToolCaller struct {
	mu       sync.Mutex
	name     string
	args     any
	response []byte
	err      error
}

func (f *fakeSGWToolCaller) CallTool(_ context.Context, name string, args any) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.name = name
	f.args = args
	return f.response, f.err
}

func (*fakeSGWToolCaller) Close() error { return nil }

func TestSGWCredentialTokenizerUsesRestrictedToolAndStrictResult(t *testing.T) {
	caller := &fakeSGWToolCaller{response: []byte(`{
		"protocolVersion":1,
		"requestId":"request-1",
		"outcome":"ready",
		"segments":[{"id":"/input","text":"<<SGW_SECRET:s-gw:test:one>>"}]
	}`)}
	tokenizer, err := newSGWCredentialTokenizer(caller)
	if err != nil {
		t.Fatalf("new tokenizer: %v", err)
	}
	request := CredentialTokenizationRequest{
		ProtocolVersion: 1,
		RequestID:       "request-1",
		Connector:       "codex",
		Provider:        "openai",
		Path:            "/v1/responses",
		Segments: []CredentialTokenizationSegment{{
			ID: "/input", Text: "synthetic input",
		}},
	}
	result, err := tokenizer.PrepareProxyTokenization(context.Background(), request)
	if err != nil {
		t.Fatalf("prepare tokenization: %v", err)
	}
	if caller.name != sgwTokenizerToolName {
		t.Fatalf("tool = %q, want %q", caller.name, sgwTokenizerToolName)
	}
	if result.RequestID != request.RequestID || result.Outcome != CredentialTokenizationReady {
		t.Fatalf("result = %#v", result)
	}
}

func TestSGWCredentialTokenizerRejectsExpandedPrivilegeResponse(t *testing.T) {
	caller := &fakeSGWToolCaller{response: []byte(`{
		"protocolVersion":1,
		"requestId":"request-1",
		"outcome":"clean",
		"handles":["s-gw:credential:unexpected"]
	}`)}
	tokenizer, err := newSGWCredentialTokenizer(caller)
	if err != nil {
		t.Fatalf("new tokenizer: %v", err)
	}
	_, err = tokenizer.PrepareProxyTokenization(context.Background(), CredentialTokenizationRequest{})
	if !errors.Is(err, errSGWMCPProtocol) {
		t.Fatalf("error = %v, want protocol error", err)
	}
}

func TestSGWCredentialTokenizerRejectsDuplicateOutcome(t *testing.T) {
	caller := &fakeSGWToolCaller{response: []byte(`{
		"protocolVersion":1,
		"requestId":"request-1",
		"outcome":"clean",
		"outcome":"ready",
		"segments":[]
	}`)}
	tokenizer, err := newSGWCredentialTokenizer(caller)
	if err != nil {
		t.Fatalf("new tokenizer: %v", err)
	}
	_, err = tokenizer.PrepareProxyTokenization(context.Background(), CredentialTokenizationRequest{})
	if !errors.Is(err, errSGWMCPProtocol) {
		t.Fatalf("error = %v, want protocol error", err)
	}
}

func TestSGWCredentialTokenizerDoesNotReturnChildErrorDetail(t *testing.T) {
	const raw = "synthetic-child-secret"
	caller := &fakeSGWToolCaller{err: errors.New(raw)}
	tokenizer, err := newSGWCredentialTokenizer(caller)
	if err != nil {
		t.Fatalf("new tokenizer: %v", err)
	}
	_, err = tokenizer.PrepareProxyTokenization(context.Background(), CredentialTokenizationRequest{})
	if err == nil || strings.Contains(err.Error(), raw) {
		t.Fatalf("unsafe error = %v", err)
	}
}

func TestSGWMCPProcessConcurrentCallsStayBoundToRequest(t *testing.T) {
	process := startSGWHelper(t, "normal")
	defer process.Close()
	tokenizer, err := newSGWCredentialTokenizer(process)
	if err != nil {
		t.Fatalf("new tokenizer: %v", err)
	}

	const calls = 20
	errCh := make(chan error, calls)
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			requestID := fmt.Sprintf("request-%d", index)
			result, callErr := tokenizer.PrepareProxyTokenization(context.Background(), CredentialTokenizationRequest{
				ProtocolVersion: 1,
				RequestID:       requestID,
				Connector:       "codex",
				Provider:        "openai",
				Segments:        []CredentialTokenizationSegment{{ID: "/input", Text: "plain text"}},
			})
			if callErr != nil {
				errCh <- callErr
				return
			}
			if result.RequestID != requestID || result.Outcome != CredentialTokenizationClean {
				errCh <- fmt.Errorf("response mismatch: %#v", result)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for callErr := range errCh {
		t.Error(callErr)
	}
}

func TestSGWMCPProcessTimeoutTerminatesHungBroker(t *testing.T) {
	process := startSGWHelper(t, "hang")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := process.CallTool(ctx, sgwTokenizerToolName, map[string]any{"requestId": "hang"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	select {
	case <-process.closed:
	default:
		t.Fatal("hung broker process was not closed")
	}
}

func TestSGWMCPProcessDoesNotInheritParentCredentialEnvironment(t *testing.T) {
	t.Setenv("SGW_CLIENT_SENTINEL", "must-not-reach-child")
	process := startSGWHelper(t, "env-check")
	defer process.Close()
	result, err := process.CallTool(context.Background(), sgwTokenizerToolName, map[string]any{
		"requestId": "environment-check",
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if strings.Contains(string(result), "must-not-reach-child") {
		t.Fatal("parent credential environment reached child")
	}
}

func TestSGWMCPProcessRejectsExpandedToolEnvelope(t *testing.T) {
	process := startSGWHelper(t, "expanded-tool-result")
	defer process.Close()
	_, err := process.CallTool(context.Background(), sgwTokenizerToolName, map[string]any{
		"requestId": "expanded",
	})
	if !errors.Is(err, errSGWMCPProtocol) {
		t.Fatalf("error = %v, want protocol error", err)
	}
}

func TestSGWMCPProcessRejectsUnexpectedRunnerIdentity(t *testing.T) {
	_, err := startSGWTestHelper(t, "wrong-server")
	if !errors.Is(err, errSGWMCPProtocol) {
		t.Fatalf("error = %v, want protocol error", err)
	}
}

func TestSGWMCPProcessRejectsExpandedToolInventory(t *testing.T) {
	_, err := startSGWTestHelper(t, "expanded-tools")
	if !errors.Is(err, errSGWMCPProtocol) {
		t.Fatalf("error = %v, want protocol error", err)
	}
}

func startSGWHelper(t *testing.T, mode string) *sgwMCPProcess {
	t.Helper()
	process, err := startSGWTestHelper(t, mode)
	if err != nil {
		t.Fatalf("start helper: %v", err)
	}
	return process
}

func startSGWTestHelper(t *testing.T, mode string) (*sgwMCPProcess, error) {
	t.Helper()
	return startSGWMCPProcess(
		os.Args[0],
		[]string{"-test.run=^TestSGWMCPHelperProcess$"},
		[]string{"GO_WANT_SGW_MCP_HELPER=1", "SGW_MCP_HELPER_MODE=" + mode},
		t.TempDir(),
	)
}

func TestSGWMCPHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SGW_MCP_HELPER") != "1" {
		return
	}
	mode := os.Getenv("SGW_MCP_HELPER_MODE")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), sgwMCPMaxFrameBytes)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(scanner.Bytes(), &request) != nil {
			os.Exit(2)
		}
		switch request.Method {
		case "initialize":
			serverName := sgwRunnerServerName
			if mode == "wrong-server" {
				serverName = "not-s-gw-core"
			}
			writeSGWHelperResponse(encoder, request.ID, map[string]any{
				"protocolVersion": sgwMCPProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]string{"name": serverName, "version": sgwRunnerVersion},
			})
		case "notifications/initialized":
			continue
		case "tools/list":
			tools := []map[string]any{{
				"name":        sgwTokenizerToolName,
				"description": "fixture tokenizer",
				"inputSchema": map[string]any{"type": "object"},
			}}
			if mode == "expanded-tools" {
				tools = append(tools, map[string]any{
					"name":        "sgw_export_credentials",
					"description": "must not be admitted",
					"inputSchema": map[string]any{"type": "object"},
				})
			}
			writeSGWHelperResponse(encoder, request.ID, map[string]any{"tools": tools})
		case "tools/call":
			if mode == "hang" {
				time.Sleep(time.Hour)
			}
			var params struct {
				Arguments struct {
					RequestID string `json:"requestId"`
				} `json:"arguments"`
			}
			if json.Unmarshal(request.Params, &params) != nil {
				os.Exit(3)
			}
			payload := map[string]any{
				"protocolVersion": 1,
				"requestId":       params.Arguments.RequestID,
				"outcome":         "clean",
			}
			if mode == "env-check" && os.Getenv("SGW_CLIENT_SENTINEL") != "" {
				payload["leaked"] = os.Getenv("SGW_CLIENT_SENTINEL")
			}
			encoded, _ := json.Marshal(payload)
			result := map[string]any{
				"content": []map[string]string{{"type": "text", "text": string(encoded)}},
			}
			if mode == "expanded-tool-result" {
				result["structuredContent"] = map[string]any{"unexpected": true}
			}
			writeSGWHelperResponse(encoder, request.ID, result)
		default:
			os.Exit(4)
		}
	}
	os.Exit(0)
}

func writeSGWHelperResponse(encoder *json.Encoder, id json.RawMessage, result any) {
	if err := encoder.Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}); err != nil {
		os.Exit(5)
	}
}

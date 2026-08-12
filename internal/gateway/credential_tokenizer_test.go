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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/configs"
)

type fakeCredentialTokenizer struct {
	mu       sync.Mutex
	requests []CredentialTokenizationRequest
	prepare  func(context.Context, CredentialTokenizationRequest) (CredentialTokenizationResult, error)
}

type blockingCredentialTokenizer struct {
	release   <-chan struct{}
	active    int32
	maxActive int32
	started   int32
}

func (b *blockingCredentialTokenizer) PrepareProxyTokenization(
	context.Context,
	CredentialTokenizationRequest,
) (CredentialTokenizationResult, error) {
	active := atomic.AddInt32(&b.active, 1)
	atomic.AddInt32(&b.started, 1)
	for {
		previous := atomic.LoadInt32(&b.maxActive)
		if active <= previous || atomic.CompareAndSwapInt32(&b.maxActive, previous, active) {
			break
		}
	}
	<-b.release
	atomic.AddInt32(&b.active, -1)
	return CredentialTokenizationResult{}, nil
}

func (f *fakeCredentialTokenizer) PrepareProxyTokenization(
	ctx context.Context,
	request CredentialTokenizationRequest,
) (CredentialTokenizationResult, error) {
	f.mu.Lock()
	f.requests = append(f.requests, request)
	f.mu.Unlock()
	if f.prepare == nil {
		return CredentialTokenizationResult{
			ProtocolVersion: credentialTokenizerProtocolVersion,
			RequestID:       request.RequestID,
			Outcome:         CredentialTokenizationClean,
		}, nil
	}
	return f.prepare(ctx, request)
}

func (f *fakeCredentialTokenizer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeCredentialTokenizer) lastRequest() (CredentialTokenizationRequest, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return CredentialTokenizationRequest{}, false
	}
	return f.requests[len(f.requests)-1], true
}

func readyCredentialResult(request CredentialTokenizationRequest) CredentialTokenizationResult {
	segments := make([]CredentialTokenizationSegment, 0, len(request.Segments))
	for _, segment := range request.Segments {
		segments = append(segments, CredentialTokenizationSegment{
			ID:   segment.ID,
			Text: "<<SGW_SECRET:s-gw:test:handle>>",
		})
	}
	return CredentialTokenizationResult{
		ProtocolVersion: credentialTokenizerProtocolVersion,
		RequestID:       request.RequestID,
		Outcome:         CredentialTokenizationReady,
		Segments:        segments,
	}
}

type credentialCaptureInspector struct {
	mu       sync.Mutex
	contents []string
}

func (c *credentialCaptureInspector) Inspect(_ context.Context, _ string, content string, _ []ChatMessage, _, _ string) *ScanVerdict {
	c.mu.Lock()
	c.contents = append(c.contents, content)
	c.mu.Unlock()
	return allowVerdict("credential-test")
}

func (c *credentialCaptureInspector) InspectMidStream(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return c.Inspect(ctx, direction, content, messages, model, mode)
}

func (c *credentialCaptureInspector) SetScannerMode(string)      {}
func (c *credentialCaptureInspector) SetHILTConfig(bool, string) {}

func (c *credentialCaptureInspector) allContent() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.contents, "\n")
}

func TestCredentialTokenizationExtractsProviderText(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		provider string
		body     string
		wantIDs  []string
		mutable  bool
	}{
		{
			name: "OpenAI chat",
			path: "/v1/chat/completions",
			body: `{"messages":[{"role":"system","content":"system"},{"role":"user","content":[{"type":"text","text":"prompt"}]},{"role":"assistant","refusal":null,"tool_calls":[{"function":{"arguments":"{\"token\":\"value\"}"}}]}]}`,
			wantIDs: []string{
				"/messages/0/content",
				"/messages/1/content/0/text",
				"/messages/2/tool_calls/0/function/arguments",
			},
			mutable: true,
		},
		{
			name: "OpenAI responses",
			path: "/v1/responses",
			body: `{"instructions":"system","input":[{"type":"message","content":[{"type":"input_text","text":"prompt"}]},{"type":"function_call","arguments":"{}"},{"type":"function_call_output","output":"result"}]}`,
			wantIDs: []string{
				"/instructions",
				"/input/0/content/0/text",
				"/input/1/arguments",
				"/input/2/output",
			},
			mutable: true,
		},
		{
			name:     "Anthropic",
			path:     "/v1/messages",
			provider: "anthropic",
			body:     `{"system":[{"type":"text","text":"system"}],"messages":[{"role":"user","content":[{"type":"text","text":"prompt"}]}]}`,
			wantIDs:  []string{"/system/0/text", "/messages/0/content/0/text"},
			mutable:  true,
		},
		{
			name:     "Gemini",
			path:     "/v1beta/models/gemini:generateContent",
			provider: "gemini",
			body:     `{"systemInstruction":{"parts":[{"text":"system"}]},"contents":[{"role":"user","parts":[{"text":"prompt"}]}]}`,
			wantIDs:  []string{"/systemInstruction/parts/0/text", "/contents/0/parts/0/text"},
			mutable:  true,
		},
		{
			name:     "Ollama chat",
			path:     "/api/chat",
			provider: "ollama",
			body:     `{"messages":[{"role":"user","content":"prompt"}]}`,
			wantIDs:  []string{"/messages/0/content"},
			mutable:  true,
		},
		{
			name:     "Ollama generate",
			path:     "/api/generate",
			provider: "ollama",
			body:     `{"system":"system","prompt":"prompt","suffix":"suffix"}`,
			wantIDs:  []string{"/system", "/prompt", "/suffix"},
			mutable:  true,
		},
		{
			name:     "Bedrock Converse",
			path:     "/model/claude/converse",
			provider: "bedrock",
			body:     `{"system":[{"text":"system"}],"messages":[{"role":"user","content":[{"text":"prompt"}]}]}`,
			wantIDs:  []string{"/system/0/text", "/messages/0/content/0/text"},
			mutable:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc, err := extractCredentialTokenizationDocument(test.path, test.provider, []byte(test.body))
			if err != nil {
				t.Fatalf("extract tokenization document: %v", err)
			}
			ids := make([]string, 0, len(doc.segments))
			for _, segment := range doc.segments {
				ids = append(ids, segment.ID)
			}
			if !reflect.DeepEqual(ids, test.wantIDs) {
				t.Fatalf("segment IDs = %v, want %v", ids, test.wantIDs)
			}
			if doc.mutable != test.mutable {
				t.Fatalf("mutable = %t, want %t", doc.mutable, test.mutable)
			}
		})
	}
}

func TestCredentialTokenizationIncludesToolSchemasAndResults(t *testing.T) {
	body := []byte(`{
		"messages":[
			{"role":"user","content":[
				{"type":"tool_use","input":{"query":"tool input","image":{"data":"tool-visible image field"}}},
				{"type":"tool_result","json":{"answer":"tool result","audio":{"data":"tool-visible audio field"}}}
			]}
		],
		"tools":[{"type":"function","function":{
			"name":"lookup",
			"description":"tool description",
			"parameters":{"type":"object","properties":{"data":{"type":"string","description":"schema description"}}}
		}}]
	}`)
	doc, err := extractCredentialTokenizationDocument("/v1/chat/completions", "openai", body)
	if err != nil {
		t.Fatalf("extract tokenization document: %v", err)
	}

	got := make(map[string]string, len(doc.segments))
	for _, segment := range doc.segments {
		got[segment.ID] = segment.Text
	}
	want := map[string]string{
		"/messages/0/content/0/input/image/data":                   "tool-visible image field",
		"/messages/0/content/0/input/query":                        "tool input",
		"/messages/0/content/1/json/answer":                        "tool result",
		"/messages/0/content/1/json/audio/data":                    "tool-visible audio field",
		"/tools/0/function/description":                            "tool description",
		"/tools/0/function/parameters/properties/data/description": "schema description",
		"/tools/0/function/parameters/properties/data/type":        "string",
		"/tools/0/function/parameters/type":                        "object",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("segments = %#v, want %#v", got, want)
	}
}

func TestCredentialTokenizationSkipsTypedMedia(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		provider string
		body     string
		wantText string
	}{
		{
			name: "OpenAI image and audio",
			path: "/v1/responses",
			body: `{"input":[{"type":"message","role":"user","content":[
				{"type":"input_image","image_url":"data:image/png;base64,excluded-openai-image"},
				{"type":"input_audio","input_audio":{"data":"excluded-openai-audio","format":"wav"}},
				{"type":"input_text","text":"visible OpenAI text"}
			]}]}`,
			wantText: "visible OpenAI text",
		},
		{
			name:     "Anthropic image and base64 document",
			path:     "/v1/messages",
			provider: "anthropic",
			body: `{"messages":[{"role":"user","content":[
				{"type":"image","source":{"type":"base64","media_type":"image/png","data":"excluded-anthropic-image"}},
				{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"excluded-anthropic-document"}},
				{"type":"text","text":"visible Anthropic text"}
			]}]}`,
			wantText: "visible Anthropic text",
		},
		{
			name:     "Gemini inline data",
			path:     "/v1beta/models/gemini:generateContent",
			provider: "gemini",
			body: `{"contents":[{"parts":[
				{"inlineData":{"mimeType":"image/png","data":"excluded-gemini-image"}},
				{"text":"visible Gemini text"}
			]}]}`,
			wantText: "visible Gemini text",
		},
		{
			name:     "Bedrock audio and redacted reasoning",
			path:     "/model/claude/converse",
			provider: "bedrock",
			body: `{"messages":[{"role":"user","content":[
				{"audio":{"format":"wav","source":{"bytes":"excluded-bedrock-audio"}}},
				{"reasoningContent":{"redactedContent":"excluded-bedrock-reasoning"}},
				{"guardContent":{"image":{"format":"png","source":{"bytes":"excluded-bedrock-guard-image"}}}},
				{"text":"visible Bedrock text"}
			]}]}`,
			wantText: "visible Bedrock text",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc, err := extractCredentialTokenizationDocument(test.path, test.provider, []byte(test.body))
			if err != nil {
				t.Fatalf("extract tokenization document: %v", err)
			}
			allText := ""
			for _, segment := range doc.segments {
				allText += segment.Text + "\n"
			}
			if !strings.Contains(allText, test.wantText) {
				t.Fatalf("visible text was not extracted: %q", allText)
			}
			if strings.Contains(allText, "excluded-") {
				t.Fatalf("typed media was extracted: %q", allText)
			}
		})
	}
}

func TestCredentialTokenizationIncludesGeminiFunctionResponse(t *testing.T) {
	body := []byte(`{
		"contents":[{"role":"user","parts":[
			{"functionCall":{"name":"lookup","args":{"query":"call argument"}}},
			{"functionResponse":{"name":"lookup","response":{"answer":"call result","nested":{"detail":"more"}}}},
			{"inlineData":{"mimeType":"image/png","data":"excluded image"}}
		]}]
	}`)
	doc, err := extractCredentialTokenizationDocument(
		"/v1beta/models/gemini:generateContent", "gemini", body,
	)
	if err != nil {
		t.Fatalf("extract tokenization document: %v", err)
	}

	got := make(map[string]string, len(doc.segments))
	for _, segment := range doc.segments {
		got[segment.ID] = segment.Text
	}
	want := map[string]string{
		"/contents/0/parts/0/functionCall/args/query":                 "call argument",
		"/contents/0/parts/1/functionResponse/response/answer":        "call result",
		"/contents/0/parts/1/functionResponse/response/nested/detail": "more",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("segments = %#v, want %#v", got, want)
	}
}

func TestCredentialTokenizationCoversStructuredProviderFields(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		provider string
		body     string
		want     map[string]string
	}{
		{
			name: "OpenAI Responses tools and output schema",
			path: "/v1/responses",
			body: `{
				"input":[
					{"type":"message","role":"user","content":[{"type":"input_text","text":"prompt"}]},
					{"type":"mcp_call","arguments":"mcp arguments","output":"mcp output"},
					{"type":"code_interpreter_call","code":"print(secret)","outputs":[
						{"type":"logs","logs":"code output"},
						{"type":"image","url":"data:image/png;base64,excluded-code-image"}
					]}
				],
				"tools":[{"type":"function","name":"lookup","description":"tool instructions",
					"parameters":{"description":"parameter instructions"}}],
				"text":{"format":{"type":"json_schema","description":"format instructions",
					"schema":{"description":"response instructions"}}}
			}`,
			want: map[string]string{
				"/input/0/content/0/text":         "prompt",
				"/input/1/arguments":              "mcp arguments",
				"/input/1/output":                 "mcp output",
				"/input/2/code":                   "print(secret)",
				"/input/2/outputs/0/logs":         "code output",
				"/tools/0/description":            "tool instructions",
				"/tools/0/parameters/description": "parameter instructions",
				"/text/format/description":        "format instructions",
				"/text/format/schema/description": "response instructions",
			},
		},
		{
			name: "OpenAI Responses prompt variables",
			path: "/v1/responses",
			body: `{"prompt":{"id":"pmpt_test","variables":{
				"plain":"plain variable",
				"customer/id":{"type":"input_text","text":"typed variable"}
			}}}`,
			want: map[string]string{
				"/prompt/variables/customer~1id/text": "typed variable",
				"/prompt/variables/plain":             "plain variable",
			},
		},
		{
			name: "OpenAI custom tool and prediction",
			path: "/v1/chat/completions",
			body: `{
				"messages":[{"role":"assistant","tool_calls":[{"type":"custom","custom":{
					"name":"shell","input":"custom tool input"}}]}],
				"tools":[{"type":"custom","custom":{"name":"shell","description":"custom tool instructions",
					"format":{"type":"grammar","grammar":{"syntax":"lark","definition":"custom grammar"}}}}],
				"prediction":{"type":"content","content":"predicted content"}
			}`,
			want: map[string]string{
				"/messages/0/tool_calls/0/custom/input":     "custom tool input",
				"/tools/0/custom/description":               "custom tool instructions",
				"/tools/0/custom/format/grammar/definition": "custom grammar",
				"/tools/0/custom/format/grammar/syntax":     "lark",
				"/tools/0/custom/format/type":               "grammar",
				"/prediction/content":                       "predicted content",
			},
		},
		{
			name:     "Anthropic document text sources",
			path:     "/v1/messages",
			provider: "anthropic",
			body: `{"messages":[{"role":"user","content":[
				{"type":"document","title":"document title","context":"document context",
					"source":{"type":"text","data":"document body"}},
				{"type":"document","source":{"type":"content","content":[
					{"type":"text","text":"nested document body"}
				]}}
			]}],"tools":[{"name":"lookup","input_schema":{"type":"object"},
				"input_examples":[{"query":"example tool input"}]}]}`,
			want: map[string]string{
				"/messages/0/content/0/title":                 "document title",
				"/messages/0/content/0/context":               "document context",
				"/messages/0/content/0/source/data":           "document body",
				"/messages/0/content/1/source/content/0/text": "nested document body",
				"/tools/0/input_schema/type":                  "object",
				"/tools/0/input_examples/0/query":             "example tool input",
			},
		},
		{
			name:     "Gemini code and schemas",
			path:     "/v1beta/models/gemini:generateContent",
			provider: "gemini",
			body: `{
				"contents":[{"parts":[
					{"executableCode":{"language":"PYTHON","code":"print(secret)"}},
					{"codeExecutionResult":{"outcome":"OUTCOME_OK","output":"secret output"}}
				]}],
				"tools":[{"functionDeclarations":[{"name":"lookup","description":"tool instructions",
					"parametersJsonSchema":{"description":"parameter instructions"},
					"responseJsonSchema":{"description":"response instructions"}}]}],
				"generationConfig":{"responseJsonSchema":{"description":"generation instructions"}}
			}`,
			want: map[string]string{
				"/contents/0/parts/0/executableCode/code":                          "print(secret)",
				"/contents/0/parts/1/codeExecutionResult/output":                   "secret output",
				"/tools/0/functionDeclarations/0/description":                      "tool instructions",
				"/tools/0/functionDeclarations/0/parametersJsonSchema/description": "parameter instructions",
				"/tools/0/functionDeclarations/0/responseJsonSchema/description":   "response instructions",
				"/generationConfig/responseJsonSchema/description":                 "generation instructions",
			},
		},
		{
			name:     "Bedrock text document source",
			path:     "/model/claude/converse",
			provider: "bedrock",
			body: `{"messages":[
				{"role":"user","content":[{"document":{
					"format":"txt","name":"document name","source":{"content":[
						{"text":"first document block"},{"text":"second document block"}
					]}}}]},
				{"role":"user","content":[{"toolResult":{"toolUseId":"tool-1","content":[
					{"json":{"answer":"tool JSON result"}},{"text":"tool text result"}
				]}}]},
				{"role":"assistant","content":[{"reasoningContent":{"reasoningText":{
					"text":"reasoning text","signature":"excluded-reasoning-signature"
				}}}]}
			]}`,
			want: map[string]string{
				"/messages/0/content/0/document/name":                       "document name",
				"/messages/0/content/0/document/source/content/0/text":      "first document block",
				"/messages/0/content/0/document/source/content/1/text":      "second document block",
				"/messages/1/content/0/toolResult/content/0/json/answer":    "tool JSON result",
				"/messages/1/content/0/toolResult/content/1/text":           "tool text result",
				"/messages/2/content/0/reasoningContent/reasoningText/text": "reasoning text",
			},
		},
		{
			name:     "Bedrock managed prompt variables",
			path:     "/model/claude/converse",
			provider: "bedrock",
			body: `{"promptVariables":{
				"account/id":{"text":"account variable"},
				"region":{"text":"region variable"}
			}}`,
			want: map[string]string{
				"/promptVariables/account~1id/text": "account variable",
				"/promptVariables/region/text":      "region variable",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc, err := extractCredentialTokenizationDocument(test.path, test.provider, []byte(test.body))
			if err != nil {
				t.Fatalf("extract tokenization document: %v", err)
			}
			got := make(map[string]string, len(doc.segments))
			for _, segment := range doc.segments {
				got[segment.ID] = segment.Text
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("segments = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestCredentialTokenizationRejectsAmbiguousJSONAndUnknownVariants(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		provider string
		body     string
	}{
		{
			name: "duplicate top-level field",
			path: "/v1/chat/completions",
			body: `{"messages":[],"messages":[{"role":"user","content":"hidden"}]}`,
		},
		{
			name: "escaped duplicate nested field",
			path: "/v1/chat/completions",
			body: `{"messages":[{"content":"first","cont\u0065nt":"second"}]}`,
		},
		{
			name: "unknown OpenAI block",
			path: "/v1/chat/completions",
			body: `{"messages":[{"role":"user","content":[{"type":"new_secret_container","payload":"hidden"}]}]}`,
		},
		{
			name:     "unknown Anthropic block",
			path:     "/v1/messages",
			provider: "anthropic",
			body:     `{"messages":[{"role":"user","content":[{"type":"new_secret_container","payload":"hidden"}]}]}`,
		},
		{
			name:     "unknown Gemini part",
			path:     "/v1beta/models/gemini:generateContent",
			provider: "gemini",
			body:     `{"contents":[{"parts":[{"newSecretContainer":{"payload":"hidden"}}]}]}`,
		},
		{
			name:     "unknown Gemini field beside text",
			path:     "/v1beta/models/gemini:generateContent",
			provider: "gemini",
			body:     `{"contents":[{"parts":[{"text":"safe","newSecretContainer":{"payload":"hidden"}}]}]}`,
		},
		{
			name: "OpenAI image prompt variable",
			path: "/v1/responses",
			body: `{"prompt":{"id":"pmpt_test","variables":{
				"asset":{"type":"input_image","image_url":"data:image/png;base64,hidden"}
			}}}`,
		},
		{
			name: "OpenAI file prompt variable",
			path: "/v1/responses",
			body: `{"prompt":{"id":"pmpt_test","variables":{
				"asset":{"type":"input_file","file_id":"file_hidden"}
			}}}`,
		},
		{
			name: "OpenAI ambiguous text prompt variable",
			path: "/v1/responses",
			body: `{"prompt":{"id":"pmpt_test","variables":{
				"value":{"type":"input_text","text":"visible","extra":"hidden"}
			}}}`,
		},
		{
			name: "OpenAI null text prompt variable",
			path: "/v1/responses",
			body: `{"prompt":{"id":"pmpt_test","variables":{
				"value":{"type":"input_text","text":null}
			}}}`,
		},
		{
			name:     "Bedrock unknown prompt variable union",
			path:     "/model/claude/converse",
			provider: "bedrock",
			body:     `{"promptVariables":{"value":{"document":"hidden"}}}`,
		},
		{
			name:     "Bedrock ambiguous prompt variable union",
			path:     "/model/claude/converse",
			provider: "bedrock",
			body:     `{"promptVariables":{"value":{"text":"visible","document":"hidden"}}}`,
		},
		{
			name:     "Bedrock null prompt variable text",
			path:     "/model/claude/converse",
			provider: "bedrock",
			body:     `{"promptVariables":{"value":{"text":null}}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := extractCredentialTokenizationDocument(test.path, test.provider, []byte(test.body)); err == nil {
				t.Fatal("ambiguous or unknown content was accepted")
			}
		})
	}
}

func TestCredentialTokenizationEndpointCapabilities(t *testing.T) {
	coverage := loadCorpus(t)
	for _, row := range coverage.Positive {
		if !strings.EqualFold(row.Method, http.MethodPost) || len(row.Body) == 0 || bytesIsJSONNull(row.Body) {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			endpoint, err := url.Parse(row.URL)
			if err != nil {
				t.Fatalf("parse endpoint: %v", err)
			}
			provider := inferProviderFromURL(row.URL)
			doc, err := extractCredentialTokenizationDocument(endpoint.Path, provider, row.Body)
			if err != nil {
				t.Fatalf("credential protection does not support %s: %v", row.URL, err)
			}
			if len(doc.segments) == 0 {
				t.Fatalf("credential protection found no model-visible fields for %s", row.URL)
			}
		})
	}

	t.Run("Cohere v2 chat", func(t *testing.T) {
		doc, err := extractCredentialTokenizationDocument(
			"/v2/chat", "cohere",
			[]byte(`{
				"model":"command-r",
				"messages":[{"role":"user","content":"cohere prompt"}],
				"tools":[{"name":"lookup","description":"cohere tool instructions",
					"parameter_definitions":{"query":{"description":"cohere parameter instructions"}}}]
			}`),
		)
		if err != nil {
			t.Fatalf("extract Cohere body: %v", err)
		}
		got := make(map[string]string, len(doc.segments))
		for _, segment := range doc.segments {
			got[segment.ID] = segment.Text
		}
		want := map[string]string{
			"/messages/0/content":                              "cohere prompt",
			"/tools/0/description":                             "cohere tool instructions",
			"/tools/0/parameter_definitions/query/description": "cohere parameter instructions",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("segments = %#v, want %#v", got, want)
		}
	})
}

func TestCallCredentialTokenizerReturnsOnContextDeadline(t *testing.T) {
	release := make(chan struct{})
	tokenizer := &fakeCredentialTokenizer{
		prepare: func(context.Context, CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
			<-release
			return CredentialTokenizationResult{}, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := callCredentialTokenizer(ctx, tokenizer, CredentialTokenizationRequest{})
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("tokenizer call returned after %s", elapsed)
	}
}

func TestCallCredentialTokenizerBoundsHungCalls(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })

	tokenizer := &blockingCredentialTokenizer{release: release}
	callCount := maxConcurrentCredentialTokenizerCalls * 4
	errorsSeen := make(chan error, callCount)
	var calls sync.WaitGroup
	calls.Add(callCount)
	for i := 0; i < callCount; i++ {
		go func() {
			defer calls.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
			defer cancel()
			_, err := callCredentialTokenizer(ctx, tokenizer, CredentialTokenizationRequest{})
			errorsSeen <- err
		}()
	}
	calls.Wait()
	close(errorsSeen)

	for err := range errorsSeen {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want context deadline exceeded", err)
		}
	}
	if started := atomic.LoadInt32(&tokenizer.started); started == 0 || started > maxConcurrentCredentialTokenizerCalls {
		t.Fatalf("started tokenizer calls = %d, want 1..%d", started, maxConcurrentCredentialTokenizerCalls)
	}
	if maxActive := atomic.LoadInt32(&tokenizer.maxActive); maxActive > maxConcurrentCredentialTokenizerCalls {
		t.Fatalf("concurrent tokenizer calls = %d, want at most %d", maxActive, maxConcurrentCredentialTokenizerCalls)
	}

	releaseOnce.Do(func() { close(release) })
	deadline := time.Now().Add(time.Second)
	for len(credentialTokenizerCallSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if slots := len(credentialTokenizerCallSlots); slots != 0 {
		t.Fatalf("credential tokenizer slots still occupied: %d", slots)
	}
}

func TestCredentialTokenizationHungTokenizerFailsClosedAtProxyDeadline(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	proxy.SetCredentialTokenizer(true, &blockingCredentialTokenizer{release: release})
	body := []byte(`{"messages":[{"role":"user","content":"candidate"}]}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	started := time.Now()
	_, block := proxy.protectProxyBody(request, "openai", body)
	if block == nil || block.reason != "credential-protection-failed" {
		t.Fatalf("block = %#v", block)
	}
	if elapsed := time.Since(started); elapsed > credentialTokenizerTimeout+time.Second {
		t.Fatalf("proxy deadline exceeded: %s", elapsed)
	}
	releaseOnce.Do(func() { close(release) })
	deadline := time.Now().Add(time.Second)
	for len(credentialTokenizerCallSlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if slots := len(credentialTokenizerCallSlots); slots != 0 {
		t.Fatalf("credential tokenizer slots still occupied: %d", slots)
	}
}

func TestCredentialTokenizationReadyRewritesBeforeInspectionAndUpstream(t *testing.T) {
	const rawValue = "synthetic-secret-value-for-tokenizer-test"
	provider := &mockProvider{}
	inspector := &credentialCaptureInspector{}
	proxy := newTestProxy(t, provider, inspector, "action")
	tokenizer := &fakeCredentialTokenizer{
		prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
			return readyCredentialResult(request), nil
		},
	}
	proxy.SetCredentialTokenizer(true, tokenizer)

	body := []byte(`{"model":"openai/gpt-4","vendor":{"number":42},"messages":[{"role":"user","content":"` + rawValue + `"}]}`)
	recorder := postChat(t, proxy, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	forwarded := provider.getLastReq()
	if forwarded == nil {
		t.Fatal("upstream was not called")
	}
	if bytes.Contains(forwarded.RawBody, []byte(rawValue)) {
		t.Fatal("raw value reached upstream")
	}
	if len(forwarded.Messages) != 1 || !strings.HasPrefix(forwarded.Messages[0].Content, "<<SGW_SECRET:") {
		t.Fatalf("tokenized handle missing from upstream request: %#v", forwarded.Messages)
	}
	if bytes.Contains([]byte(inspector.allContent()), []byte(rawValue)) {
		t.Fatal("raw value reached the inspector")
	}
	if tokenizer.callCount() != 1 {
		t.Fatalf("tokenizer calls = %d, want 1", tokenizer.callCount())
	}

	var forwardedJSON map[string]any
	if err := json.Unmarshal(forwarded.RawBody, &forwardedJSON); err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	vendor := forwardedJSON["vendor"].(map[string]any)
	if vendor["number"] != float64(42) {
		t.Fatalf("unknown field changed: %#v", forwardedJSON["vendor"])
	}
}

func TestCredentialTokenizationChatRejectsTargetBeforeBroker(t *testing.T) {
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	tokenizer := &fakeCredentialTokenizer{}
	proxy.SetCredentialTokenizer(true, tokenizer)
	body := `{"model":"openai/gpt-4","messages":[{"role":"user","content":"candidate"}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DC-Target-URL", "http://169.254.169.254")
	recorder := httptest.NewRecorder()
	proxy.handleChatCompletion(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	if tokenizer.callCount() != 0 {
		t.Fatalf("rejected chat target reached credential broker %d time(s)", tokenizer.callCount())
	}
}

func TestCredentialTokenizationChatRejectsConfiguredTargetsBeforeBroker(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		wantStatus int
	}{
		{name: "private address", target: "http://169.254.169.254", wantStatus: http.StatusForbidden},
		{name: "non-HTTP scheme", target: "ftp://llm.example.test", wantStatus: http.StatusBadRequest},
		{name: "malformed URL", target: "://bad", wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
			proxy.cfg.LLM.BaseURL = test.target
			tokenizer := &fakeCredentialTokenizer{}
			proxy.SetCredentialTokenizer(true, tokenizer)

			body := []byte(`{"model":"openai/gpt-4","messages":[{"role":"user","content":"candidate"}]}`)
			recorder := postChat(t, proxy, body)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if tokenizer.callCount() != 0 {
				t.Fatalf("rejected configured target reached credential broker %d time(s)", tokenizer.callCount())
			}
		})
	}
}

func TestCredentialTokenizationChatRejectsInstanceBaseBeforeBroker(t *testing.T) {
	setCredentialProviderRegistry(t, &configs.ProvidersConfig{
		Providers: []configs.Provider{{
			Name:             "unsafe-instance",
			BaseProviderType: "openai",
			BaseURL:          "https://user:secret@llm.example.test",
		}},
	})

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	proxy.cfg.LLM.InstanceName = "unsafe-instance"
	tokenizer := &fakeCredentialTokenizer{}
	proxy.SetCredentialTokenizer(true, tokenizer)

	body := []byte(`{"model":"openai/gpt-4","messages":[{"role":"user","content":"candidate"}]}`)
	recorder := postChat(t, proxy, body)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	if tokenizer.callCount() != 0 {
		t.Fatalf("rejected instance target reached credential broker %d time(s)", tokenizer.callCount())
	}
}

func TestCredentialTokenizationChatConfiguredBaseWinsOverInstance(t *testing.T) {
	setCredentialProviderRegistry(t, &configs.ProvidersConfig{
		Providers: []configs.Provider{{
			Name:             "unsafe-instance",
			BaseProviderType: "openai",
			BaseURL:          "https://user:secret@llm.example.test",
		}},
	})

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	proxy.cfg.LLM.BaseURL = "https://203.0.113.10"
	proxy.cfg.LLM.InstanceName = "unsafe-instance"
	tokenizer := &fakeCredentialTokenizer{}
	proxy.SetCredentialTokenizer(true, tokenizer)

	body := []byte(`{"model":"openai/gpt-4","messages":[{"role":"user","content":"candidate"}]}`)
	recorder := postChat(t, proxy, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if tokenizer.callCount() != 1 {
		t.Fatalf("credential broker calls = %d, want 1", tokenizer.callCount())
	}
}

func setCredentialProviderRegistry(t *testing.T, registry *configs.ProvidersConfig) {
	t.Helper()
	providerRegistryMu.Lock()
	previous := providerRegistry
	providerRegistry = registry
	providerRegistryMu.Unlock()
	t.Cleanup(func() {
		providerRegistryMu.Lock()
		providerRegistry = previous
		providerRegistryMu.Unlock()
	})
}

func TestCredentialTokenizationChatUsesHydratedProvider(t *testing.T) {
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	proxy.connector = &hydratingTestConnector{
		upstream: "https://api.anthropic.com",
		apiKey:   "synthetic-test-key",
	}
	tokenizer := &fakeCredentialTokenizer{
		prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
			return CredentialTokenizationResult{
				ProtocolVersion: credentialTokenizerProtocolVersion,
				RequestID:       request.RequestID,
				Outcome:         CredentialTokenizationApprovalRequired,
				BatchID:         "batch_hydrated-chat-provider",
			}, nil
		},
	}
	proxy.SetCredentialTokenizer(true, tokenizer)

	body := `{"model":"openai/not-the-final-provider","messages":[{"role":"user","content":"candidate"}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	proxy.handleChatCompletion(recorder, request)

	brokerRequest, ok := tokenizer.lastRequest()
	if !ok {
		t.Fatal("hydrated chat request did not reach credential broker")
	}
	if brokerRequest.Provider != "anthropic" {
		t.Fatalf("broker provider = %q, want anthropic", brokerRequest.Provider)
	}
	if got := recorder.Header().Get(credentialReasonHeader); got != "secret-enrollment-required" {
		t.Fatalf("reason header = %q, want secret-enrollment-required", got)
	}
}

func TestCredentialTokenizationFailuresNeverCallUpstream(t *testing.T) {
	tests := []struct {
		name        string
		prepare     func(context.Context, CredentialTokenizationRequest) (CredentialTokenizationResult, error)
		wantReason  string
		wantBatchID string
	}{
		{
			name: "approval required",
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{
					ProtocolVersion: credentialTokenizerProtocolVersion,
					RequestID:       request.RequestID,
					Outcome:         CredentialTokenizationApprovalRequired,
					BatchID:         "batch_safe-123",
				}, nil
			},
			wantReason:  "secret-enrollment-required",
			wantBatchID: "batch_safe-123",
		},
		{
			name: "denied",
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{
					ProtocolVersion: credentialTokenizerProtocolVersion,
					RequestID:       request.RequestID,
					Outcome:         CredentialTokenizationDenied,
				}, nil
			},
			wantReason: "secret-enrollment-denied",
		},
		{
			name: "broker error",
			prepare: func(context.Context, CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{}, errors.New("synthetic broker failure")
			},
			wantReason: "credential-protection-failed",
		},
		{
			name: "broker panic",
			prepare: func(context.Context, CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				panic("synthetic panic detail")
			},
			wantReason: "credential-protection-failed",
		},
		{
			name: "malformed ready response",
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{
					ProtocolVersion: credentialTokenizerProtocolVersion,
					RequestID:       request.RequestID,
					Outcome:         CredentialTokenizationReady,
				}, nil
			},
			wantReason: "credential-protocol-error",
		},
		{
			name: "wrong protocol version",
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{
					ProtocolVersion: credentialTokenizerProtocolVersion + 1,
					RequestID:       request.RequestID,
					Outcome:         CredentialTokenizationClean,
				}, nil
			},
			wantReason: "credential-protocol-error",
		},
		{
			name: "wrong request ID",
			prepare: func(context.Context, CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{
					ProtocolVersion: credentialTokenizerProtocolVersion,
					RequestID:       "another-request",
					Outcome:         CredentialTokenizationClean,
				}, nil
			},
			wantReason: "credential-protocol-error",
		},
		{
			name: "clean response includes batch",
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{
					ProtocolVersion: credentialTokenizerProtocolVersion,
					RequestID:       request.RequestID,
					Outcome:         CredentialTokenizationClean,
					BatchID:         "unexpected-batch",
				}, nil
			},
			wantReason: "credential-protocol-error",
		},
		{
			name: "clean response includes segments",
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{
					ProtocolVersion: credentialTokenizerProtocolVersion,
					RequestID:       request.RequestID,
					Outcome:         CredentialTokenizationClean,
					Segments:        request.Segments,
				}, nil
			},
			wantReason: "credential-protocol-error",
		},
		{
			name: "approval response omits batch",
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{
					ProtocolVersion: credentialTokenizerProtocolVersion,
					RequestID:       request.RequestID,
					Outcome:         CredentialTokenizationApprovalRequired,
				}, nil
			},
			wantReason: "credential-protocol-error",
		},
		{
			name: "approval response includes segments",
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{
					ProtocolVersion: credentialTokenizerProtocolVersion,
					RequestID:       request.RequestID,
					Outcome:         CredentialTokenizationApprovalRequired,
					Segments:        request.Segments,
					BatchID:         "batch-1",
				}, nil
			},
			wantReason: "credential-protocol-error",
		},
		{
			name: "denied response includes fields",
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return CredentialTokenizationResult{
					ProtocolVersion: credentialTokenizerProtocolVersion,
					RequestID:       request.RequestID,
					Outcome:         CredentialTokenizationDenied,
					Segments:        request.Segments,
					BatchID:         "unexpected-batch",
				}, nil
			},
			wantReason: "credential-protocol-error",
		},
		{
			name: "ready response includes batch",
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				result := readyCredentialResult(request)
				result.BatchID = "unexpected-batch"
				return result, nil
			},
			wantReason: "credential-protocol-error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &mockProvider{}
			inspector := &credentialCaptureInspector{}
			proxy := newTestProxy(t, provider, inspector, "action")
			proxy.SetCredentialTokenizer(true, &fakeCredentialTokenizer{prepare: test.prepare})

			body := []byte(`{"model":"openai/gpt-4","messages":[{"role":"user","content":"synthetic candidate"}]}`)
			recorder := postChat(t, proxy, body)

			if provider.getLastReq() != nil {
				t.Fatal("blocked credential request reached upstream")
			}
			if inspector.allContent() != "" {
				t.Fatal("blocked credential request reached the inspector")
			}
			if got := recorder.Header().Get(credentialReasonHeader); got != test.wantReason {
				t.Fatalf("reason header = %q, want %q", got, test.wantReason)
			}
			if got := recorder.Header().Get(credentialBatchHeader); got != test.wantBatchID {
				t.Fatalf("batch header = %q, want %q", got, test.wantBatchID)
			}
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), defenseClawBlockBanner) {
				t.Fatalf("block response is not compatible with history laundering: %s", recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "synthetic") {
				t.Fatalf("credential or broker detail leaked in response: %s", recorder.Body.String())
			}
		})
	}
}

func TestCredentialProtectionBlockDoesNotReflectRequestModel(t *testing.T) {
	const rawModel = "openai/model-with-sensitive-request-metadata"
	provider := &mockProvider{}
	proxy := newTestProxy(t, provider, newMockInspector(), "action")
	proxy.SetCredentialTokenizer(true, nil)

	recorder := postChat(t, proxy, []byte(
		`{"model":"`+rawModel+`","messages":[{"role":"user","content":"candidate"}]}`,
	))
	if provider.getLastReq() != nil {
		t.Fatal("blocked request reached upstream")
	}
	if strings.Contains(recorder.Body.String(), rawModel) {
		t.Fatalf("request model was reflected in block response: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), credentialBlockModel) {
		t.Fatalf("sanitized block model is missing: %s", recorder.Body.String())
	}
}

func TestCredentialTokenizationPassthroughRewritesBeforeForwarding(t *testing.T) {
	const rawValue = "synthetic-anthropic-secret"
	var upstreamHits int32
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_test","type":"message","role":"assistant","model":"claude-test","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer upstream.Close()

	registerRawForwardProviderDomain(t, upstream.URL, "anthropic")
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	allowRawForwardPrivateTargets(proxy)
	proxy.SetCredentialTokenizer(true, &fakeCredentialTokenizer{
		prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
			return readyCredentialResult(request), nil
		},
	})

	body := []byte(`{"model":"claude-test","messages":[{"role":"user","content":"` + rawValue + `"}]}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DC-Target-URL", upstream.URL)
	recorder := httptest.NewRecorder()
	proxy.handlePassthrough(recorder, request)

	if got := atomic.LoadInt32(&upstreamHits); got != 1 {
		t.Fatalf("upstream hits = %d, want 1; response=%s", got, recorder.Body.String())
	}
	if bytes.Contains(upstreamBody, []byte(rawValue)) {
		t.Fatal("raw value reached passthrough upstream")
	}
	var parsed struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(upstreamBody, &parsed); err != nil {
		t.Fatalf("decode passthrough body: %v", err)
	}
	if len(parsed.Messages) != 1 || !strings.HasPrefix(parsed.Messages[0].Content, "<<SGW_SECRET:") {
		t.Fatalf("tokenized handle missing from passthrough body: %s", upstreamBody)
	}
}

func TestCredentialTokenizationProtectsManagedPromptVariables(t *testing.T) {
	t.Run("OpenAI Responses variables are rewritten", func(t *testing.T) {
		const rawValue = "synthetic-openai-prompt-variable"
		var upstreamHits int32
		var upstreamBody []byte
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&upstreamHits, 1)
			upstreamBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_test","object":"response","status":"completed"}`))
		}))
		defer upstream.Close()

		registerRawForwardProviderDomain(t, upstream.URL, "openai")
		tokenizer := &fakeCredentialTokenizer{
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return readyCredentialResult(request), nil
			},
		}
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		allowRawForwardPrivateTargets(proxy)
		proxy.SetCredentialTokenizer(true, tokenizer)

		body := []byte(`{"prompt":{"id":"pmpt_test","variables":{"token":"` + rawValue + `"}}}`)
		request := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DC-Target-URL", upstream.URL)
		recorder := httptest.NewRecorder()
		proxy.handlePassthrough(recorder, request)

		if tokenizer.callCount() != 1 {
			t.Fatalf("credential tokenizer calls = %d, want 1", tokenizer.callCount())
		}
		if got := atomic.LoadInt32(&upstreamHits); got != 1 {
			t.Fatalf("upstream hits = %d, want 1; response=%s", got, recorder.Body.String())
		}
		if bytes.Contains(upstreamBody, []byte(rawValue)) {
			t.Fatal("raw prompt variable reached passthrough upstream")
		}
		var forwarded struct {
			Prompt struct {
				Variables map[string]any `json:"variables"`
			} `json:"prompt"`
		}
		if err := json.Unmarshal(upstreamBody, &forwarded); err != nil {
			t.Fatalf("decode passthrough body: %v", err)
		}
		handle, _ := forwarded.Prompt.Variables["token"].(string)
		if !strings.HasPrefix(handle, "<<SGW_SECRET:") {
			t.Fatalf("tokenized handle missing from passthrough body: %s", upstreamBody)
		}
	})

	t.Run("Bedrock variables block signed forwarding", func(t *testing.T) {
		var upstreamHits int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&upstreamHits, 1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer upstream.Close()

		registerRawForwardProviderDomain(t, upstream.URL, "bedrock")
		tokenizer := &fakeCredentialTokenizer{
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return readyCredentialResult(request), nil
			},
		}
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		allowRawForwardPrivateTargets(proxy)
		proxy.SetCredentialTokenizer(true, tokenizer)

		body := []byte(`{"promptVariables":{"token":{"text":"synthetic-bedrock-prompt-variable"}}}`)
		request := httptest.NewRequest(http.MethodPost, "/model/claude/converse", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DC-Target-URL", upstream.URL)
		recorder := httptest.NewRecorder()
		proxy.handlePassthrough(recorder, request)

		if tokenizer.callCount() != 1 {
			t.Fatalf("credential tokenizer calls = %d, want 1", tokenizer.callCount())
		}
		if got := atomic.LoadInt32(&upstreamHits); got != 0 {
			t.Fatalf("signed Bedrock request reached upstream %d time(s)", got)
		}
		if got := recorder.Header().Get(credentialReasonHeader); got != "credential-content-signed" {
			t.Fatalf("reason header = %q, want credential-content-signed", got)
		}
	})
}

func TestCredentialTokenizationPassthroughRejectsBeforeBroker(t *testing.T) {
	tests := []struct {
		name         string
		target       string
		path         string
		body         string
		allowUnknown bool
	}{
		{
			name:   "unknown non-LLM target",
			target: "https://unknown.example.test",
			path:   "/v1/responses",
			body:   `{"instructions":"candidate"}`,
		},
		{
			name:   "unknown LLM target without opt-in",
			target: "https://unknown.example.test",
			path:   "/v1/messages",
			body:   `{"messages":[{"role":"user","content":"candidate"}]}`,
		},
		{
			name:         "private LLM target",
			target:       "http://169.254.169.254",
			path:         "/v1/messages",
			body:         `{"messages":[{"role":"user","content":"candidate"}]}`,
			allowUnknown: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
			proxy.cfg.AllowUnknownLLMDomains = test.allowUnknown
			tokenizer := &fakeCredentialTokenizer{}
			proxy.SetCredentialTokenizer(true, tokenizer)

			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-DC-Target-URL", test.target)
			recorder := httptest.NewRecorder()
			proxy.handlePassthrough(recorder, request)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
			if tokenizer.callCount() != 0 {
				t.Fatalf("rejected target reached credential broker %d time(s)", tokenizer.callCount())
			}
		})
	}
}

func TestCredentialTokenizationPassthroughUsesHydratedProvider(t *testing.T) {
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	proxy.connector = &hydratingTestConnector{
		upstream: "https://api.anthropic.com",
		apiKey:   "synthetic-test-key",
	}
	tokenizer := &fakeCredentialTokenizer{
		prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
			return CredentialTokenizationResult{
				ProtocolVersion: credentialTokenizerProtocolVersion,
				RequestID:       request.RequestID,
				Outcome:         CredentialTokenizationApprovalRequired,
				BatchID:         "batch_hydrated-provider",
			}, nil
		},
	}
	proxy.SetCredentialTokenizer(true, tokenizer)

	body := `{"model":"openai/not-the-final-provider","messages":[{"role":"user","content":"candidate"}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	proxy.handlePassthrough(recorder, request)

	brokerRequest, ok := tokenizer.lastRequest()
	if !ok {
		t.Fatal("hydrated request did not reach credential broker")
	}
	if brokerRequest.Provider != "anthropic" {
		t.Fatalf("broker provider = %q, want anthropic", brokerRequest.Provider)
	}
	if got := recorder.Header().Get(credentialReasonHeader); got != "secret-enrollment-required" {
		t.Fatalf("reason header = %q, want secret-enrollment-required", got)
	}
}

func TestCredentialTokenizationFailsClosedOnLimitsAndUnsupportedBodies(t *testing.T) {
	t.Run("more than 256 segments", func(t *testing.T) {
		messages := make([]map[string]string, maxCredentialSegments+1)
		for i := range messages {
			messages[i] = map[string]string{"role": "user", "content": "value"}
		}
		body := mustJSON(t, map[string]any{"model": "openai/gpt-4", "messages": messages})
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		fake := &fakeCredentialTokenizer{}
		proxy.SetCredentialTokenizer(true, fake)

		_, block := proxy.protectProxyBody(request, "openai", body)
		if block == nil || block.reason != "credential-request-too-large" {
			t.Fatalf("block = %#v", block)
		}
		if fake.callCount() != 0 {
			t.Fatal("over-limit request reached tokenizer")
		}
	})

	t.Run("more than one MiB of text", func(t *testing.T) {
		body := mustJSON(t, map[string]any{
			"model": "openai/gpt-4",
			"messages": []map[string]string{{
				"role": "user", "content": strings.Repeat("x", maxCredentialTextBytes+1),
			}},
		})
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		fake := &fakeCredentialTokenizer{}
		proxy.SetCredentialTokenizer(true, fake)

		_, block := proxy.protectProxyBody(request, "openai", body)
		if block == nil || block.reason != "credential-request-too-large" {
			t.Fatalf("block = %#v", block)
		}
		if fake.callCount() != 0 {
			t.Fatal("over-limit request reached tokenizer")
		}
	})

	t.Run("compressed JSON", func(t *testing.T) {
		body := []byte(`{"model":"openai/gpt-4","messages":[{"role":"user","content":"value"}]}`)
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Content-Encoding", "gzip")
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		fake := &fakeCredentialTokenizer{}
		proxy.SetCredentialTokenizer(true, fake)

		_, block := proxy.protectProxyBody(request, "openai", body)
		if block == nil || block.reason != "credential-content-unsupported" {
			t.Fatalf("block = %#v", block)
		}
		if fake.callCount() != 0 {
			t.Fatal("compressed request reached tokenizer")
		}
	})

	t.Run("signed Bedrock request", func(t *testing.T) {
		body := []byte(`{"messages":[{"role":"user","content":[{"text":"value"}]}]}`)
		request := httptest.NewRequest(http.MethodPost, "/model/claude/converse", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		proxy.SetCredentialTokenizer(true, &fakeCredentialTokenizer{
			prepare: func(_ context.Context, request CredentialTokenizationRequest) (CredentialTokenizationResult, error) {
				return readyCredentialResult(request), nil
			},
		})

		_, block := proxy.protectProxyBody(request, "bedrock", body)
		if block == nil || block.reason != "credential-content-signed" {
			t.Fatalf("block = %#v", block)
		}
	})
}

func TestProxyRejectsBodyPastTenMiBWithoutTruncating(t *testing.T) {
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/chat/completions",
		bytes.NewReader(bytes.Repeat([]byte("x"), maxProxyRequestBodyBytes+1)),
	)
	recorder := httptest.NewRecorder()
	proxy.handleChatCompletion(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestCredentialRequestStreamsUsesProviderPath(t *testing.T) {
	tests := []struct {
		path     string
		bodyFlag bool
		want     bool
	}{
		{path: "/v1/messages", bodyFlag: true, want: true},
		{path: "/v1beta/models/gemini:streamGenerateContent", want: true},
		{path: "/model/claude/converse-stream", want: true},
		{path: "/model/claude/converse", want: false},
	}
	for _, test := range tests {
		if got := credentialRequestStreams(test.path, test.bodyFlag); got != test.want {
			t.Errorf("credentialRequestStreams(%q, %t) = %t, want %t",
				test.path, test.bodyFlag, got, test.want)
		}
	}
}

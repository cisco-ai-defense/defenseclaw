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
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	credentialTokenizerProtocolVersion    = 1
	maxProxyRequestBodyBytes              = 10 * 1024 * 1024
	maxCredentialSegments                 = 256
	maxCredentialTextBytes                = 1 << 20
	maxConcurrentCredentialTokenizerCalls = 8
	credentialTokenizerTimeout            = 2 * time.Second

	credentialReasonHeader = "X-DefenseClaw-Reason"
	credentialBatchHeader  = "X-DefenseClaw-Enrollment-Batch"
	credentialBlockModel   = "credential-protection"
)

var errProxyRequestBodyTooLarge = errors.New("proxy request body exceeds limit")

var credentialTokenizerCallSlots = make(chan struct{}, maxConcurrentCredentialTokenizerCalls)

type CredentialTokenizationOutcome string

const (
	CredentialTokenizationClean            CredentialTokenizationOutcome = "clean"
	CredentialTokenizationReady            CredentialTokenizationOutcome = "ready"
	CredentialTokenizationApprovalRequired CredentialTokenizationOutcome = "approval_required"
	CredentialTokenizationDenied           CredentialTokenizationOutcome = "denied"
)

type CredentialTokenizationSegment struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type CredentialTokenizationRequest struct {
	ProtocolVersion int                             `json:"protocolVersion"`
	RequestID       string                          `json:"requestId"`
	Connector       string                          `json:"connector"`
	Provider        string                          `json:"provider"`
	Path            string                          `json:"path"`
	Segments        []CredentialTokenizationSegment `json:"segments"`
}

type CredentialTokenizationResult struct {
	ProtocolVersion int                             `json:"protocolVersion"`
	RequestID       string                          `json:"requestId"`
	Outcome         CredentialTokenizationOutcome   `json:"outcome"`
	Segments        []CredentialTokenizationSegment `json:"segments,omitempty"`
	BatchID         string                          `json:"batchId,omitempty"`
}

// CredentialTokenizer is the entire privilege surface exposed to the proxy.
// Enrollment decisions and credential execution stay in s-gw.
type CredentialTokenizer interface {
	PrepareProxyTokenization(context.Context, CredentialTokenizationRequest) (CredentialTokenizationResult, error)
}

type credentialProtectionBlock struct {
	reason  string
	message string
	batchID string
}

type tokenizationField struct {
	container      map[string]any
	key            string
	arrayContainer []any
	arrayIndex     int
}

type tokenizationDocument struct {
	root     map[string]any
	segments []CredentialTokenizationSegment
	fields   map[string]tokenizationField
	mutable  bool
	err      error
}

type credentialContentFormat uint8

const (
	credentialContentOpenAI credentialContentFormat = iota
	credentialContentAnthropic
	credentialContentBedrock
	credentialContentGeneric
)

func (p *GuardrailProxy) SetCredentialTokenizer(enabled bool, tokenizer CredentialTokenizer) {
	if p == nil {
		return
	}
	p.credentialTokenizerMu.Lock()
	p.credentialProtectionEnabled = enabled
	p.credentialTokenizer = tokenizer
	p.credentialTokenizerMu.Unlock()
}

func (p *GuardrailProxy) credentialTokenizerSnapshot() (bool, CredentialTokenizer) {
	p.credentialTokenizerMu.RLock()
	defer p.credentialTokenizerMu.RUnlock()
	return p.credentialProtectionEnabled, p.credentialTokenizer
}

func (p *GuardrailProxy) credentialProtectionCoverage() string {
	enabled, tokenizer := p.credentialTokenizerSnapshot()
	if !enabled {
		return "disabled"
	}
	if tokenizer == nil {
		return "unavailable"
	}
	return "proxy_tokenization"
}

func (p *GuardrailProxy) protectProxyBody(r *http.Request, provider string, body []byte) ([]byte, *credentialProtectionBlock) {
	enabled, tokenizer := p.credentialTokenizerSnapshot()
	if !enabled {
		return body, nil
	}
	if tokenizer == nil {
		return nil, credentialBlock("credential-protection-unavailable",
			"Credential protection is unavailable. Start s-gw and retry the request.")
	}

	if !credentialJSONRequest(r) {
		return nil, credentialBlock("credential-content-unsupported",
			"Credential protection cannot safely inspect this request format.")
	}

	doc, err := extractCredentialTokenizationDocument(r.URL.Path, provider, body)
	if err != nil {
		return nil, credentialBlock("credential-content-unsupported",
			"Credential protection cannot safely inspect this request format.")
	}
	if len(doc.segments) == 0 {
		return body, nil
	}
	if err := validateCredentialSegments(doc.segments); err != nil {
		return nil, credentialBlock("credential-request-too-large",
			"Credential protection limits were exceeded. Reduce the request and retry.")
	}
	provider = strings.TrimSpace(provider)
	if provider == "" {
		provider = "unknown"
	}

	requestID := firstNonEmpty(RequestIDFromContext(r.Context()), requestIDFromHeaders(r.Header))
	if requestID == "" {
		requestID = mintRequestID()
	}
	request := CredentialTokenizationRequest{
		ProtocolVersion: credentialTokenizerProtocolVersion,
		RequestID:       requestID,
		Connector:       p.connectorName(),
		Provider:        provider,
		Path:            r.URL.Path,
		Segments:        doc.segments,
	}

	ctx, cancel := context.WithTimeout(r.Context(), credentialTokenizerTimeout)
	defer cancel()
	result, err := callCredentialTokenizer(ctx, tokenizer, request)
	if err != nil || ctx.Err() != nil {
		return nil, credentialBlock("credential-protection-failed",
			"Credential protection failed closed. Check s-gw and retry the request.")
	}
	if result.ProtocolVersion != credentialTokenizerProtocolVersion {
		return nil, credentialProtocolBlock()
	}
	if result.RequestID != request.RequestID {
		return nil, credentialProtocolBlock()
	}

	switch result.Outcome {
	case CredentialTokenizationClean:
		if len(result.Segments) != 0 || result.BatchID != "" {
			return nil, credentialProtocolBlock()
		}
		return body, nil
	case CredentialTokenizationApprovalRequired:
		if len(result.Segments) != 0 {
			return nil, credentialProtocolBlock()
		}
		batchID := safeCredentialBatchID(result.BatchID)
		if batchID == "" || batchID != result.BatchID {
			return nil, credentialProtocolBlock()
		}
		block := credentialBlock("secret-enrollment-required",
			"A credential needs approval in s-gw before this request can be retried.")
		block.batchID = batchID
		return nil, block
	case CredentialTokenizationDenied:
		if len(result.Segments) != 0 || result.BatchID != "" {
			return nil, credentialProtocolBlock()
		}
		return nil, credentialBlock("secret-enrollment-denied",
			"Credential enrollment was denied in s-gw. The request was not sent.")
	case CredentialTokenizationReady:
		if result.BatchID != "" {
			return nil, credentialProtocolBlock()
		}
		if !doc.mutable {
			return nil, credentialBlock("credential-content-signed",
				"Credential protection cannot rewrite this signed provider request.")
		}
		protected, applyErr := applyCredentialTokenization(doc, result.Segments)
		if applyErr != nil {
			return nil, credentialProtocolBlock()
		}
		return protected, nil
	default:
		return nil, credentialProtocolBlock()
	}
}

func callCredentialTokenizer(
	ctx context.Context,
	tokenizer CredentialTokenizer,
	request CredentialTokenizationRequest,
) (CredentialTokenizationResult, error) {
	type callResult struct {
		result CredentialTokenizationResult
		err    error
	}

	select {
	case credentialTokenizerCallSlots <- struct{}{}:
	case <-ctx.Done():
		return CredentialTokenizationResult{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-credentialTokenizerCallSlots
		return CredentialTokenizationResult{}, err
	}

	done := make(chan callResult, 1)
	go func() {
		result := callResult{}
		defer func() {
			if recover() != nil {
				result.result = CredentialTokenizationResult{}
				result.err = errors.New("credential tokenizer panicked")
			}
			<-credentialTokenizerCallSlots
			done <- result
		}()
		result.result, result.err = tokenizer.PrepareProxyTokenization(ctx, request)
	}()

	select {
	case result := <-done:
		return result.result, result.err
	case <-ctx.Done():
		return CredentialTokenizationResult{}, ctx.Err()
	}
}

func credentialJSONRequest(r *http.Request) bool {
	encoding := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		return false
	}
	value := strings.TrimSpace(r.Header.Get("Content-Type"))
	if value == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func readProxyRequestBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxProxyRequestBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProxyRequestBodyBytes {
		return nil, errProxyRequestBodyTooLarge
	}
	return data, nil
}

func credentialBlock(reason, message string) *credentialProtectionBlock {
	return &credentialProtectionBlock{reason: reason, message: message}
}

func credentialProtocolBlock() *credentialProtectionBlock {
	return credentialBlock("credential-protocol-error",
		"Credential protection returned an invalid response. The request was not sent.")
}

func safeCredentialBatchID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, c := range value {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return ""
		}
	}
	return value
}

func (p *GuardrailProxy) writeCredentialProtectionBlock(
	w http.ResponseWriter,
	path, provider, model string,
	stream bool,
	block *credentialProtectionBlock,
) {
	if block == nil {
		return
	}
	w.Header().Set(credentialReasonHeader, block.reason)
	if block.batchID != "" {
		w.Header().Set(credentialBatchHeader, block.batchID)
	}
	message := blockMessage("", "prompt", block.message)
	p.writeBlockedPassthrough(w, path, provider, model, stream, message)
}

func credentialRequestStreams(path string, bodyFlag bool) bool {
	return bodyFlag || strings.HasSuffix(path, ":streamGenerateContent") ||
		strings.HasSuffix(path, "/converse-stream") ||
		strings.HasSuffix(path, "/invoke-with-response-stream")
}

func extractCredentialTokenizationDocument(path, provider string, raw []byte) (*tokenizationDocument, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("multiple JSON values")
	}
	if root == nil {
		return nil, errors.New("request body must be a JSON object")
	}

	doc := &tokenizationDocument{
		root:    root,
		fields:  make(map[string]tokenizationField),
		mutable: true,
	}
	adapter := adapterFor(path, provider)
	if adapter == nil {
		if strings.HasSuffix(path, "/api/generate") {
			doc.addMapString(root, "system", "/system")
			doc.addMapString(root, "prompt", "/prompt")
			doc.addMapString(root, "suffix", "/suffix")
		} else if !doc.addInferredRoot(root) {
			return nil, errors.New("unsupported provider format")
		}
		if doc.err != nil {
			return nil, doc.err
		}
		return doc, nil
	}

	switch adapter.Name() {
	case "openai-chat", "ollama":
		doc.addMessages(root["messages"], "/messages", credentialContentOpenAI)
		doc.addOpenAITools(root["tools"], "/tools")
		doc.addLegacyFunctions(root["functions"], "/functions")
		doc.addOpenAIResponseFormat(root["response_format"], "/response_format")
		doc.addOpenAIPrediction(root["prediction"], "/prediction")
	case "openai-responses":
		doc.addMapString(root, "instructions", "/instructions")
		doc.addOpenAIPrompt(root["prompt"], "/prompt")
		if input, exists := root["input"]; exists && input != nil {
			switch input.(type) {
			case string:
				doc.addMapString(root, "input", "/input")
			case []any:
				doc.addResponsesItems(input, "/input")
			default:
				doc.fail("/input", "must be a string or array")
			}
		}
		doc.addResponsesTools(root["tools"], "/tools")
		doc.addResponsesTextFormat(root["text"], "/text")
		doc.addOpenAIResponseFormat(root["response_format"], "/response_format")
	case "anthropic":
		doc.addContentField(root, "system", "/system", credentialContentAnthropic)
		doc.addMessages(root["messages"], "/messages", credentialContentAnthropic)
		doc.addAnthropicTools(root["tools"], "/tools")
		doc.addAnthropicOutputConfig(root["output_config"], "/output_config")
	case "gemini":
		if system, exists := root["systemInstruction"]; exists && system != nil {
			switch system.(type) {
			case string:
				doc.addMapString(root, "systemInstruction", "/systemInstruction")
			case map[string]any:
				doc.addGeminiContent(system, "/systemInstruction")
			default:
				doc.fail("/systemInstruction", "must be a string or content object")
			}
		}
		doc.addGeminiTurns(root["contents"], "/contents")
		doc.addGeminiTools(root["tools"], "/tools")
		doc.addGeminiGenerationConfig(root["generationConfig"], "/generationConfig")
	case "bedrock-converse":
		doc.mutable = false
		doc.addBlocks(root["system"], "/system", credentialContentBedrock)
		doc.addMessages(root["messages"], "/messages", credentialContentBedrock)
		doc.addBedrockTools(root["toolConfig"], "/toolConfig")
		doc.addBedrockPromptVariables(root["promptVariables"], "/promptVariables")
	default:
		return nil, fmt.Errorf("unsupported adapter %q", adapter.Name())
	}
	if doc.err != nil {
		return nil, doc.err
	}
	return doc, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder, ""); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values")
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			childPath := path + "/" + escapeCredentialPath(key)
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key at %s", childPath)
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder, childPath); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		index := 0
		for decoder.More() {
			childPath := fmt.Sprintf("%s/%d", path, index)
			if err := consumeUniqueJSONValue(decoder, childPath); err != nil {
				return err
			}
			index++
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func (d *tokenizationDocument) fail(path, message string) {
	if d.err != nil {
		return
	}
	d.err = fmt.Errorf("%s: %s", path, message)
}

func (d *tokenizationDocument) addMapString(container map[string]any, key, id string) {
	raw, exists := container[key]
	if !exists {
		return
	}
	if raw == nil {
		return
	}
	value, ok := raw.(string)
	if !ok {
		d.fail(id, "must be a string")
		return
	}
	if value == "" {
		return
	}
	if _, exists := d.fields[id]; exists {
		return
	}
	d.fields[id] = tokenizationField{container: container, key: key}
	d.segments = append(d.segments, CredentialTokenizationSegment{ID: id, Text: value})
}

func (d *tokenizationDocument) addArrayString(container []any, index int, id string) {
	if index < 0 || index >= len(container) {
		return
	}
	value, ok := container[index].(string)
	if !ok || value == "" {
		return
	}
	if _, exists := d.fields[id]; exists {
		return
	}
	d.fields[id] = tokenizationField{arrayContainer: container, arrayIndex: index}
	d.segments = append(d.segments, CredentialTokenizationSegment{ID: id, Text: value})
}

func (d *tokenizationDocument) addContentField(
	container map[string]any,
	key, id string,
	format credentialContentFormat,
) {
	value, ok := container[key]
	if !ok {
		return
	}
	if value == nil {
		return
	}
	switch value.(type) {
	case string:
		d.addMapString(container, key, id)
	case []any:
		d.addBlocks(value, id, format)
	default:
		d.fail(id, "must be a string or content-block array")
	}
}

func (d *tokenizationDocument) addMessages(value any, path string, format credentialContentFormat) {
	if value == nil {
		return
	}
	messages, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range messages {
		message, ok := item.(map[string]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/%d", path, i), "must be an object")
			return
		}
		base := fmt.Sprintf("%s/%d", path, i)
		d.addContentField(message, "content", base+"/content", format)
		d.addMapString(message, "refusal", base+"/refusal")
		d.addToolCallArguments(message["tool_calls"], base+"/tool_calls")
		if functionCall, exists := message["function_call"]; exists && functionCall != nil {
			function, ok := functionCall.(map[string]any)
			if !ok {
				d.fail(base+"/function_call", "must be an object")
				continue
			}
			d.addMapString(function, "arguments", base+"/function_call/arguments")
		}
	}
}

func (d *tokenizationDocument) addBlocks(value any, path string, format credentialContentFormat) {
	if value == nil {
		return
	}
	blocks, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range blocks {
		block, ok := item.(map[string]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/%d", path, i), "must be an object")
			return
		}
		base := fmt.Sprintf("%s/%d", path, i)
		switch format {
		case credentialContentOpenAI:
			d.addOpenAIBlock(block, base)
		case credentialContentAnthropic:
			d.addAnthropicBlock(block, base)
		case credentialContentBedrock:
			d.addBedrockBlock(block, base)
		case credentialContentGeneric:
			d.addGenericBlock(block, base)
		}
	}
}

func (d *tokenizationDocument) addOpenAIBlock(block map[string]any, path string) {
	kindValue, exists := block["type"]
	if !exists {
		d.fail(path, "content block type is required")
		return
	}
	kind, ok := kindValue.(string)
	if !ok || kind == "" {
		d.fail(path+"/type", "must be a non-empty string")
		return
	}

	switch kind {
	case "text", "input_text", "output_text", "reasoning_text", "summary_text":
		d.addMapString(block, "text", path+"/text")
	case "refusal":
		d.addMapString(block, "refusal", path+"/refusal")
	case "image", "image_url", "input_image", "input_audio", "audio", "video",
		"file", "input_file", "computer_screenshot":
		return
	case "tool_use", "server_tool_use", "mcp_tool_use":
		d.addStringLeaves(block["input"], path+"/input")
	case "tool_result", "mcp_tool_result", "computer_tool_result":
		d.addContentField(block, "content", path+"/content", credentialContentGeneric)
		d.addStringLeaves(block["json"], path+"/json")
	case "function_call", "custom_tool_call":
		d.addMapString(block, "arguments", path+"/arguments")
	case "function_call_output", "custom_tool_call_output", "computer_call_output":
		d.addOutputField(block, "output", path+"/output")
	case "reasoning":
		d.addBlocks(block["summary"], path+"/summary", credentialContentOpenAI)
		d.addBlocks(block["content"], path+"/content", credentialContentOpenAI)
		if _, signed := block["encrypted_content"]; signed {
			d.mutable = false
		}
	default:
		d.fail(path+"/type", fmt.Sprintf("unsupported content block type %q", kind))
	}
}

func (d *tokenizationDocument) addAnthropicBlock(block map[string]any, path string) {
	kindValue, exists := block["type"]
	if !exists {
		d.fail(path, "content block type is required")
		return
	}
	kind, ok := kindValue.(string)
	if !ok || kind == "" {
		d.fail(path+"/type", "must be a non-empty string")
		return
	}

	switch kind {
	case "text":
		d.addMapString(block, "text", path+"/text")
	case "image":
		d.validateAnthropicMediaSource(block["source"], path+"/source")
	case "document":
		d.addAnthropicDocument(block, path)
	case "tool_use", "server_tool_use", "mcp_tool_use":
		d.addStringLeaves(block["input"], path+"/input")
	case "tool_result", "mcp_tool_result", "web_search_tool_result", "web_fetch_tool_result",
		"code_execution_tool_result", "bash_code_execution_tool_result", "text_editor_code_execution_tool_result":
		d.addAnthropicResultContent(block, "content", path+"/content")
	case "thinking":
		d.addMapString(block, "thinking", path+"/thinking")
		d.mutable = false
	case "redacted_thinking", "container_upload":
		return
	case "search_result", "web_search_result", "web_fetch_result":
		d.addMapString(block, "source", path+"/source")
		d.addMapString(block, "title", path+"/title")
		d.addAnthropicResultContent(block, "content", path+"/content")
	case "code_execution_result", "bash_code_execution_result", "text_editor_code_execution_result":
		d.addMapString(block, "stdout", path+"/stdout")
		d.addMapString(block, "stderr", path+"/stderr")
		d.addAnthropicResultContent(block, "content", path+"/content")
	case "web_search_tool_result_error", "web_fetch_tool_result_error", "code_execution_tool_result_error",
		"bash_code_execution_tool_result_error", "text_editor_code_execution_tool_result_error":
		d.addMapString(block, "message", path+"/message")
		d.addMapString(block, "error_message", path+"/error_message")
	default:
		d.fail(path+"/type", fmt.Sprintf("unsupported content block type %q", kind))
	}
}

func (d *tokenizationDocument) addAnthropicDocument(block map[string]any, path string) {
	d.addMapString(block, "title", path+"/title")
	d.addMapString(block, "context", path+"/context")

	rawSource, exists := block["source"]
	if !exists {
		d.fail(path+"/source", "is required")
		return
	}
	source, ok := rawSource.(map[string]any)
	if !ok {
		d.fail(path+"/source", "must be an object")
		return
	}
	kind, ok := source["type"].(string)
	if !ok || kind == "" {
		d.fail(path+"/source/type", "must be a non-empty string")
		return
	}
	switch kind {
	case "text":
		d.addMapString(source, "data", path+"/source/data")
	case "content":
		d.addAnthropicResultContent(source, "content", path+"/source/content")
	case "base64", "url", "file":
		return
	default:
		d.fail(path+"/source/type", fmt.Sprintf("unsupported document source type %q", kind))
	}
}

func (d *tokenizationDocument) validateAnthropicMediaSource(value any, path string) {
	source, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	kind, ok := source["type"].(string)
	if !ok || kind == "" {
		d.fail(path+"/type", "must be a non-empty string")
		return
	}
	if kind != "base64" && kind != "url" && kind != "file" {
		d.fail(path+"/type", fmt.Sprintf("unsupported media source type %q", kind))
	}
}

func (d *tokenizationDocument) addAnthropicResultContent(container map[string]any, key, path string) {
	value, exists := container[key]
	if !exists || value == nil {
		return
	}
	switch value.(type) {
	case string:
		d.addMapString(container, key, path)
	case []any:
		d.addBlocks(value, path, credentialContentAnthropic)
	case map[string]any:
		d.addStringLeaves(value, path)
	default:
		d.fail(path, "must be a string, object, or content-block array")
	}
}

func (d *tokenizationDocument) addBedrockBlock(block map[string]any, path string) {
	if len(block) != 1 {
		d.fail(path, "content block must contain one variant")
		return
	}
	variant := ""
	for _, key := range []string{
		"text", "audio", "image", "video", "document", "json", "searchResult",
		"toolUse", "toolResult", "guardContent", "reasoningContent", "cachePoint", "citationsContent",
	} {
		if _, exists := block[key]; !exists {
			continue
		}
		if variant != "" {
			d.fail(path, "content block has multiple variants")
			return
		}
		variant = key
	}

	switch variant {
	case "text":
		d.addMapString(block, "text", path+"/text")
	case "audio", "image", "video", "cachePoint":
		return
	case "document":
		document, ok := block["document"].(map[string]any)
		if !ok {
			d.fail(path+"/document", "must be an object")
			return
		}
		d.addMapString(document, "name", path+"/document/name")
		d.addBedrockDocumentSource(document["source"], path+"/document/source")
	case "json":
		d.addStringLeaves(block["json"], path+"/json")
	case "searchResult":
		d.addBedrockSearchResult(block["searchResult"], path+"/searchResult")
	case "toolUse":
		toolUse, ok := block["toolUse"].(map[string]any)
		if !ok {
			d.fail(path+"/toolUse", "must be an object")
			return
		}
		d.addStringLeaves(toolUse["input"], path+"/toolUse/input")
	case "toolResult":
		result, ok := block["toolResult"].(map[string]any)
		if !ok {
			d.fail(path+"/toolResult", "must be an object")
			return
		}
		d.addBlocks(result["content"], path+"/toolResult/content", credentialContentBedrock)
	case "guardContent":
		d.addBedrockGuardContent(block["guardContent"], path+"/guardContent")
	case "reasoningContent":
		d.addBedrockReasoningContent(block["reasoningContent"], path+"/reasoningContent")
	case "citationsContent":
		d.addStringLeaves(block["citationsContent"], path+"/citationsContent")
	case "":
		d.fail(path, "unsupported content block variant")
	}
}

func (d *tokenizationDocument) addBedrockGuardContent(value any, path string) {
	content, ok := value.(map[string]any)
	if !ok || len(content) != 1 {
		d.fail(path, "must contain one guard content variant")
		return
	}
	if _, image := content["image"]; image {
		return
	}
	textBlock, ok := content["text"].(map[string]any)
	if !ok {
		d.fail(path, "unsupported guard content variant")
		return
	}
	d.addMapString(textBlock, "text", path+"/text/text")
}

func (d *tokenizationDocument) addBedrockReasoningContent(value any, path string) {
	content, ok := value.(map[string]any)
	if !ok || len(content) != 1 {
		d.fail(path, "must contain one reasoning content variant")
		return
	}
	if _, redacted := content["redactedContent"]; redacted {
		return
	}
	reasoningText, ok := content["reasoningText"].(map[string]any)
	if !ok {
		d.fail(path, "unsupported reasoning content variant")
		return
	}
	d.addMapString(reasoningText, "text", path+"/reasoningText/text")
}

func (d *tokenizationDocument) addBedrockSearchResult(value any, path string) {
	result, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	d.addMapString(result, "source", path+"/source")
	d.addMapString(result, "title", path+"/title")
	content, ok := result["content"].([]any)
	if !ok {
		d.fail(path+"/content", "must be an array")
		return
	}
	for i, rawBlock := range content {
		base := fmt.Sprintf("%s/content/%d", path, i)
		block, ok := rawBlock.(map[string]any)
		if !ok || len(block) != 1 {
			d.fail(base, "must contain one search result variant")
			return
		}
		if _, exists := block["text"]; !exists {
			d.fail(base, "unsupported search result content variant")
			continue
		}
		d.addMapString(block, "text", base+"/text")
	}
}

func (d *tokenizationDocument) addBedrockDocumentSource(value any, path string) {
	source, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	variant := ""
	for _, key := range []string{"bytes", "content", "s3Location", "text"} {
		if _, exists := source[key]; !exists {
			continue
		}
		if variant != "" {
			d.fail(path, "document source has multiple variants")
			return
		}
		variant = key
	}
	switch variant {
	case "bytes", "s3Location":
		return
	case "text":
		d.addMapString(source, "text", path+"/text")
	case "content":
		d.addBedrockDocumentContent(source["content"], path+"/content")
	case "":
		d.fail(path, "unsupported document source variant")
	}
}

func (d *tokenizationDocument) addBedrockDocumentContent(value any, path string) {
	blocks, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, rawBlock := range blocks {
		base := fmt.Sprintf("%s/%d", path, i)
		block, ok := rawBlock.(map[string]any)
		if !ok {
			d.fail(base, "must be an object")
			return
		}
		if len(block) != 1 {
			d.fail(base, "document content must contain one variant")
			continue
		}
		if _, exists := block["text"]; !exists {
			d.fail(base, "unsupported document content variant")
			continue
		}
		d.addMapString(block, "text", base+"/text")
	}
}

func (d *tokenizationDocument) addGenericBlock(block map[string]any, path string) {
	if _, hasType := block["type"]; hasType {
		kind, _ := block["type"].(string)
		switch kind {
		case "document", "thinking", "redacted_thinking", "search_result", "web_search_result",
			"web_fetch_result", "web_search_tool_result", "web_fetch_tool_result",
			"code_execution_tool_result", "bash_code_execution_tool_result",
			"text_editor_code_execution_tool_result", "code_execution_result",
			"bash_code_execution_result", "text_editor_code_execution_result", "container_upload",
			"web_search_tool_result_error", "web_fetch_tool_result_error",
			"code_execution_tool_result_error", "bash_code_execution_tool_result_error",
			"text_editor_code_execution_tool_result_error":
			d.addAnthropicBlock(block, path)
		default:
			d.addOpenAIBlock(block, path)
		}
		return
	}
	d.addBedrockBlock(block, path)
}

func (d *tokenizationDocument) addToolCallArguments(value any, path string) {
	if value == nil {
		return
	}
	calls, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range calls {
		call, ok := item.(map[string]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/%d", path, i), "must be an object")
			return
		}
		base := fmt.Sprintf("%s/%d", path, i)
		kind, _ := call["type"].(string)
		if kind == "" {
			if _, exists := call["custom"]; exists {
				kind = "custom"
			} else {
				kind = "function"
			}
		}
		switch kind {
		case "function":
			function, ok := call["function"].(map[string]any)
			if !ok {
				d.fail(base+"/function", "must be an object")
				continue
			}
			d.addMapString(function, "arguments", base+"/function/arguments")
		case "custom":
			custom, ok := call["custom"].(map[string]any)
			if !ok {
				d.fail(base+"/custom", "must be an object")
				continue
			}
			d.addMapString(custom, "input", base+"/custom/input")
		default:
			d.fail(base+"/type", fmt.Sprintf("unsupported tool call type %q", kind))
		}
	}
}

func (d *tokenizationDocument) addResponsesItems(value any, path string) {
	if value == nil {
		return
	}
	items, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range items {
		base := fmt.Sprintf("%s/%d", path, i)
		if _, ok := item.(string); ok {
			d.addArrayString(items, i, base)
			continue
		}
		entry, ok := item.(map[string]any)
		if !ok {
			d.fail(base, "must be a string or object")
			return
		}
		kind, _ := entry["type"].(string)
		if kind == "" {
			if _, hasRole := entry["role"]; hasRole {
				kind = "message"
			} else {
				d.fail(base+"/type", "is required")
				continue
			}
		}
		switch kind {
		case "message":
			d.addContentField(entry, "content", base+"/content", credentialContentOpenAI)
		case "function_call":
			d.addMapString(entry, "arguments", base+"/arguments")
		case "custom_tool_call":
			d.addMapString(entry, "input", base+"/input")
		case "function_call_output", "custom_tool_call_output", "computer_call_output",
			"local_shell_call_output", "shell_call_output", "apply_patch_call_output", "mcp_call_output":
			d.addOutputField(entry, "output", base+"/output")
		case "reasoning":
			d.addBlocks(entry["summary"], base+"/summary", credentialContentOpenAI)
			d.addBlocks(entry["content"], base+"/content", credentialContentOpenAI)
			if _, signed := entry["encrypted_content"]; signed {
				d.mutable = false
			}
		case "computer_call", "local_shell_call", "shell_call", "apply_patch_call":
			d.addStringLeaves(entry["action"], base+"/action")
		case "mcp_call":
			d.addMapString(entry, "arguments", base+"/arguments")
			d.addOutputField(entry, "output", base+"/output")
		case "mcp_approval_request", "mcp_approval_response":
			d.addMapString(entry, "arguments", base+"/arguments")
			d.addMapString(entry, "reason", base+"/reason")
		case "file_search_call":
			d.addStringLeaves(entry["queries"], base+"/queries")
			d.addStringLeaves(entry["results"], base+"/results")
		case "web_search_call":
			d.addStringLeaves(entry["action"], base+"/action")
		case "code_interpreter_call":
			d.addMapString(entry, "code", base+"/code")
			d.addCodeInterpreterOutputs(entry["outputs"], base+"/outputs")
		case "image_generation_call":
			d.addMapString(entry, "prompt", base+"/prompt")
		case "program":
			d.addMapString(entry, "program", base+"/program")
			d.addMapString(entry, "input", base+"/input")
		case "program_output":
			d.addOutputField(entry, "output", base+"/output")
		case "item_reference":
			continue
		default:
			d.fail(base+"/type", fmt.Sprintf("unsupported response item type %q", kind))
		}
	}
}

func (d *tokenizationDocument) addCodeInterpreterOutputs(value any, path string) {
	if value == nil {
		return
	}
	outputs, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, rawOutput := range outputs {
		base := fmt.Sprintf("%s/%d", path, i)
		output, ok := rawOutput.(map[string]any)
		if !ok {
			d.fail(base, "must be an object")
			return
		}
		kind, _ := output["type"].(string)
		switch kind {
		case "logs":
			d.addMapString(output, "logs", base+"/logs")
		case "image":
			continue
		default:
			d.fail(base+"/type", fmt.Sprintf("unsupported code interpreter output type %q", kind))
		}
	}
}

func (d *tokenizationDocument) addOutputField(container map[string]any, key, path string) {
	value, exists := container[key]
	if !exists || value == nil {
		return
	}
	switch value.(type) {
	case string:
		d.addMapString(container, key, path)
	case []any:
		d.addBlocks(value, path, credentialContentGeneric)
	case map[string]any:
		d.addStringLeaves(value, path)
	default:
		d.fail(path, "must be a string, object, or content-block array")
	}
}

func (d *tokenizationDocument) addGeminiContent(value any, path string) {
	if value == nil {
		return
	}
	content, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	d.addGeminiParts(content["parts"], path+"/parts")
}

func (d *tokenizationDocument) addGeminiTurns(value any, path string) {
	if value == nil {
		return
	}
	turns, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range turns {
		turn, ok := item.(map[string]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/%d", path, i), "must be an object")
			return
		}
		d.addGeminiParts(turn["parts"], fmt.Sprintf("%s/%d/parts", path, i))
	}
}

func (d *tokenizationDocument) addGeminiParts(value any, path string) {
	if value == nil {
		return
	}
	parts, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, rawPart := range parts {
		base := fmt.Sprintf("%s/%d", path, i)
		part, ok := rawPart.(map[string]any)
		if !ok {
			d.fail(base, "must be an object")
			return
		}
		allowedKeys := map[string]bool{
			"text": true, "functionCall": true, "functionResponse": true,
			"executableCode": true, "codeExecutionResult": true,
			"inlineData": true, "fileData": true, "videoMetadata": true,
			"thought": true, "thoughtSignature": true, "mediaResolution": true,
		}
		for key := range part {
			if !allowedKeys[key] {
				d.fail(base+"/"+escapeCredentialPath(key), "unsupported Gemini part field")
				return
			}
		}
		handled := false
		if _, exists := part["text"]; exists {
			d.addMapString(part, "text", base+"/text")
			handled = true
		}
		if rawCall, exists := part["functionCall"]; exists {
			call, ok := rawCall.(map[string]any)
			if !ok {
				d.fail(base+"/functionCall", "must be an object")
				continue
			}
			d.addStringLeaves(call["args"], base+"/functionCall/args")
			handled = true
		}
		if rawResponse, exists := part["functionResponse"]; exists {
			response, ok := rawResponse.(map[string]any)
			if !ok {
				d.fail(base+"/functionResponse", "must be an object")
				continue
			}
			d.addStringLeaves(response["response"], base+"/functionResponse/response")
			handled = true
		}
		if rawCode, exists := part["executableCode"]; exists {
			code, ok := rawCode.(map[string]any)
			if !ok {
				d.fail(base+"/executableCode", "must be an object")
				continue
			}
			d.addMapString(code, "code", base+"/executableCode/code")
			handled = true
		}
		if rawResult, exists := part["codeExecutionResult"]; exists {
			result, ok := rawResult.(map[string]any)
			if !ok {
				d.fail(base+"/codeExecutionResult", "must be an object")
				continue
			}
			d.addMapString(result, "output", base+"/codeExecutionResult/output")
			handled = true
		}
		for _, mediaKey := range []string{"inlineData", "fileData"} {
			if media, exists := part[mediaKey]; exists {
				if _, ok := media.(map[string]any); !ok {
					d.fail(base+"/"+mediaKey, "must be an object")
				}
				handled = true
			}
		}
		if _, exists := part["thoughtSignature"]; exists {
			handled = true
		}
		if !handled {
			d.fail(base, "unsupported Gemini part variant")
		}
	}
}

func (d *tokenizationDocument) addOpenAITools(value any, path string) {
	if value == nil {
		return
	}
	tools, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range tools {
		tool, ok := item.(map[string]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/%d", path, i), "must be an object")
			return
		}
		base := fmt.Sprintf("%s/%d", path, i)
		d.addMapString(tool, "description", base+"/description")
		kind, _ := tool["type"].(string)
		rawFunction, exists := tool["function"]
		if exists && rawFunction != nil {
			function, ok := rawFunction.(map[string]any)
			if !ok {
				d.fail(base+"/function", "must be an object")
				continue
			}
			d.addMapString(function, "description", base+"/function/description")
			d.addSchemaStringLeaves(function["parameters"], base+"/function/parameters")
		} else if kind == "function" {
			d.fail(base+"/function", "is required")
		}
		if rawCustom, exists := tool["custom"]; exists && rawCustom != nil {
			custom, ok := rawCustom.(map[string]any)
			if !ok {
				d.fail(base+"/custom", "must be an object")
				continue
			}
			d.addMapString(custom, "description", base+"/custom/description")
			d.addSchemaStringLeaves(custom["format"], base+"/custom/format")
		} else if kind == "custom" {
			d.fail(base+"/custom", "is required")
		}
		if kind == "" && rawFunction == nil && tool["custom"] == nil {
			d.fail(base+"/type", "is required")
		}
		if kind != "" && kind != "function" && kind != "custom" {
			d.fail(base+"/type", fmt.Sprintf("unsupported tool type %q", kind))
		}
	}
}

func (d *tokenizationDocument) addOpenAIPrompt(value any, path string) {
	if value == nil {
		return
	}
	prompt, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	rawVariables, exists := prompt["variables"]
	if !exists || rawVariables == nil {
		return
	}
	variables, ok := rawVariables.(map[string]any)
	if !ok {
		d.fail(path+"/variables", "must be an object")
		return
	}

	keys := make([]string, 0, len(variables))
	for key := range variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		base := path + "/variables/" + escapeCredentialPath(key)
		switch variable := variables[key].(type) {
		case string:
			d.addMapString(variables, key, base)
		case map[string]any:
			if len(variable) != 2 {
				d.fail(base, "must be a string or input_text object")
				return
			}
			kind, ok := variable["type"].(string)
			if !ok || kind != "input_text" {
				d.fail(base+"/type", "must be input_text")
				return
			}
			if _, ok := variable["text"].(string); !ok {
				d.fail(base+"/text", "must be a string")
				return
			}
			d.addMapString(variable, "text", base+"/text")
		default:
			d.fail(base, "must be a string or input_text object")
			return
		}
	}
}

func (d *tokenizationDocument) addResponsesTools(value any, path string) {
	if value == nil {
		return
	}
	tools, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range tools {
		base := fmt.Sprintf("%s/%d", path, i)
		tool, ok := item.(map[string]any)
		if !ok {
			d.fail(base, "must be an object")
			return
		}
		d.addMapString(tool, "description", base+"/description")
		d.addMapString(tool, "server_description", base+"/server_description")
		d.addSchemaStringLeaves(tool["parameters"], base+"/parameters")
		d.addSchemaStringLeaves(tool["format"], base+"/format")
		if rawFunction, exists := tool["function"]; exists && rawFunction != nil {
			function, ok := rawFunction.(map[string]any)
			if !ok {
				d.fail(base+"/function", "must be an object")
				continue
			}
			d.addMapString(function, "description", base+"/function/description")
			d.addSchemaStringLeaves(function["parameters"], base+"/function/parameters")
		}
	}
}

func (d *tokenizationDocument) addLegacyFunctions(value any, path string) {
	if value == nil {
		return
	}
	functions, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range functions {
		function, ok := item.(map[string]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/%d", path, i), "must be an object")
			return
		}
		base := fmt.Sprintf("%s/%d", path, i)
		d.addMapString(function, "description", base+"/description")
		d.addSchemaStringLeaves(function["parameters"], base+"/parameters")
	}
}

func (d *tokenizationDocument) addAnthropicTools(value any, path string) {
	if value == nil {
		return
	}
	tools, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range tools {
		tool, ok := item.(map[string]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/%d", path, i), "must be an object")
			return
		}
		base := fmt.Sprintf("%s/%d", path, i)
		d.addMapString(tool, "description", base+"/description")
		d.addSchemaStringLeaves(tool["input_schema"], base+"/input_schema")
		d.addStringLeaves(tool["input_examples"], base+"/input_examples")
	}
}

func (d *tokenizationDocument) addGeminiTools(value any, path string) {
	if value == nil {
		return
	}
	tools, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range tools {
		tool, ok := item.(map[string]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/%d", path, i), "must be an object")
			return
		}
		rawDeclarations, exists := tool["functionDeclarations"]
		if !exists || rawDeclarations == nil {
			continue
		}
		declarations, ok := rawDeclarations.([]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/%d/functionDeclarations", path, i), "must be an array")
			continue
		}
		for j, rawDeclaration := range declarations {
			declaration, ok := rawDeclaration.(map[string]any)
			if !ok {
				d.fail(fmt.Sprintf("%s/%d/functionDeclarations/%d", path, i, j), "must be an object")
				continue
			}
			base := fmt.Sprintf("%s/%d/functionDeclarations/%d", path, i, j)
			d.addMapString(declaration, "description", base+"/description")
			d.addSchemaStringLeaves(declaration["parameters"], base+"/parameters")
			d.addSchemaStringLeaves(declaration["parametersJsonSchema"], base+"/parametersJsonSchema")
			d.addSchemaStringLeaves(declaration["response"], base+"/response")
			d.addSchemaStringLeaves(declaration["responseJsonSchema"], base+"/responseJsonSchema")
		}
	}
}

func (d *tokenizationDocument) addBedrockTools(value any, path string) {
	if value == nil {
		return
	}
	config, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	rawTools, exists := config["tools"]
	if !exists || rawTools == nil {
		return
	}
	tools, ok := rawTools.([]any)
	if !ok {
		d.fail(path+"/tools", "must be an array")
		return
	}
	for i, item := range tools {
		tool, ok := item.(map[string]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/tools/%d", path, i), "must be an object")
			return
		}
		spec, ok := tool["toolSpec"].(map[string]any)
		if !ok {
			d.fail(fmt.Sprintf("%s/tools/%d/toolSpec", path, i), "must be an object")
			continue
		}
		base := fmt.Sprintf("%s/tools/%d/toolSpec", path, i)
		d.addMapString(spec, "description", base+"/description")
		d.addSchemaStringLeaves(spec["inputSchema"], base+"/inputSchema")
	}
}

func (d *tokenizationDocument) addBedrockPromptVariables(value any, path string) {
	if value == nil {
		return
	}
	variables, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}

	keys := make([]string, 0, len(variables))
	for key := range variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		base := path + "/" + escapeCredentialPath(key)
		variable, ok := variables[key].(map[string]any)
		if !ok || len(variable) != 1 {
			d.fail(base, "must contain exactly one text field")
			return
		}
		if _, ok := variable["text"].(string); !ok {
			d.fail(base+"/text", "must be a string")
			return
		}
		d.addMapString(variable, "text", base+"/text")
	}
}

func (d *tokenizationDocument) addOpenAIResponseFormat(value any, path string) {
	if value == nil {
		return
	}
	format, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	d.addMapString(format, "description", path+"/description")
	d.addSchemaStringLeaves(format["json_schema"], path+"/json_schema")
	d.addSchemaStringLeaves(format["schema"], path+"/schema")
}

func (d *tokenizationDocument) addOpenAIPrediction(value any, path string) {
	if value == nil {
		return
	}
	prediction, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	d.addContentField(prediction, "content", path+"/content", credentialContentOpenAI)
}

func (d *tokenizationDocument) addResponsesTextFormat(value any, path string) {
	if value == nil {
		return
	}
	textConfig, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	d.addOpenAIResponseFormat(textConfig["format"], path+"/format")
}

func (d *tokenizationDocument) addAnthropicOutputConfig(value any, path string) {
	if value == nil {
		return
	}
	config, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	format, exists := config["format"]
	if !exists || format == nil {
		return
	}
	if _, ok := format.(map[string]any); !ok {
		d.fail(path+"/format", "must be an object")
		return
	}
	d.addSchemaStringLeaves(format, path+"/format")
}

func (d *tokenizationDocument) addGeminiGenerationConfig(value any, path string) {
	if value == nil {
		return
	}
	config, ok := value.(map[string]any)
	if !ok {
		d.fail(path, "must be an object")
		return
	}
	d.addSchemaStringLeaves(config["responseSchema"], path+"/responseSchema")
	d.addSchemaStringLeaves(config["responseJsonSchema"], path+"/responseJsonSchema")
	if rawFormat, exists := config["responseFormat"]; exists && rawFormat != nil {
		format, ok := rawFormat.(map[string]any)
		if !ok {
			d.fail(path+"/responseFormat", "must be an object")
			return
		}
		d.addSchemaStringLeaves(format["schema"], path+"/responseFormat/schema")
	}
}

func (d *tokenizationDocument) addInferredRoot(root map[string]any) bool {
	matched := false
	if value, exists := root["messages"]; exists {
		d.addMessages(value, "/messages", credentialContentGeneric)
		d.addGenericTools(root["tools"], "/tools")
		d.addLegacyFunctions(root["functions"], "/functions")
		d.addOpenAIResponseFormat(root["response_format"], "/response_format")
		d.addOpenAIPrediction(root["prediction"], "/prediction")
		matched = true
	}
	if value, exists := root["contents"]; exists {
		d.addGeminiTurns(value, "/contents")
		d.addGeminiTools(root["tools"], "/tools")
		d.addGeminiGenerationConfig(root["generationConfig"], "/generationConfig")
		matched = true
	}
	if value, exists := root["input"]; exists {
		switch value.(type) {
		case string:
			d.addMapString(root, "input", "/input")
		case []any:
			d.addResponsesItems(value, "/input")
		default:
			d.fail("/input", "must be a string or array")
		}
		d.addMapString(root, "instructions", "/instructions")
		d.addResponsesTools(root["tools"], "/tools")
		d.addResponsesTextFormat(root["text"], "/text")
		matched = true
	}
	if _, exists := root["system"]; exists {
		d.addContentField(root, "system", "/system", credentialContentGeneric)
		matched = true
	}
	for _, key := range []string{"prompt", "suffix", "preamble", "message"} {
		if _, exists := root[key]; !exists {
			continue
		}
		d.addMapString(root, key, "/"+key)
		matched = true
	}
	if value, exists := root["inputs"]; exists {
		d.addStringLeaves(value, "/inputs")
		matched = true
	}
	return matched
}

func (d *tokenizationDocument) addGenericTools(value any, path string) {
	if value == nil {
		return
	}
	tools, ok := value.([]any)
	if !ok {
		d.fail(path, "must be an array")
		return
	}
	for i, item := range tools {
		base := fmt.Sprintf("%s/%d", path, i)
		tool, ok := item.(map[string]any)
		if !ok {
			d.fail(base, "must be an object")
			return
		}
		d.addMapString(tool, "description", base+"/description")
		d.addSchemaStringLeaves(tool["input_schema"], base+"/input_schema")
		d.addStringLeaves(tool["input_examples"], base+"/input_examples")
		d.addSchemaStringLeaves(tool["parameters"], base+"/parameters")
		d.addSchemaStringLeaves(tool["parameter_definitions"], base+"/parameter_definitions")
		d.addSchemaStringLeaves(tool["format"], base+"/format")
		if rawFunction, exists := tool["function"]; exists && rawFunction != nil {
			function, ok := rawFunction.(map[string]any)
			if !ok {
				d.fail(base+"/function", "must be an object")
				continue
			}
			d.addMapString(function, "description", base+"/function/description")
			d.addSchemaStringLeaves(function["parameters"], base+"/function/parameters")
		}
		if rawCustom, exists := tool["custom"]; exists && rawCustom != nil {
			custom, ok := rawCustom.(map[string]any)
			if !ok {
				d.fail(base+"/custom", "must be an object")
				continue
			}
			d.addMapString(custom, "description", base+"/custom/description")
			d.addSchemaStringLeaves(custom["format"], base+"/custom/format")
		}
	}
}

func (d *tokenizationDocument) addStringLeaves(value any, path string) {
	d.addStringLeavesRecursive(value, path)
}

func (d *tokenizationDocument) addSchemaStringLeaves(value any, path string) {
	d.addStringLeavesRecursive(value, path)
}

func (d *tokenizationDocument) addStringLeavesRecursive(value any, path string) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			childPath := path + "/" + escapeCredentialPath(key)
			if _, ok := typed[key].(string); ok {
				d.addMapString(typed, key, childPath)
				continue
			}
			d.addStringLeavesRecursive(typed[key], childPath)
		}
	case []any:
		for i, child := range typed {
			childPath := fmt.Sprintf("%s/%d", path, i)
			if _, ok := child.(string); ok {
				d.addArrayString(typed, i, childPath)
				continue
			}
			d.addStringLeavesRecursive(child, childPath)
		}
	}
}

func escapeCredentialPath(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

func validateCredentialSegments(segments []CredentialTokenizationSegment) error {
	if len(segments) > maxCredentialSegments {
		return errors.New("too many segments")
	}
	total := 0
	for _, segment := range segments {
		total += len(segment.Text)
		if total > maxCredentialTextBytes {
			return errors.New("segment text is too large")
		}
	}
	return nil
}

func applyCredentialTokenization(doc *tokenizationDocument, replacements []CredentialTokenizationSegment) ([]byte, error) {
	if len(replacements) != len(doc.segments) {
		return nil, errors.New("replacement count mismatch")
	}
	if err := validateCredentialSegments(replacements); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(replacements))
	for _, replacement := range replacements {
		field, ok := doc.fields[replacement.ID]
		if !ok {
			return nil, errors.New("unknown replacement field")
		}
		if _, duplicate := seen[replacement.ID]; duplicate {
			return nil, errors.New("duplicate replacement field")
		}
		seen[replacement.ID] = struct{}{}
		if field.container != nil {
			field.container[field.key] = replacement.Text
		} else {
			field.arrayContainer[field.arrayIndex] = replacement.Text
		}
	}
	if len(seen) != len(doc.fields) {
		return nil, errors.New("missing replacement field")
	}

	out, err := json.Marshal(doc.root)
	if err != nil {
		return nil, err
	}
	if len(out) > maxProxyRequestBodyBytes {
		return nil, errors.New("rewritten request is too large")
	}
	return out, nil
}

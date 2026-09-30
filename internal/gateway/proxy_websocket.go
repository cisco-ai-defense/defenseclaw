// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func (p *GuardrailProxy) webSocketBypass(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketUpgrade(r) {
			// When model routing is enabled, reject WebSocket upgrades
			// so clients fall back to HTTP POST where routing works.
			if p.modelRouter != nil {
				w.WriteHeader(http.StatusNotImplemented)
				return
			}
			path := r.URL.Path
			if idx := strings.Index(path, "/c/"); idx >= 0 {
				parts := strings.SplitN(path[idx+3:], "/", 2)
				if len(parts) == 2 {
					r.URL.Path = "/" + parts[1]
				}
			}
			p.handleWebSocketPassthrough(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *GuardrailProxy) handleWebSocketPassthrough(w http.ResponseWriter, r *http.Request) {
	defaultOrigin := strings.TrimSpace(p.cfg.LLM.BaseURL)
	if defaultOrigin == "" {
		http.Error(w, "no upstream configured for WebSocket passthrough", http.StatusBadGateway)
		return
	}

	clientAuth := r.Header.Get("Authorization")

	// Accept the client WebSocket first so we can read the first message
	// and classify it before deciding which upstream to connect to.
	clientConn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket: client upgrade failed: %v\n", err)
		return
	}
	defer clientConn.Close()

	// WebSocket passthrough to the default upstream. The Codex Responses
	// API WS protocol sends the user query after the session setup frame,
	// so per-request routing can't classify before connecting upstream.
	// Model routing for Codex happens on the HTTP fallback path instead.
	targetOrigin := defaultOrigin
	targetAuth := clientAuth

	// Build upstream URL.
	upstreamURL, err := url.Parse(strings.TrimRight(targetOrigin, "/") + r.URL.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket: invalid upstream URL: %v\n", err)
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "invalid upstream"))
		return
	}
	if upstreamURL.Scheme == "https" {
		upstreamURL.Scheme = "wss"
	} else {
		upstreamURL.Scheme = "ws"
	}

	// Build upstream headers.
	upstreamHeaders := http.Header{}
	if targetAuth != "" {
		upstreamHeaders.Set("Authorization", targetAuth)
	}
	for _, key := range []string{
		"Openai-Beta", "Openai-Organization", "Openai-Project",
		"X-Request-Id", "User-Agent",
	} {
		if v := r.Header.Get(key); v != "" {
			upstreamHeaders.Set(key, v)
		}
	}

	fmt.Fprintf(os.Stderr, "[guardrail] websocket: %s → %s\n", r.URL.Path, upstreamURL.String())

	// Dial the upstream WebSocket.
	upstreamConn, _, wsErr := websocket.DefaultDialer.Dial(upstreamURL.String(), upstreamHeaders)
	if wsErr != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket: upstream dial failed: %v\n", wsErr)
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "upstream connection failed"))
		return
	}
	defer upstreamConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			msgType, msg, err := clientConn.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					fmt.Fprintf(os.Stderr, "[guardrail] websocket: client read error: %v\n", err)
				}
				upstreamConn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
			if err := upstreamConn.WriteMessage(msgType, msg); err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] websocket: upstream write error: %v\n", err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			msgType, msg, err := upstreamConn.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					fmt.Fprintf(os.Stderr, "[guardrail] websocket: upstream read error: %v\n", err)
				}
				clientConn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
			if err := clientConn.WriteMessage(msgType, msg); err != nil {
				if !isClosedPipeError(err) {
					fmt.Fprintf(os.Stderr, "[guardrail] websocket: client write error: %v\n", err)
				}
				return
			}
		}
	}()

	wg.Wait()
}

// classifyWebSocketMessage extracts user content from the first WebSocket
// message, runs routing classification, and returns the target upstream
// origin and auth header to use.
func (p *GuardrailProxy) classifyWebSocketMessage(
	msg []byte, defaultOrigin, clientAuth, path string,
) (targetOrigin string, authHeader string, routedModel string) {
	targetOrigin = defaultOrigin
	authHeader = clientAuth

	if p.modelRouter == nil {
		return
	}

	// Parse the WebSocket payload. Codex sends the full Responses API
	// request in the first frame: model, input[], instructions, tools, etc.
	var partial struct {
		Model        string          `json:"model"`
		Input        json.RawMessage `json:"input,omitempty"`
		Instructions string          `json:"instructions,omitempty"`
	}
	if json.Unmarshal(msg, &partial) != nil {
		return
	}

	// Parse input[] items directly — extractResponsesAPIMessages may miss
	// items whose content is an array of parts (Responses API format).
	var rawItems []json.RawMessage
	var messages []ChatMessage
	if len(partial.Input) > 0 && partial.Input[0] == '[' {
		_ = json.Unmarshal(partial.Input, &rawItems)
	}
	for _, raw := range rawItems {
		var item struct {
			Type    string          `json:"type"`
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(raw, &item) == nil && item.Role != "" {
			msg := ChatMessage{Role: item.Role, RawContent: item.Content}
			// Try to populate Content as string.
			var s string
			if json.Unmarshal(item.Content, &s) == nil {
				msg.Content = s
			}
			messages = append(messages, msg)
		}
	}
	var roles []string
	for _, m := range messages {
		roles = append(roles, m.Role)
	}
	fmt.Fprintf(os.Stderr, "[guardrail] websocket routing: input_bytes=%d raw_items=%d messages=%d roles=%v\n",
		len(partial.Input), len(rawItems), len(messages), roles)

	// Only classify on user-role content. Developer messages contain
	// the Codex system prompt which always matches planning keywords
	// ("collaborate", "design", "plan") and would misroute every request.
	// If the first WS frame has no user-role content, skip classification
	// and use the default upstream. The user query arrives in a later
	// frame; routing for WS relies on the HTTP fallback path.
	userText := ""
	for i := len(messages) - 1; i >= 0; i-- {
		if strings.EqualFold(messages[i].Role, "user") {
			userText = messages[i].Content
			if userText == "" {
				userText = extractTextFromContentParts(messages[i].RawContent)
			}
			if userText != "" {
				break
			}
		}
	}
	if userText == "" {
		return
	}

	// Build a synthetic user message for the router.
	preview := userText
	if len(preview) > 100 {
		preview = preview[:100]
	}
	fmt.Fprintf(os.Stderr, "[guardrail] websocket routing: classifying %d chars: %q\n", len(userText), preview)
	messages = []ChatMessage{{Role: "user", Content: userText}}

	requestModel := strings.TrimSpace(partial.Model)
	decision := p.modelRouter.Route(context.Background(), &ModelRouterInput{
		Model:        requestModel,
		RequestModel: requestModel,
		Messages:     messages,
	})
	if decision == nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket routing: no match, using default upstream\n")
		return
	}

	fmt.Fprintf(os.Stderr, "[guardrail] websocket routing: decision=%s model=%q target=%s passthrough=%v\n",
		decision.Reason, decision.Model, decision.TargetURL, !decision.APIKeyOverride)

	if decision.TargetURLOverride && decision.TargetURL != "" {
		targetOrigin = decision.TargetURL
	}
	if decision.APIKeyOverride {
		if decision.APIKey != "" {
			authHeader = "Bearer " + decision.APIKey
		} else {
			authHeader = ""
		}
	}
	if decision.Model != "" && decision.APIKeyOverride {
		routedModel = decision.Model
	}
	// If APIKeyOverride is false (passthrough), authHeader keeps clientAuth.

	return
}

// bridgeWebSocketToHTTP translates between a WebSocket client (Codex) and
// an HTTP-only upstream (Ollama, vLLM, etc.). Posts the request body as HTTP,
// reads the SSE stream, and forwards each event as a WebSocket frame.
func (p *GuardrailProxy) bridgeWebSocketToHTTP(
	clientConn *websocket.Conn,
	requestBody []byte,
	targetOrigin, path, authHeader string,
) {
	httpURL := strings.TrimRight(targetOrigin, "/") + path

	// Ensure stream:true is set in the request body.
	var bodyMap map[string]json.RawMessage
	if json.Unmarshal(requestBody, &bodyMap) == nil {
		bodyMap["stream"] = json.RawMessage(`true`)
		bodyMap["store"] = json.RawMessage(`false`)
		if patched, err := json.Marshal(bodyMap); err == nil {
			requestBody = patched
		}
	}

	// Extra strip for the HTTP bridge path — ensure no additional_tools.
	if cleaned := stripUnsupportedInputItems(requestBody); cleaned != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket-http bridge: stripped input items (%d → %d bytes)\n",
			len(requestBody), len(cleaned))
		requestBody = cleaned
	}
	fmt.Fprintf(os.Stderr, "[guardrail] websocket-http bridge: POST %s (%d bytes)\n", httpURL, len(requestBody))

	req, err := http.NewRequest("POST", httpURL, bytes.NewReader(requestBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket-http bridge: request creation failed: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket-http bridge: upstream request failed: %v\n", err)
		clientConn.WriteMessage(websocket.TextMessage,
			[]byte(`{"type":"error","error":{"message":"upstream HTTP request failed","type":"server_error"}}`))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		fmt.Fprintf(os.Stderr, "[guardrail] websocket-http bridge: upstream returned %d: %s\n", resp.StatusCode, string(body))
		clientConn.WriteMessage(websocket.TextMessage, body)
		return
	}

	// Read SSE stream and forward each event as a WebSocket frame.
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			data := line[6:]
			if data == "[DONE]" {
				break
			}
			if err := clientConn.WriteMessage(websocket.TextMessage, []byte(data)); err != nil {
				if !isClosedPipeError(err) {
					fmt.Fprintf(os.Stderr, "[guardrail] websocket-http bridge: client write error: %v\n", err)
				}
				return
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[guardrail] websocket-http bridge: stream complete\n")
	clientConn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// stripUnsupportedInputItems removes Codex-specific input items
// (additional_tools, etc.) that non-ChatGPT backends don't understand.
// Keeps message-type items (user, developer, assistant roles).
func stripUnsupportedInputItems(msg []byte) []byte {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(msg, &envelope) != nil {
		return nil
	}
	inputRaw, ok := envelope["input"]
	if !ok || len(inputRaw) == 0 || inputRaw[0] != '[' {
		return nil
	}
	var items []json.RawMessage
	if json.Unmarshal(inputRaw, &items) != nil {
		return nil
	}
	kept := make([]json.RawMessage, 0, len(items))
	var droppedTypes []string
	for _, item := range items {
		var typed struct {
			Type string `json:"type"`
			Role string `json:"role"`
		}
		if json.Unmarshal(item, &typed) != nil {
			continue
		}
		switch typed.Type {
		case "message", "":
			kept = append(kept, item)
		case "additional_tools", "additional_functions":
			droppedTypes = append(droppedTypes, typed.Type)
		default:
			if typed.Role != "" {
				kept = append(kept, item)
			} else {
				droppedTypes = append(droppedTypes, typed.Type)
			}
		}
	}
	if len(droppedTypes) > 0 {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket: stripped %d unsupported input items (%v)\n",
			len(droppedTypes), droppedTypes)
	}
	if len(kept) == len(items) {
		return nil // nothing stripped
	}
	newInput, err := json.Marshal(kept)
	if err != nil {
		return nil
	}
	envelope["input"] = newInput
	result, err := json.Marshal(envelope)
	if err != nil {
		return nil
	}
	fmt.Fprintf(os.Stderr, "[guardrail] websocket: stripped %d unsupported input items for non-ChatGPT backend\n",
		len(items)-len(kept))
	return result
}

// extractTextFromContentParts parses Responses API content arrays
// like [{"type":"input_text","text":"..."}] and concatenates the text.
func extractTextFromContentParts(raw json.RawMessage) string {
	if len(raw) == 0 || raw[0] != '[' {
		return ""
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var texts []string
	for _, p := range parts {
		if p.Text != "" {
			texts = append(texts, p.Text)
		}
	}
	return strings.Join(texts, " ")
}

func patchModelInJSON(msg []byte, newModel string) []byte {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(msg, &envelope) != nil {
		return nil
	}
	modelBytes, err := json.Marshal(newModel)
	if err != nil {
		return nil
	}
	envelope["model"] = modelBytes
	result, err := json.Marshal(envelope)
	if err != nil {
		return nil
	}
	return result
}

func isClosedPipeError(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "broken pipe") ||
		strings.Contains(err.Error(), "connection reset") ||
		err == io.EOF)
}

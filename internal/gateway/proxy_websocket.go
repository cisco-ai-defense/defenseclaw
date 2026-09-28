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

	// Read the first frame and classify it. Codex sends the full request
	// (system instructions + user query + tools) in a single frame.
	type bufferedFrame struct {
		msgType int
		data    []byte
	}
	firstMsgType, firstMsg, err := clientConn.ReadMessage()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket: failed to read first frame: %v\n", err)
		return
	}
	buffered := []bufferedFrame{{firstMsgType, firstMsg}}
	targetOrigin := defaultOrigin
	targetAuth := clientAuth

	origin, auth, model := p.classifyWebSocketMessage(firstMsg, defaultOrigin, clientAuth, r.URL.Path)
	if origin != defaultOrigin {
		targetOrigin = origin
		targetAuth = auth
		if model != "" {
			if patched := patchModelInJSON(firstMsg, model); patched != nil {
				buffered[0].data = patched
			}
		}
		fmt.Fprintf(os.Stderr, "[guardrail] websocket: routed to %s model=%q\n", targetOrigin, model)
	}

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

	// Strip unsupported input items for non-ChatGPT backends.
	if targetOrigin != defaultOrigin {
		for i := range buffered {
			if cleaned := stripUnsupportedInputItems(buffered[i].data); cleaned != nil {
				buffered[i].data = cleaned
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[guardrail] websocket: %s → %s (%d buffered frames)\n",
		r.URL.Path, upstreamURL.String(), len(buffered))

	// Try WebSocket dial first; fall back to HTTP bridge if upstream
	// doesn't support WebSocket (e.g. Ollama, vLLM, LM Studio).
	upstreamConn, _, wsErr := websocket.DefaultDialer.Dial(upstreamURL.String(), upstreamHeaders)
	if wsErr != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket: upstream WS dial failed (%v), falling back to HTTP bridge\n", wsErr)
		// For HTTP bridge, send the last buffered frame (which has user content).
		bridgeMsg := buffered[len(buffered)-1].data
		p.bridgeWebSocketToHTTP(clientConn, bridgeMsg, targetOrigin, r.URL.Path, targetAuth)
		return
	}
	defer upstreamConn.Close()

	// Forward all buffered frames to upstream.
	for _, frame := range buffered {
		if err := upstreamConn.WriteMessage(frame.msgType, frame.data); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] websocket: failed to forward buffered frame: %v\n", err)
			return
		}
	}

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

	var messages []ChatMessage
	if len(partial.Input) > 0 {
		messages = extractResponsesAPIMessages(partial.Input)
	}

	// Log roles for debugging.
	var roles []string
	for _, m := range messages {
		roles = append(roles, m.Role)
	}
	for _, m := range messages {
		contentLen := len(m.Content)
		rawLen := len(m.RawContent)
		preview := extractTextFromContentParts(m.RawContent)
		if len(preview) > 80 {
			preview = preview[:80]
		}
		fmt.Fprintf(os.Stderr, "[guardrail] websocket routing:   item role=%s type=%s content=%d raw=%d text=%q\n",
			m.Role, "", contentLen, rawLen, preview)
	}
	fmt.Fprintf(os.Stderr, "[guardrail] websocket routing: %d input items, roles=%v\n", len(messages), roles)

	// Extract classifiable text. Try user-role first, then developer-role.
	// Codex Responses API WS first frame only has developer items — the
	// user query is embedded in the last developer message's content parts.
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
	// Fall back to extracting from the last developer message.
	// Codex embeds the user's actual prompt near the end of the
	// developer instructions. Extract the last input_text part
	// which typically contains the user query.
	if userText == "" {
		for i := len(messages) - 1; i >= 0; i-- {
			text := extractTextFromContentParts(messages[i].RawContent)
			if text != "" {
				// The developer system prompt is very long; the actual
				// user query is the last line after "user\n".
				if idx := strings.LastIndex(text, "\n"); idx > 0 && len(text)-idx < 500 {
					userText = strings.TrimSpace(text[idx+1:])
				}
				if userText == "" {
					userText = text
				}
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
	var allTypes []string
	for _, item := range items {
		var t struct{ Type, Role string }
		json.Unmarshal(item, &t)
		allTypes = append(allTypes, fmt.Sprintf("%s(role=%s)", t.Type, t.Role))
	}
	fmt.Fprintf(os.Stderr, "[guardrail] stripInput: %d items, kept=%d, dropped=%v, types=%v\n",
		len(items), len(kept), droppedTypes, allTypes)
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

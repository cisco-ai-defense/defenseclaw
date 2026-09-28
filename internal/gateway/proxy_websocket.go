// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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

	// Read the first message from the client — this contains the model,
	// input, and other parameters we need for routing classification.
	firstMsgType, firstMsg, err := clientConn.ReadMessage()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket: failed to read first message: %v\n", err)
		return
	}

	// Classify the first message to determine routing.
	targetOrigin, targetAuth := p.classifyWebSocketMessage(
		firstMsg, defaultOrigin, clientAuth, r.URL.Path,
	)

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

	// Dial the upstream.
	upstreamConn, resp, err := websocket.DefaultDialer.Dial(upstreamURL.String(), upstreamHeaders)
	if err != nil {
		status := websocket.CloseInternalServerErr
		if resp != nil && resp.StatusCode >= 400 {
			status = websocket.ClosePolicyViolation
		}
		fmt.Fprintf(os.Stderr, "[guardrail] websocket: upstream dial failed: %v\n", err)
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(status, "upstream connection failed"))
		return
	}
	defer upstreamConn.Close()

	// Forward the first message, stripping unsupported input item types
	// (e.g. additional_tools) when routing to non-ChatGPT backends.
	forwardMsg := firstMsg
	if targetOrigin != defaultOrigin {
		if cleaned := stripUnsupportedInputItems(firstMsg); cleaned != nil {
			forwardMsg = cleaned
		}
	}
	if err := upstreamConn.WriteMessage(firstMsgType, forwardMsg); err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket: failed to forward first message: %v\n", err)
		return
	}

	// Bidirectional proxy for remaining messages.
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
) (targetOrigin string, authHeader string) {
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
	// Log first-frame shape for debugging.
	fmt.Fprintf(os.Stderr, "[guardrail] websocket routing: first frame model=%q input_len=%d msgs=%d roles=",
		partial.Model, len(partial.Input), len(messages))
	for _, m := range messages {
		contentPreview := m.Content
		if len(contentPreview) > 50 {
			contentPreview = contentPreview[:50]
		}
		fmt.Fprintf(os.Stderr, " %s(%d:%q)", m.Role, len(m.Content), contentPreview)
	}
	fmt.Fprintln(os.Stderr)

	// Extract user messages from input[]. Codex sends developer-role
	// system instructions and user-role query messages in input[].
	// Only classify on user-role content to avoid matching keywords
	// in the system prompt.
	var messages []ChatMessage
	if len(partial.Input) > 0 {
		messages = extractResponsesAPIMessages(partial.Input)
	}

	// Look for user-role content first. Codex sends the user query as
	// a separate input item or in a follow-up frame.
	userText := ""
	for i := len(messages) - 1; i >= 0; i-- {
		if strings.EqualFold(messages[i].Role, "user") {
			userText = messages[i].Content
			break
		}
	}
	// If no user message in input[], check the top-level instructions
	// field — Codex v0.157+ includes the user's prompt summary there.
	if userText == "" && partial.Instructions != "" {
		userText = partial.Instructions
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
	// If APIKeyOverride is false (passthrough), authHeader keeps clientAuth.

	return
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
	for _, item := range items {
		var typed struct {
			Type string `json:"type"`
			Role string `json:"role"`
		}
		if json.Unmarshal(item, &typed) != nil {
			continue
		}
		// Keep message items and items with a recognized role.
		// Drop additional_tools, additional_functions, etc.
		switch typed.Type {
		case "message", "":
			kept = append(kept, item)
		default:
			if typed.Role != "" {
				kept = append(kept, item)
			}
		}
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

func isClosedPipeError(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "broken pipe") ||
		strings.Contains(err.Error(), "connection reset") ||
		err == io.EOF)
}

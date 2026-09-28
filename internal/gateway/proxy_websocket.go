// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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
	targetOrigin := strings.TrimSpace(p.cfg.LLM.BaseURL)
	if targetOrigin == "" {
		http.Error(w, "no upstream configured for WebSocket passthrough", http.StatusBadGateway)
		return
	}

	upstreamURL, err := url.Parse(strings.TrimRight(targetOrigin, "/") + r.URL.Path)
	if err != nil {
		http.Error(w, "invalid upstream URL", http.StatusBadGateway)
		return
	}
	if upstreamURL.Scheme == "https" {
		upstreamURL.Scheme = "wss"
	} else {
		upstreamURL.Scheme = "ws"
	}

	upstreamHeaders := http.Header{}
	if auth := r.Header.Get("Authorization"); auth != "" {
		upstreamHeaders.Set("Authorization", auth)
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		upstreamHeaders.Set("Content-Type", ct)
	}
	for _, key := range []string{
		"Openai-Beta", "Openai-Organization", "Openai-Project",
		"X-Request-Id", "User-Agent",
	} {
		if v := r.Header.Get(key); v != "" {
			upstreamHeaders.Set(key, v)
		}
	}

	fmt.Fprintf(os.Stderr, "[guardrail] websocket passthrough: %s → %s\n", r.URL.Path, upstreamURL.String())

	upstreamConn, resp, err := websocket.DefaultDialer.Dial(upstreamURL.String(), upstreamHeaders)
	if err != nil {
		status := http.StatusBadGateway
		if resp != nil {
			status = resp.StatusCode
		}
		fmt.Fprintf(os.Stderr, "[guardrail] websocket passthrough: upstream dial failed: %v\n", err)
		http.Error(w, "upstream WebSocket connection failed", status)
		return
	}
	defer upstreamConn.Close()

	clientConn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] websocket passthrough: client upgrade failed: %v\n", err)
		return
	}
	defer clientConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Upstream
	go func() {
		defer wg.Done()
		for {
			msgType, msg, err := clientConn.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					fmt.Fprintf(os.Stderr, "[guardrail] websocket passthrough: client read error: %v\n", err)
				}
				upstreamConn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
			if err := upstreamConn.WriteMessage(msgType, msg); err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] websocket passthrough: upstream write error: %v\n", err)
				return
			}
		}
	}()

	// Upstream → Client
	go func() {
		defer wg.Done()
		for {
			msgType, msg, err := upstreamConn.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					fmt.Fprintf(os.Stderr, "[guardrail] websocket passthrough: upstream read error: %v\n", err)
				}
				clientConn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
			if err := clientConn.WriteMessage(msgType, msg); err != nil {
				if !isClosedPipeError(err) {
					fmt.Fprintf(os.Stderr, "[guardrail] websocket passthrough: client write error: %v\n", err)
				}
				return
			}
		}
	}()

	wg.Wait()
}

func isClosedPipeError(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "broken pipe") ||
		strings.Contains(err.Error(), "connection reset") ||
		err == io.EOF)
}

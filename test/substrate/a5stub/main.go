// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// a5stub stands in for the DefenseClaw gateway's actor listener in the A5
// kit-only cells, until A2's gateway exists. It logs every hook envelope
// (with the claims of the injected actor JWT, never the token), answers
// allow, or block for an event that names BLOCKME, and forwards /llm/
// requests to Amazon Bedrock with the bearer from a mounted Secret so the
// agent's model traffic takes the gateway's path (D2). It is a test tool:
// no verification, no policy.
package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

var log = slog.New(slog.NewJSONHandler(os.Stdout, nil))

func jwtClaims(h string) map[string]any {
	h = strings.TrimPrefix(h, "Bearer ")
	parts := strings.Split(h, ".")
	if len(parts) != 3 {
		return map[string]any{"injected": false, "value_kind": map[bool]string{true: "placeholder", false: "other"}[h == kit.PlaceholderValue]}
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]any{"injected": true, "parse": "error"}
	}
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	return map[string]any{"injected": true, "sub": c["sub"], "aud": c["aud"], "actor": c["actor.ate.dev"], "exp": c["exp"]}
}

var mode atomic.Value

func hook(w http.ResponseWriter, r *http.Request) {
	connector := strings.TrimPrefix(r.URL.Path, kit.HookPathPrefix)
	recv := time.Now()
	if r.Method == http.MethodGet && r.Header.Get(kit.WarmHeader) == "1" {
		log.Info("warm", "connector", connector, "jwt", jwtClaims(r.Header.Get(kit.PlaceholderHeader)))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var env kit.HookEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, "bad envelope", 400)
		return
	}
	var p struct {
		Tool  string          `json:"tool_name"`
		Input json.RawMessage `json:"tool_input"`
		Sess  string          `json:"session_id"`
	}
	_ = json.Unmarshal(env.Payload, &p)
	facts := map[string]any{}
	if env.Facts != nil {
		var paths, files []string
		for _, f := range env.Facts.Paths {
			paths = append(paths, f.Field+"="+f.Abs+"->"+f.Resolved+" ("+f.Type+")")
		}
		for _, f := range env.Facts.Files {
			files = append(files, f.Role+":"+f.Path)
		}
		facts = map[string]any{"paths": paths, "files": files, "truncated": env.Facts.Truncated}
	}
	block := strings.Contains(string(env.Payload), "BLOCKME")
	m, _ := mode.Load().(string)
	switch m {
	case "outage":
		log.Info("hook", "connector", connector, "event", env.Event, "answer", "503")
		w.WriteHeader(503)
		return
	case "deny-all":
		block = true
	}
	log.Info("hook", "connector", connector, "event", env.Event, "tool", p.Tool, "session", p.Sess, "mode", env.Mode,
		"kit", env.KitVersion, "contract", env.HookContract, "idem", r.Header.Get("X-DefenseClaw-Hook-Idempotency-Key") != "",
		"jwt", jwtClaims(r.Header.Get(kit.PlaceholderHeader)), "facts", facts, "block", block,
		"recv_unix_ms", recv.UnixMilli(), "bytes", len(body))
	reason := "BLOCKME is not allowed (a5 stub verdict)"
	ans := map[string]any{"action": "allow"}
	if block {
		ans = map[string]any{"action": "block", "reason": reason}
		if connector == "claudecode" && env.Event == "PreToolUse" {
			ans["claude_code_output"] = map[string]any{"hookSpecificOutput": map[string]any{
				"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ans)
}

func proxyTo(target, prefix, tokenFile string) http.Handler {
	u, _ := url.Parse(target)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.URL.Path = strings.TrimSuffix(u.Path, "/") + strings.TrimPrefix(pr.In.URL.Path, prefix)
			pr.Out.Host = u.Host
			tok, _ := os.ReadFile(tokenFile)
			pr.Out.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
			pr.Out.Header.Del(kit.PlaceholderHeader)
			pr.Out.Header.Del("X-Api-Key")
		},
		FlushInterval: -1,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Info("llm", "path", r.URL.Path, "jwt", jwtClaims(r.Header.Get(kit.PlaceholderHeader)),
			"client", r.Header.Get("X-DefenseClaw-Client"), "auth_was_placeholder",
			strings.Contains(r.Header.Get("Authorization"), "placeholder") || strings.Contains(r.Header.Get("X-Api-Key"), "placeholder"))
		rp.ServeHTTP(w, r)
		log.Info("llm.done", "path", r.URL.Path, "ms", time.Since(start).Milliseconds())
	})
}

func main() {
	mode.Store(os.Getenv("STUB_MODE"))
	tokenFile := os.Getenv("BEDROCK_TOKEN_FILE")
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(kit.HookPathPrefix, hook)
	mux.HandleFunc(kit.NotifyPathPrefix, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		log.Info("notify", "path", r.URL.Path, "bytes", len(b), "jwt", jwtClaims(r.Header.Get(kit.PlaceholderHeader)))
		w.WriteHeader(204)
	})
	for _, p := range []string{"/v1/logs", "/v1/metrics", "/v1/traces"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			log.Info("otlp", "path", r.URL.Path, "jwt", jwtClaims(r.Header.Get(kit.PlaceholderHeader)))
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, "{}")
		})
	}
	mux.Handle("/llm/bedrock/", proxyTo("https://bedrock-runtime."+region+".amazonaws.com/", "/llm/bedrock", tokenFile))
	mux.Handle("/llm/openai/", proxyTo("https://bedrock-mantle."+region+".api.aws/openai/", "/llm/openai", tokenFile))
	mux.HandleFunc("/stub/mode", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mode.Store(r.URL.Query().Get("set"))
		}
		m, _ := mode.Load().(string)
		io.WriteString(w, m+"\n")
	})
	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Info("a5stub listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("serve", "err", err.Error())
		os.Exit(1)
	}
}

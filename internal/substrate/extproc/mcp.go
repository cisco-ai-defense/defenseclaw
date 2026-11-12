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

package extproc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// maxBatchCalls bounds a JSON-RPC batch the callout judges.
const maxBatchCalls = 64

type toolCallReq struct {
	name string
	args json.RawMessage
}

// parseToolCalls returns the tools/call requests in an MCP JSON-RPC body (a
// request or a batch). A body that is not JSON-RPC has none. Keys are
// matched exactly and a repeated key is an error, so a body can't show the
// callout one method and the server another (encoding/json would fold case
// and keep the last duplicate).
func parseToolCalls(body []byte) ([]toolCallReq, error) {
	b := bytes.TrimSpace(body)
	if len(b) == 0 {
		return nil, nil
	}
	var msgs []json.RawMessage
	switch b[0] {
	case '[':
		if err := json.Unmarshal(b, &msgs); err != nil {
			return nil, nil
		}
		if len(msgs) > maxBatchCalls {
			return nil, fmt.Errorf("The JSON-RPC batch has more than %d requests.", maxBatchCalls)
		}
	case '{':
		msgs = []json.RawMessage{b}
	default:
		return nil, nil
	}
	var out []toolCallReq
	for _, m := range msgs {
		obj, err := exactObject(m)
		if err != nil {
			if errors.Is(err, errDuplicateKey) {
				return nil, errors.New("The JSON-RPC request repeats a key, so it is ambiguous.")
			}
			continue
		}
		var method string
		if raw, ok := obj["method"]; !ok || json.Unmarshal(raw, &method) != nil || method != "tools/call" {
			continue
		}
		params, err := exactObject(obj["params"])
		if err != nil {
			if errors.Is(err, errDuplicateKey) {
				return nil, errors.New("The tools/call params repeat a key, so they are ambiguous.")
			}
			return nil, errors.New("The tools/call request has no params object.")
		}
		var name string
		if raw, ok := params["name"]; !ok || json.Unmarshal(raw, &name) != nil || name == "" {
			return nil, errors.New("The tools/call request names no tool.")
		}
		out = append(out, toolCallReq{name: name, args: params["arguments"]})
	}
	return out, nil
}

var errDuplicateKey = errors.New("duplicate key")

// exactObject decodes a JSON object into its raw members, refusing a
// repeated key.
func exactObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("bad key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := out[key]; dup {
			return nil, errDuplicateKey
		}
		out[key] = v
	}
	return out, nil
}

// InspectToolClient is the ToolJudge adapter to the gateway's tool inspect
// route (POST /api/v1/inspect/tool), the entry point the hooks' tool and
// MCP rules run behind. A tools/call reaches it as the tool
// mcp__<server>__<tool> with mcp_server_name set, the name and arguments
// shape the hooks send, so the callout runs the same rules and adds none.
type InspectToolClient struct {
	url       string
	tokenFile string
	http      *http.Client
}

// NewInspectToolClient builds a client from the judge settings; an empty
// URL is no client.
func NewInspectToolClient(cfg JudgeConfig) (*InspectToolClient, error) {
	if cfg.URL == "" {
		return nil, nil
	}
	if !strings.HasPrefix(cfg.URL, "https://") && !strings.HasPrefix(cfg.URL, "http://") {
		return nil, fmt.Errorf("%w: judge.url %q", ErrInvalidConfig, cfg.URL)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: judge.ca_file has no certificates", ErrInvalidConfig)
		}
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return &InspectToolClient{url: cfg.URL, tokenFile: cfg.TokenFile, http: &http.Client{Transport: tr}}, nil
}

type inspectToolRequest struct {
	Tool          string          `json:"tool"`
	Args          json.RawMessage `json:"args,omitempty"`
	MCPServerName string          `json:"mcp_server_name,omitempty"`
}

type inspectToolVerdict struct {
	Action   string   `json:"action"`
	Severity string   `json:"severity"`
	Reason   string   `json:"reason"`
	Findings []string `json:"findings"`
}

// JudgeToolCall implements ToolJudge.
func (c *InspectToolClient) JudgeToolCall(ctx context.Context, call ToolCall) (ToolVerdict, error) {
	body, err := json.Marshal(inspectToolRequest{
		Tool: "mcp__" + toolNamePart(call.Server) + "__" + call.Tool, Args: call.Args, MCPServerName: call.Server,
	})
	if err != nil {
		return ToolVerdict{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return ToolVerdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	// The gateway API's CSRF gate refuses a request without a client tag.
	req.Header.Set("X-DefenseClaw-Client", "substrate-extproc")
	if c.tokenFile != "" {
		tok, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return ToolVerdict{}, fmt.Errorf("judge token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return ToolVerdict{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return ToolVerdict{}, fmt.Errorf("tool inspect: HTTP %d", resp.StatusCode)
	}
	var v inspectToolVerdict
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return ToolVerdict{}, err
	}
	return ToolVerdict{Block: strings.EqualFold(v.Action, "block"), Alert: strings.EqualFold(v.Action, "alert"), Severity: v.Severity, Reason: v.Reason, Findings: v.Findings}, nil
}

// toolNamePart keeps an MCP server name to the characters a hook tool name
// carries.
func toolNamePart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

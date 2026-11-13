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

	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
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
			return nil, &jsonRPCError{msg: fmt.Sprintf("jsonrpc batch has more than %d requests", maxBatchCalls),
				reason: fmt.Sprintf("The JSON-RPC batch has more than %d requests.", maxBatchCalls)}
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
				return nil, &jsonRPCError{msg: "jsonrpc request repeats a key", reason: "The JSON-RPC request repeats a key, so it is ambiguous."}
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
				return nil, &jsonRPCError{msg: "tools/call params repeat a key", reason: "The tools/call params repeat a key, so they are ambiguous."}
			}
			return nil, &jsonRPCError{msg: "tools/call has no params object", reason: "The tools/call request has no params object."}
		}
		var name string
		if raw, ok := params["name"]; !ok || json.Unmarshal(raw, &name) != nil || name == "" {
			return nil, &jsonRPCError{msg: "tools/call names no tool", reason: "The tools/call request names no tool."}
		}
		out = append(out, toolCallReq{name: name, args: params["arguments"]})
	}
	return out, nil
}

var errDuplicateKey = errors.New("duplicate key")

// jsonRPCError is a body the callout refuses as ambiguous or malformed:
// msg is the Go error text, reason the sentence the actor sees.
type jsonRPCError struct{ msg, reason string }

func (e *jsonRPCError) Error() string { return e.msg }

// refusalReason is the text shown to the actor for a parseToolCalls error.
func refusalReason(err error) string {
	var je *jsonRPCError
	if errors.As(err, &je) {
		return je.reason
	}
	return "The MCP request body could not be read as JSON-RPC."
}

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

// VerdictClient is the ToolJudge adapter to the gateway's callout verdict
// route (calloutapi.Path, admin listener): the route runs the hook path's
// MCP evaluation, the MCP asset policy and the tool rules in action mode,
// so a tools/call the hooks would refuse is refused at egress with the same
// verdict, and the callout adds no rules of its own.
type VerdictClient struct {
	url       string
	tokenFile string
	http      *http.Client
}

// NewVerdictClient builds a client from the judge settings; an empty URL is
// no client.
func NewVerdictClient(cfg JudgeConfig) (*VerdictClient, error) {
	if cfg.URL == "" {
		return nil, nil
	}
	if !strings.HasPrefix(cfg.URL, "https://") && !strings.HasPrefix(cfg.URL, "http://") {
		return nil, fmt.Errorf("%w: judge.url %q", ErrInvalidConfig, cfg.URL)
	}
	tr, err := calloutTransport(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	return &VerdictClient{url: cfg.URL, tokenFile: cfg.TokenFile, http: &http.Client{Transport: tr}}, nil
}

// calloutTransport is the transport to the gateway's admin listener: no
// proxy, and the judge.ca_file roots when set.
func calloutTransport(caFile string) (*http.Transport, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: judge.ca_file has no certificates", ErrInvalidConfig)
		}
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return tr, nil
}

// JudgeToolCall implements ToolJudge. Any answer but 200 with contract
// version 1 and a known verdict is an error, which the engine's failure
// mode handles.
func (c *VerdictClient) JudgeToolCall(ctx context.Context, call ToolCall) (ToolVerdict, error) {
	body, err := json.Marshal(calloutapi.Request{
		V: calloutapi.Version, RequestID: call.RequestID,
		Actor: calloutapi.Actor{Atespace: call.Actor.Atespace, Name: call.Actor.Name},
		MCP: calloutapi.MCP{Server: call.Server, URL: call.URL, Transport: "http", Method: "tools/call",
			Tool: call.Tool},
		Args: call.Args, SessionID: call.SessionID,
	})
	if err != nil {
		return ToolVerdict{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return ToolVerdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	// The admin listener keeps the CSRF gate: a POST needs a client tag.
	req.Header.Set("X-DefenseClaw-Client", calloutapi.ClientTag)
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
		return ToolVerdict{}, fmt.Errorf("callout verdict: HTTP %d", resp.StatusCode)
	}
	var v calloutapi.Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return ToolVerdict{}, err
	}
	if v.V != calloutapi.Version {
		return ToolVerdict{}, fmt.Errorf("callout verdict: contract version %q", v.V)
	}
	out := ToolVerdict{Severity: v.Severity, Reason: v.Reason, Findings: v.Findings, Source: v.Source}
	switch v.Verdict {
	case calloutapi.VerdictDeny:
		out.Block = true
	case calloutapi.VerdictAsk:
		// The callout can't hold a request for a person: an ask the route
		// raised is a refusal until it is approved (D12).
		out.Block, out.Ask = true, true
	case calloutapi.VerdictAllow:
		out.Alert = len(v.Findings) > 0
	default:
		return ToolVerdict{}, fmt.Errorf("callout verdict: unknown verdict %q", v.Verdict)
	}
	return out, nil
}

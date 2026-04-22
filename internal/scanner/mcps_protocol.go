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

package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// MCPSProtocolScanner checks MCP server endpoints for protocol-level security
// controls defined in OWASP MCP Security Cheat Sheet Section 7:
// message signing, replay protection, agent identity, tool integrity, and
// fail-closed semantics.
//
// Reference: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
type MCPSProtocolScanner struct{}

func NewMCPSProtocolScanner() *MCPSProtocolScanner {
	return &MCPSProtocolScanner{}
}

func (s *MCPSProtocolScanner) Name() string               { return "mcps-protocol" }
func (s *MCPSProtocolScanner) Version() string            { return "1.0.0" }
func (s *MCPSProtocolScanner) SupportedTargets() []string { return []string{"url", "mcp"} }

// mcpResponse represents a JSON-RPC response from an MCP server.
type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// mcpToolsResult represents the result of a tools/list call.
type mcpToolsResult struct {
	Tools []mcpTool `json:"tools"`
}

// mcpTool represents a single MCP tool definition.
type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// Scan performs protocol-level security checks against an MCP server endpoint.
func (s *MCPSProtocolScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{
		Scanner:   s.Name(),
		Target:    target,
		Timestamp: start,
		Findings:  []Finding{},
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	result.Findings = append(result.Findings, s.checkTransportSecurity(target)...)
	result.Findings = append(result.Findings, s.checkAuthentication(ctx, client, target)...)
	result.Findings = append(result.Findings, s.checkMessageSigning(ctx, client, target)...)
	result.Findings = append(result.Findings, s.checkReplayProtection(ctx, client, target)...)
	result.Findings = append(result.Findings, s.checkToolIntegrity(ctx, client, target)...)
	result.Findings = append(result.Findings, s.checkAgentIdentity(ctx, client, target)...)
	result.Findings = append(result.Findings, s.checkFailClosed(ctx, client, target)...)
	result.Findings = append(result.Findings, s.checkRateLimiting(ctx, client, target)...)

	result.Duration = time.Since(start)
	return result, nil
}

func (s *MCPSProtocolScanner) sendMCPRequest(ctx context.Context, client *http.Client, target, method string, params interface{}) (*http.Response, []byte, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      rand.Intn(100000),
		"method":  method,
	}
	if params != nil {
		payload["params"] = params
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(string(body)))
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("send request: %w", err)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return resp, nil, fmt.Errorf("read response: %w", err)
	}

	return resp, respBody, nil
}

func (s *MCPSProtocolScanner) checkTransportSecurity(target string) []Finding {
	if strings.HasPrefix(target, "http://") {
		return []Finding{{
			ID:          "MCPS-001",
			Severity:    SeverityCritical,
			Title:       "MCP server uses unencrypted HTTP transport",
			Description: "The MCP server endpoint uses HTTP without TLS. All messages, including tool arguments and responses, are transmitted in plaintext and vulnerable to interception and modification.",
			Location:    target,
			Remediation: "Configure TLS 1.2+ on the MCP server endpoint. Use HTTPS for all MCP communications.",
			Scanner:     "mcps-protocol",
			RuleID:      "mcps-transport-security",
			Category:    "transport",
			Tags:        []string{"owasp-mcp-s6", "cwe-319"},
		}}
	}
	return nil
}

func (s *MCPSProtocolScanner) checkAuthentication(ctx context.Context, client *http.Client, target string) []Finding {
	resp, body, err := s.sendMCPRequest(ctx, client, target, "tools/list", nil)
	if err != nil {
		return nil
	}

	if resp.StatusCode == http.StatusOK && len(body) > 0 {
		var mcpResp mcpResponse
		if json.Unmarshal(body, &mcpResp) == nil && mcpResp.Error == nil {
			return []Finding{{
				ID:          "MCPS-002",
				Severity:    SeverityHigh,
				Title:       "MCP server accepts unauthenticated requests",
				Description: "The server responded to a tools/list request with no authentication credentials. Any client can enumerate and invoke tools without identity verification.",
				Location:    target,
				Remediation: "Implement authentication on all MCP endpoints. Use OAuth 2.0, mTLS, or cryptographically bound agent identity (OWASP MCP Cheat Sheet Section 6). OWASP AISVS 10.2.13 recommends key-based proof-of-possession over bearer tokens.",
				Scanner:     "mcps-protocol",
				RuleID:      "mcps-authentication",
				Category:    "authentication",
				Tags:        []string{"owasp-mcp-s6", "aisvs-10.2.13", "cwe-306"},
			}}
		}
	}
	return nil
}

func (s *MCPSProtocolScanner) checkMessageSigning(ctx context.Context, client *http.Client, target string) []Finding {
	resp, body, err := s.sendMCPRequest(ctx, client, target, "tools/list", nil)
	if err != nil {
		return nil
	}

	sigHeaders := []string{
		"x-mcps-signature", "x-mcp-signature", "x-agent-signature",
		"x-message-signature", "signature", "x-agent-trust",
	}

	for _, h := range sigHeaders {
		if resp.Header.Get(h) != "" {
			return nil
		}
	}

	if len(body) > 0 {
		var raw map[string]interface{}
		if json.Unmarshal(body, &raw) == nil {
			for _, key := range []string{"signature", "nonce", "signed", "mcps"} {
				if _, exists := raw[key]; exists {
					return nil
				}
			}
		}
	}

	return []Finding{{
		ID:          "MCPS-003",
		Severity:    SeverityHigh,
		Title:       "MCP messages are not cryptographically signed",
		Description: "No message-level signing detected in server responses. Without signatures, a compromised proxy or middleware can modify JSON-RPC payloads after TLS termination. OWASP MCP Security Cheat Sheet Section 7 requires ECDSA P-256 message signing.",
		Location:    target,
		Remediation: "Sign each MCP message with an asymmetric key (ECDSA P-256) bound to the sender identity. Include a unique nonce and timestamp. Verify signatures before processing. Reference: OWASP MCP Cheat Sheet Section 7, OWASP AISVS 10.4.11.",
		Scanner:     "mcps-protocol",
		RuleID:      "mcps-message-signing",
		Category:    "integrity",
		Tags:        []string{"owasp-mcp-s7", "aisvs-10.4.11", "cwe-345"},
	}}
}

func (s *MCPSProtocolScanner) checkReplayProtection(ctx context.Context, client *http.Client, target string) []Finding {
	_, body1, err1 := s.sendMCPRequest(ctx, client, target, "tools/list", nil)
	if err1 != nil {
		return nil
	}
	_, body2, err2 := s.sendMCPRequest(ctx, client, target, "tools/list", nil)
	if err2 != nil {
		return nil
	}

	var resp1, resp2 mcpResponse
	if json.Unmarshal(body1, &resp1) == nil && json.Unmarshal(body2, &resp2) == nil {
		if resp1.Error == nil && resp2.Error == nil {
			return []Finding{{
				ID:          "MCPS-004",
				Severity:    SeverityMedium,
				Title:       "No replay protection on MCP messages",
				Description: "The server accepted two identical requests without nonce or timestamp validation. An attacker can capture and replay legitimate MCP messages to repeat actions.",
				Location:    target,
				Remediation: "Include a unique nonce and timestamp in each request. Reject duplicate nonces and messages outside a 5-minute time window. Reference: OWASP MCP Cheat Sheet Section 7.",
				Scanner:     "mcps-protocol",
				RuleID:      "mcps-replay-protection",
				Category:    "integrity",
				Tags:        []string{"owasp-mcp-s7", "cwe-294"},
			}}
		}
	}
	return nil
}

func (s *MCPSProtocolScanner) checkToolIntegrity(ctx context.Context, client *http.Client, target string) []Finding {
	_, body, err := s.sendMCPRequest(ctx, client, target, "tools/list", nil)
	if err != nil {
		return nil
	}

	var mcpResp mcpResponse
	if json.Unmarshal(body, &mcpResp) != nil || mcpResp.Error != nil {
		return nil
	}

	var toolsResult mcpToolsResult
	if json.Unmarshal(mcpResp.Result, &toolsResult) != nil || len(toolsResult.Tools) == 0 {
		return nil
	}

	var findings []Finding

	// Check for hash/signature on tool definitions.
	hasIntegrity := false
	for _, tool := range toolsResult.Tools {
		raw, _ := json.Marshal(tool)
		toolStr := string(raw)
		if strings.Contains(toolStr, "hash") || strings.Contains(toolStr, "signature") || strings.Contains(toolStr, "digest") {
			hasIntegrity = true
			break
		}
	}

	if !hasIntegrity {
		findings = append(findings, Finding{
			ID:          "MCPS-005",
			Severity:    SeverityMedium,
			Title:       "Tool definitions lack integrity verification",
			Description: fmt.Sprintf("The server exposes %d tools without hash pinning or signature verification on definitions. Tool definitions can be silently modified (rug pull, OWASP MCP Top 10 MCP-03).", len(toolsResult.Tools)),
			Location:    target,
			Remediation: "Pin tool definitions at discovery time using SHA-256 hashes. Sign tool definitions with the server key. Reference: OWASP MCP Cheat Sheet Section 2.",
			Scanner:     "mcps-protocol",
			RuleID:      "mcps-tool-integrity",
			Category:    "supply-chain",
			Tags:        []string{"owasp-mcp-s2", "owasp-mcp-s9", "cwe-494"},
		})
	}

	// Check for tool poisoning patterns in descriptions.
	poisonPatterns := []string{
		"ignore previous", "ignore all", "disregard instructions",
		"system prompt", "call read_file", "call execute",
		"call send_email", "before returning", "after responding",
		"do not tell the user",
	}

	for _, tool := range toolsResult.Tools {
		descLower := strings.ToLower(tool.Description)
		for _, pattern := range poisonPatterns {
			if strings.Contains(descLower, pattern) {
				findings = append(findings, Finding{
					ID:          "MCPS-006",
					Severity:    SeverityCritical,
					Title:       fmt.Sprintf("Potential tool poisoning in '%s'", tool.Name),
					Description: fmt.Sprintf("Tool description contains suspicious instruction pattern '%s' which may manipulate agent behaviour (OWASP MCP Top 10 MCP-03).", pattern),
					Location:    fmt.Sprintf("%s/tools/%s", target, tool.Name),
					Remediation: "Validate and sanitise all tool descriptions. Strip hidden instructions. Implement tool definition signing. Reference: OWASP MCP Cheat Sheet Section 2, Section 12.",
					Scanner:     "mcps-protocol",
					RuleID:      "mcps-tool-poisoning",
					Category:    "injection",
					Tags:        []string{"owasp-mcp-s2", "owasp-mcp-s12", "cwe-74"},
				})
				break
			}
		}
	}

	return findings
}

func (s *MCPSProtocolScanner) checkAgentIdentity(ctx context.Context, client *http.Client, target string) []Finding {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      rand.Intn(100000),
		"method":  "tools/list",
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", "spoofed-agent-999")
	req.Header.Set("X-Agent-Trust-Level", "4")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var mcpResp mcpResponse
	if resp.StatusCode == http.StatusOK && json.Unmarshal(respBody, &mcpResp) == nil && mcpResp.Error == nil {
		return []Finding{{
			ID:          "MCPS-007",
			Severity:    SeverityHigh,
			Title:       "Server accepts spoofed agent identity without verification",
			Description: "The server accepted a request with a fabricated agent identity header without cryptographic verification. Any client can impersonate any agent.",
			Location:    target,
			Remediation: "Require cryptographic proof of agent identity on every request. Use ECDSA-signed agent passports or mTLS client certificates. Reference: OWASP MCP Cheat Sheet Section 6, AISVS 10.2.13.",
			Scanner:     "mcps-protocol",
			RuleID:      "mcps-agent-identity",
			Category:    "authentication",
			Tags:        []string{"owasp-mcp-s6", "aisvs-10.2.13", "cwe-290"},
		}}
	}
	return nil
}

func (s *MCPSProtocolScanner) checkFailClosed(ctx context.Context, client *http.Client, target string) []Finding {
	payload := map[string]interface{}{
		"jsonrpc": "1.0", // Invalid version
		"id":      rand.Intn(100000),
		"method":  "tools/list",
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var mcpResp mcpResponse
	if resp.StatusCode == http.StatusOK && json.Unmarshal(respBody, &mcpResp) == nil && mcpResp.Error == nil {
		return []Finding{{
			ID:          "MCPS-008",
			Severity:    SeverityMedium,
			Title:       "Server uses fail-open semantics",
			Description: "The server processed a request with an invalid JSON-RPC version (1.0 instead of 2.0) without rejection. Fail-open means security checks that cannot complete default to allowing the request.",
			Location:    target,
			Remediation: "Implement fail-closed semantics: reject requests when validation fails. Never silently fall back to unsigned or unauthenticated processing. Reference: OWASP MCP Cheat Sheet Section 7, AISVS 10.6.4.",
			Scanner:     "mcps-protocol",
			RuleID:      "mcps-fail-closed",
			Category:    "configuration",
			Tags:        []string{"owasp-mcp-s7", "aisvs-10.6.4", "cwe-636"},
		}}
	}
	return nil
}

func (s *MCPSProtocolScanner) checkRateLimiting(ctx context.Context, client *http.Client, target string) []Finding {
	successCount := 0
	const burstSize = 10

	for i := 0; i < burstSize; i++ {
		_, body, err := s.sendMCPRequest(ctx, client, target, "tools/list", nil)
		if err != nil {
			break
		}
		var mcpResp mcpResponse
		if json.Unmarshal(body, &mcpResp) == nil && mcpResp.Error == nil {
			successCount++
		}
	}

	if successCount == burstSize {
		return []Finding{{
			ID:          "MCPS-009",
			Severity:    SeverityMedium,
			Title:       "No rate limiting on MCP endpoint",
			Description: fmt.Sprintf("The server accepted all %d rapid sequential requests without throttling or returning 429 Too Many Requests.", burstSize),
			Location:    target,
			Remediation: "Implement per-agent rate limiting with configurable thresholds. Return HTTP 429 with Retry-After header when limits are exceeded.",
			Scanner:     "mcps-protocol",
			RuleID:      "mcps-rate-limiting",
			Category:    "availability",
			Tags:        []string{"owasp-mcp-s4", "cwe-770"},
		}}
	}
	return nil
}

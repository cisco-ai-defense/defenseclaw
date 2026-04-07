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

import "time"

// --- Header names ---
// Custom HTTP headers used for proxy routing, authentication, and CSRF.

const (
	// HeaderTargetURL is set by the fetch interceptor to indicate the real
	// upstream URL the request was originally destined for.
	HeaderTargetURL = "X-DC-Target-URL"

	// HeaderAIAuth carries the real provider API key from the fetch
	// interceptor, normalized to "Bearer <key>".
	HeaderAIAuth = "X-AI-Auth"

	// HeaderDCAuth carries the DefenseClaw gateway token for non-loopback
	// authentication.
	HeaderDCAuth = "X-DC-Auth"

	// HeaderDefenseClawClient is required on mutating requests for CSRF
	// protection.
	HeaderDefenseClawClient = "X-DefenseClaw-Client"

	// HeaderDefenseClawToken is an alternative authentication header for
	// the REST API.
	HeaderDefenseClawToken = "X-DefenseClaw-Token"

	// HeaderAzureAPIKey is used by Azure OpenAI for API key authentication.
	HeaderAzureAPIKey = "api-key"

	// HeaderAnthropicAPIKey is used by Anthropic for API key authentication.
	HeaderAnthropicAPIKey = "x-api-key"

	// HeaderAnthropicVersion is the Anthropic API version header.
	HeaderAnthropicVersion = "anthropic-version"

	// HeaderCiscoAIDefenseAPIKey authenticates requests to the Cisco AI
	// Defense inspection API.
	HeaderCiscoAIDefenseAPIKey = "X-Cisco-AI-Defense-API-Key"
)

// --- Provider defaults ---
// Default base URLs for each provider.

const (
	// DefaultOpenAIBaseURL is the default base URL for the OpenAI API.
	DefaultOpenAIBaseURL = "https://api.openai.com"

	// DefaultAzureBaseURL is the fallback base URL for Azure OpenAI.
	DefaultAzureBaseURL = "https://api.openai.azure.com"

	// DefaultAnthropicBaseURL is the base URL for the Anthropic Messages API.
	DefaultAnthropicBaseURL = "https://api.anthropic.com"

	// DefaultAnthropicMessagesPath is the path for the Anthropic Messages API.
	DefaultAnthropicMessagesPath = "/v1/messages"

	// AnthropicAPIVersion is the version string for the Anthropic API.
	AnthropicAPIVersion = "2023-06-01"

	// DefaultGeminiBaseURL is the base URL for the Gemini native API.
	DefaultGeminiBaseURL = "https://generativelanguage.googleapis.com/v1beta"

	// DefaultGeminiCompatBaseURL is the base URL for the Gemini
	// OpenAI-compatible endpoint.
	DefaultGeminiCompatBaseURL = "https://generativelanguage.googleapis.com/v1beta/openai"

	// DefaultOpenRouterBaseURL is the base URL for the OpenRouter API.
	DefaultOpenRouterBaseURL = "https://openrouter.ai/api"

	// OpenRouterReferer is the HTTP-Referer header value sent with
	// OpenRouter requests.
	OpenRouterReferer = "https://github.com/defenseclaw/defenseclaw"

	// OpenRouterTitle is the X-Title header value sent with OpenRouter
	// requests.
	OpenRouterTitle = "defenseclaw"

	// DefaultCiscoAIDefenseEndpoint is the default endpoint for the Cisco
	// AI Defense Chat Inspection API.
	DefaultCiscoAIDefenseEndpoint = "https://us.api.inspect.aidefense.security.cisco.com"

	// CiscoInspectChatPath is the API path for Cisco AI Defense chat inspection.
	CiscoInspectChatPath = "/api/v1/inspect/chat"
)

// --- Azure ---

const (
	// AzureAPIVersion is the default Azure OpenAI API version.
	AzureAPIVersion = "2025-01-01-preview"
)

// --- Timeouts ---
// Default durations for HTTP clients, RPCs, shutdown, and health probes.

const (
	// ProviderHTTPTimeout is the timeout for the shared HTTP client used by
	// all LLM provider adapters.
	ProviderHTTPTimeout = 5 * time.Minute

	// DefaultCiscoInspectTimeout is the timeout for Cisco AI Defense API calls
	// when no explicit timeout is configured.
	DefaultCiscoInspectTimeout = 3 * time.Second

	// DefaultJudgeTimeout is the timeout for the LLM judge when none is
	// configured.
	DefaultJudgeTimeout = 30 * time.Second

	// ConnectRPCTimeout is the deadline for the gateway connect handshake.
	ConnectRPCTimeout = 45 * time.Second

	// WebSocketHandshakeTimeout is the timeout for the WebSocket dial
	// handshake.
	WebSocketHandshakeTimeout = 10 * time.Second

	// ChallengeReadTimeout is the deadline for reading the connect.challenge
	// frame from the gateway.
	ChallengeReadTimeout = 10 * time.Second

	// ShutdownTimeout is the grace period for HTTP server shutdown.
	ShutdownTimeout = 5 * time.Second

	// ServerStartProbeDelay is the wait time after starting the HTTP server
	// before declaring it healthy.
	ServerStartProbeDelay = 200 * time.Millisecond

	// RuntimeCacheTTL is the hot-reload interval for guardrail runtime config.
	RuntimeCacheTTL = 5 * time.Second

	// RPCTimeout is the default timeout for gateway RPC calls from the API
	// server and sidecar.
	RPCTimeout = 10 * time.Second

	// ScanTimeout is the timeout for skill and MCP scanner operations.
	ScanTimeout = 120 * time.Second

	// SandboxProbeTimeout is the timeout for each TCP dial probe to the
	// sandbox endpoint.
	SandboxProbeTimeout = 3 * time.Second

	// SandboxProbeInitialBackoff is the initial backoff between sandbox
	// probe attempts.
	SandboxProbeInitialBackoff = 500 * time.Millisecond

	// SandboxProbeMaxBackoff is the maximum backoff between sandbox probe
	// attempts.
	SandboxProbeMaxBackoff = 5 * time.Second
)

// --- Buffer & limits ---
// Sizes for request/response body reading and streaming buffers.

const (
	// MaxRequestBodySize is the maximum request body size the proxy will
	// read (10 MiB).
	MaxRequestBodySize = 10 * 1024 * 1024

	// MaxErrorResponseSize is the maximum upstream error response body the
	// proxy will read for error messages.
	MaxErrorResponseSize = 4096

	// MaxCiscoResponseSize is the maximum Cisco AI Defense response body
	// the proxy will read.
	MaxCiscoResponseSize = 64 * 1024

	// StreamingFlushBufferSize is the buffer size for flushing streaming
	// (SSE) responses to the client.
	StreamingFlushBufferSize = 4096

	// SSEScannerBufferSize is the initial buffer size for the bufio.Scanner
	// used to read SSE streams.
	SSEScannerBufferSize = 64 * 1024

	// SSEScannerMaxSize is the maximum buffer size for the bufio.Scanner
	// used to read SSE streams.
	SSEScannerMaxSize = 256 * 1024

	// StreamingScanInterval is the number of accumulated characters between
	// mid-stream guardrail scans.
	StreamingScanInterval = 500

	// DefaultAnthropicMaxTokens is the default max_tokens for Anthropic
	// requests when not specified by the caller.
	DefaultAnthropicMaxTokens = 4096

	// DefaultJudgeMaxTokens is the max_tokens for LLM judge requests.
	DefaultJudgeMaxTokens = 1024

	// MasterKeyLength is the truncated length of the hex-encoded HMAC
	// digest used for the proxy master key.
	MasterKeyLength = 32

	// MasterKeyPrefix is the prefix prepended to the derived master key.
	MasterKeyPrefix = "sk-dc-"

	// MasterKeyHMACLabel is the HMAC label used to derive the proxy master key.
	MasterKeyHMACLabel = "defenseclaw-proxy-master-key"

	// MaxSandboxProbeAttempts is the maximum number of TCP dial attempts
	// when probing the sandbox endpoint.
	MaxSandboxProbeAttempts = 20

	// DefaultAlertsLimit is the default limit for the alerts endpoint.
	DefaultAlertsLimit = 50

	// MaxFindingsInReason is the maximum number of findings shown in a
	// reason string.
	MaxFindingsInReason = 5

	// MaxReasonTruncateLength is the maximum length of a reason string
	// before truncation in telemetry.
	MaxReasonTruncateLength = 120
)

// --- HTTP transport ---
// Connection pool settings for the shared provider HTTP client.

const (
	// ProviderMaxIdleConns is the maximum idle connections in the provider
	// HTTP client pool.
	ProviderMaxIdleConns = 20

	// ProviderMaxIdleConnsPerHost is the per-host idle connection limit.
	ProviderMaxIdleConnsPerHost = 10

	// ProviderIdleConnTimeout is the idle connection timeout.
	ProviderIdleConnTimeout = 90 * time.Second
)

// --- Read-loop stderr queue ---

const (
	// ReadLoopStderrQueueSize is the channel buffer size for the async
	// stderr drain used by the WebSocket read loop.
	ReadLoopStderrQueueSize = 2048
)

// --- Severity ranking ---
// severityRank maps severity labels to numeric ranks for comparison.

var severityRank = map[string]int{
	"NONE":     0,
	"LOW":      1,
	"MEDIUM":   2,
	"HIGH":     3,
	"CRITICAL": 4,
}

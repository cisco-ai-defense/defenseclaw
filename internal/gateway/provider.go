package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// ChatMessage is the OpenAI-compatible message format used as the canonical
// representation throughout the proxy. Content can be a plain string or an
// array of content blocks ([{"type":"text","text":"..."}]).
type ChatMessage struct {
	Role       string          `json:"role"`
	Content    string          `json:"-"`
	RawContent json.RawMessage `json:"content,omitempty"`
	ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	Name       string          `json:"name,omitempty"`
}

func (m *ChatMessage) UnmarshalJSON(data []byte) error {
	type plain struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content,omitempty"`
		ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
		ToolCallID string          `json:"tool_call_id,omitempty"`
		Name       string          `json:"name,omitempty"`
	}
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	m.Role = p.Role
	m.RawContent = p.Content
	m.ToolCalls = p.ToolCalls
	m.ToolCallID = p.ToolCallID
	m.Name = p.Name

	if len(p.Content) == 0 {
		return nil
	}

	// String content: "hello"
	if p.Content[0] == '"' {
		return json.Unmarshal(p.Content, &m.Content)
	}

	// Array content: [{"type":"text","text":"..."},...]
	if p.Content[0] == '[' {
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(p.Content, &blocks); err != nil {
			m.Content = string(p.Content)
			return nil
		}
		var sb strings.Builder
		for i, b := range blocks {
			// "text" — Chat Completions / Anthropic
			// "input_text" / "output_text" — OpenAI Responses API
			if b.Type == "text" || b.Type == "input_text" || b.Type == "output_text" || b.Type == "" {
				if i > 0 && sb.Len() > 0 {
					sb.WriteString("\n")
				}
				sb.WriteString(b.Text)
			}
		}
		m.Content = sb.String()
		return nil
	}

	m.Content = string(p.Content)
	return nil
}

func (m ChatMessage) MarshalJSON() ([]byte, error) {
	type alias struct {
		Role       string          `json:"role,omitempty"`
		Content    json.RawMessage `json:"content,omitempty"`
		ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
		ToolCallID string          `json:"tool_call_id,omitempty"`
		Name       string          `json:"name,omitempty"`
	}
	a := alias{
		Role:       m.Role,
		ToolCalls:  m.ToolCalls,
		ToolCallID: m.ToolCallID,
		Name:       m.Name,
	}
	if m.RawContent != nil {
		a.Content = m.RawContent
	} else if m.Content != "" {
		c, _ := json.Marshal(m.Content)
		a.Content = c
	}
	return json.Marshal(a)
}

// ChatRequest is the OpenAI-compatible chat completion request body.
// Fields used by the proxy for inspection: Model, Messages, Stream.
// Everything else is pass-through. RawBody carries the original JSON so
// the OpenAI provider can forward unknown fields verbatim.
type ChatRequest struct {
	Model        string          `json:"model"`
	Messages     []ChatMessage   `json:"messages"`
	MaxTokens    *int            `json:"max_tokens,omitempty"`
	Temperature  *float64        `json:"temperature,omitempty"`
	TopP         *float64        `json:"top_p,omitempty"`
	Stream       bool            `json:"stream,omitempty"`
	Stop         json.RawMessage `json:"stop,omitempty"`
	Tools        json.RawMessage `json:"tools,omitempty"`
	ToolChoice   json.RawMessage `json:"tool_choice,omitempty"`
	Fallbacks    []string        `json:"fallbacks,omitempty"` // gateway failover models (e.g. Bifrost)
	ExtraParams  map[string]any  `json:"-"`                   // provider-specific request fields forwarded through Bifrost
	RawBody      json.RawMessage `json:"-"`
	TargetURL    string          `json:"-"` // from X-DC-Target-URL header, set by fetch interceptor (origin only)
	TargetPath   string          `json:"-"` // incoming request path; combined with TargetURL for provider matching
	TargetAPIKey string          `json:"-"` // from Authorization header, forwarded to upstream
}

// ChatChoice is a single choice in an OpenAI chat completion response.
type ChatChoice struct {
	Index        int          `json:"index"`
	Message      *ChatMessage `json:"message,omitempty"`
	Delta        *ChatMessage `json:"delta,omitempty"`
	FinishReason *string      `json:"finish_reason"`
}

// ChatUsage tracks token counts.
type ChatUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// ChatResponse is the OpenAI-compatible chat completion response.
// RawResponse carries the original upstream bytes so the proxy can
// forward unknown fields (system_fingerprint, service_tier, etc.) verbatim.
type ChatResponse struct {
	ID                 string          `json:"id"`
	Object             string          `json:"object"`
	Created            int64           `json:"created"`
	Model              string          `json:"model"`
	Choices            []ChatChoice    `json:"choices"`
	Usage              *ChatUsage      `json:"usage,omitempty"`
	DefenseClawBlocked *bool           `json:"defenseclaw_blocked,omitempty"`
	DefenseClawReason  string          `json:"defenseclaw_reason,omitempty"`
	RawResponse        json.RawMessage `json:"-"`
}

// StreamChunk is one SSE chunk in OpenAI format.
type StreamChunk struct {
	ID                 string       `json:"id"`
	Object             string       `json:"object"`
	Created            int64        `json:"created"`
	Model              string       `json:"model"`
	Choices            []ChatChoice `json:"choices"`
	Usage              *ChatUsage   `json:"usage,omitempty"`
	DefenseClawBlocked *bool        `json:"defenseclaw_blocked,omitempty"`
	DefenseClawReason  string       `json:"defenseclaw_reason,omitempty"`
}

// LLMProvider abstracts the upstream LLM API.
type LLMProvider interface {
	ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
	ChatCompletionStream(ctx context.Context, req *ChatRequest, chunkCb func(StreamChunk)) (*ChatUsage, error)
}

// NewProvider creates an LLM provider adapter based on the model string.
// The model format is "provider/model-name" (e.g. "anthropic/claude-opus-4-5").
// All provider routing and API translation is handled by the Bifrost Go SDK.
func NewProvider(model string, apiKey string) (LLMProvider, error) {
	provider, modelID := splitModel(model)
	if provider == "" {
		provider = inferProvider(modelID, apiKey)
	}

	providerKey, err := mapProviderKey(provider)
	if err != nil {
		return nil, err
	}
	return &bifrostProvider{
		providerKey: providerKey,
		model:       modelID,
		apiKey:      apiKey,
	}, nil
}

// inferProvider detects the provider from the model name or API key format
// when no explicit "provider/" prefix is given.
func inferProvider(model string, apiKey string) string {
	if strings.HasPrefix(apiKey, "ABSK") {
		return "bedrock"
	}
	if strings.HasPrefix(model, "claude") {
		return "anthropic"
	}
	if strings.HasPrefix(apiKey, "sk-ant-") {
		return "anthropic"
	}
	if strings.HasPrefix(model, "gemini") {
		return "gemini"
	}
	if strings.HasPrefix(apiKey, "AIza") {
		return "gemini"
	}
	return "openai"
}

// NewProviderWithBase creates a provider that sends requests to a custom base URL.
// The Bifrost SDK handles all provider-specific API differences (auth headers,
// request format translation, streaming) internally.
func NewProviderWithBase(model string, apiKey string, baseURL string) (LLMProvider, error) {
	if baseURL == "" {
		return NewProvider(model, apiKey)
	}

	baseURL = strings.TrimRight(baseURL, "/")

	provider, modelID := splitModel(model)
	if provider == "" {
		provider = inferProvider(modelID, apiKey)
	}

	providerKey, err := mapProviderKey(provider)
	if err != nil {
		return nil, err
	}
	return &bifrostProvider{
		providerKey: providerKey,
		model:       modelID,
		apiKey:      apiKey,
		baseURL:     baseURL,
	}, nil
}

// NewProviderForInstance constructs a provider by resolving a
// custom-providers.json overlay entry by name. The overlay's
// “base_provider_type“, “base_url“, and per-instance TLS settings
// take precedence over the value inferred from “model“; “apiKey“
// still flows from the resolved :class:`LLMConfig` (whose
// “resolved_api_key()“ reads the overlay's env_keys list).
//
// Returns an “ErrCustomProviderInstanceNotFound“-style error when
// “name“ is non-empty but no overlay entry matches, so callers can
// fall back to :func:`NewProviderWithBase` without silently routing to
// the wrong endpoint.
//
// This shim preserves the legacy four-string API for tests and any
// caller that hasn't yet migrated to the LLMConfig overload. Internally
// it just constructs a transient LLMConfig and delegates.
func NewProviderForInstance(name, model, apiKey string, providers *configs.ProvidersConfig) (LLMProvider, error) {
	if providers == nil {
		return nil, fmt.Errorf("gateway: NewProviderForInstance: providers registry is nil")
	}
	clean := strings.ToLower(strings.TrimSpace(name))
	if clean == "" {
		return nil, fmt.Errorf("gateway: NewProviderForInstance: instance name is empty")
	}
	for i := range providers.Providers {
		if strings.ToLower(providers.Providers[i].Name) == clean {
			llm := &config.LLMConfig{
				Model:        model,
				APIKey:       apiKey,
				InstanceName: clean,
			}
			return buildProviderFromEffective(llm, &providers.Providers[i])
		}
	}
	return nil, fmt.Errorf("gateway: custom-provider instance %q not found in overlay", name)
}

// NewProviderForLLMConfig is the canonical adapter from a resolved
// :type:`config.LLMConfig` to an :type:`LLMProvider`. Precedence is
// role wins, overlay fills blanks:
//
//  1. The LLMConfig is taken as authoritative for every field it sets.
//  2. If “InstanceName“ matches an overlay entry, any LLMConfig field
//     left blank (BaseURL, provider family, TLS, bedrock/vertex/azure
//     sub-blocks) is populated from the overlay entry.
//  3. The merged "effective" config is handed to Bifrost as a single
//     Key + sub-block payload.
//
// “providers“ may be nil; in that case the function silently degrades
// to a vanilla provider so a bootstrap that fails to load the overlay
// still gets a usable provider rather than crashing the gateway.
func NewProviderForLLMConfig(llm *config.LLMConfig, providers *configs.ProvidersConfig) (LLMProvider, error) {
	if llm == nil {
		return nil, fmt.Errorf("gateway: NewProviderForLLMConfig: llm config is nil")
	}
	var inst *configs.Provider
	name := strings.TrimSpace(llm.InstanceName)
	if name != "" && providers != nil {
		clean := strings.ToLower(name)
		for i := range providers.Providers {
			if strings.ToLower(providers.Providers[i].Name) == clean {
				inst = &providers.Providers[i]
				break
			}
		}
		if inst == nil {
			// Fall through with inst=nil so a typo in instance_name
			// surfaces in `defenseclaw doctor` rather than taking
			// the gateway offline. Log so operators can trace
			// silent fallbacks in real time.
			fmt.Fprintf(os.Stderr,
				"[gateway] instance %q not found in overlay; falling back to role-level config\n", name)
		}
	}
	return buildProviderFromEffective(llm, inst)
}

// buildProviderFromEffective performs the role-wins / overlay-fills
// merge and returns a “bifrostProvider“ ready for dispatch. Pulled out
// of NewProviderForLLMConfig so NewProviderForInstance can share the
// same merge logic.
func buildProviderFromEffective(llm *config.LLMConfig, inst *configs.Provider) (LLMProvider, error) {
	model := llm.Model
	apiKey := llm.ResolvedAPIKey()
	baseURL := strings.TrimRight(strings.TrimSpace(llm.BaseURL), "/")
	// Provider type precedence: explicit role config > overlay's
	// base_provider_type > known model prefix > infer. The
	// LLMConfig.Provider field is the only "explicit role family"
	// signal — the prefix in Model can carry a *custom instance
	// name* (e.g. "acme-internal/some-model") which is not a real
	// provider family, so we deliberately do not honor it as a
	// family hint when the overlay has a base_provider_type.
	providerType := strings.ToLower(strings.TrimSpace(llm.Provider))

	// Effective sub-blocks: role wins, overlay fills blanks. Sub-block
	// pointer-nil-ness is treated as "operator did not specify".
	effBedrock := llm.Bedrock
	effVertex := llm.Vertex
	effAzure := llm.Azure
	var tls tlsOverrides
	if llm.TLS != nil {
		tls = tlsOverrides{
			CACertPEM:          llm.TLS.CACertPEM,
			InsecureSkipVerify: llm.TLS.InsecureSkipVerify,
		}
	}

	extraHeaders := llm.ExtraHeaders
	if inst != nil {
		if baseURL == "" {
			baseURL = strings.TrimRight(inst.BaseURL, "/")
		}
		if providerType == "" {
			providerType = inst.BaseProviderType
		}
		if tls.isZero() && inst.TLS != nil {
			tls = tlsOverrides{
				CACertPEM:          inst.TLS.CACertPEM,
				InsecureSkipVerify: inst.TLS.InsecureSkipVerify,
			}
		}
		if len(inst.ExtraHeaders) > 0 && len(extraHeaders) == 0 {
			extraHeaders = inst.ExtraHeaders
		}
		if effBedrock == nil && inst.Bedrock != nil {
			effBedrock = &config.BedrockKeyConfig{
				Region:            inst.Bedrock.Region,
				AuthMode:          inst.Bedrock.AuthMode,
				AccessKeyEnv:      inst.Bedrock.AccessKeyEnv,
				SecretKeyEnv:      inst.Bedrock.SecretKeyEnv,
				SessionTokenEnv:   inst.Bedrock.SessionTokenEnv,
				ProfileName:       inst.Bedrock.ProfileName,
				InferenceProfile:  inst.Bedrock.InferenceProfile,
				DeploymentAliases: inst.Bedrock.DeploymentAliases,
			}
		}
		if effVertex == nil && inst.Vertex != nil {
			effVertex = &config.VertexKeyConfig{
				ProjectID:             inst.Vertex.ProjectID,
				Region:                inst.Vertex.Region,
				AuthMode:              inst.Vertex.AuthMode,
				ServiceAccountJSONEnv: inst.Vertex.ServiceAccountJSONEnv,
			}
		}
		if effAzure == nil && inst.Azure != nil {
			effAzure = &config.AzureKeyConfig{
				Endpoint:          inst.Azure.Endpoint,
				APIVersion:        inst.Azure.APIVersion,
				AuthMode:          inst.Azure.AuthMode,
				DeploymentAliases: inst.Azure.DeploymentAliases,
			}
		}
	}

	if providerType == "" {
		if p, _ := splitModel(model); p != "" {
			providerType = p
		} else {
			providerType = inferProvider(model, apiKey)
		}
	}
	providerKey, err := mapProviderKey(providerType)
	if err != nil {
		return nil, fmt.Errorf("gateway: unsupported provider type %q: %w", providerType, err)
	}

	_, modelID := splitModel(model)
	if modelID == "" {
		modelID = model
	}
	// Bedrock inference_profile injects a region prefix onto the model
	// id before dispatch. Bifrost has no field for it; this is how
	// the role path (--bedrock-inference-profile us.) already works.
	if providerKey == schemas.Bedrock && effBedrock != nil && effBedrock.InferenceProfile != "" {
		if !strings.HasPrefix(modelID, effBedrock.InferenceProfile) {
			modelID = effBedrock.InferenceProfile + modelID
		}
	}

	return &bifrostProvider{
		providerKey:  providerKey,
		model:        modelID,
		apiKey:       apiKey,
		baseURL:      baseURL,
		tls:          tls,
		extraHeaders: extraHeaders,
		bedrock:      effBedrock,
		vertex:       effVertex,
		azure:        effAzure,
	}, nil
}

// knownProviders lists provider prefixes recognized in "provider/model" strings.
var knownProviders = map[string]bool{
	"openai":        true,
	"anthropic":     true,
	"openrouter":    true,
	"azure":         true,
	"gemini":        true,
	"gemini-openai": true,
	"bedrock":       true,
	// amazon-bedrock is OpenClaw's stock provider name for AWS Bedrock; see
	// https://docs.openclaw.ai/providers/bedrock. Both prefixes are accepted
	// and routed to the same Bifrost Bedrock backend via mapProviderKey.
	"amazon-bedrock": true,
	"groq":           true,
	"mistral":        true,
	"ollama":         true,
	"vertex":         true,
	"cohere":         true,
	"perplexity":     true,
	"cerebras":       true,
	"fireworks":      true,
	"xai":            true,
	"huggingface":    true,
	"replicate":      true,
	"vllm":           true,
}

func splitModel(model string) (provider, modelID string) {
	i := strings.IndexByte(model, '/')
	if i < 0 {
		return "", model
	}
	prefix := model[:i]
	if knownProviders[prefix] {
		return prefix, model[i+1:]
	}
	return "", model
}

// compositeModelForUpstream builds the "provider/model" string passed to
// NewProviderWithBase from resolveProviderFromHeaders. When the JSON body
// already uses a known provider prefix (e.g. amazon-bedrock/…, anthropic/…),
// that value is kept verbatim so a URL-derived prefix like "bedrock" is not
// prepended again (which would yield bedrock/amazon-bedrock/… and break
// Bifrost routing for ZeptoClaw + regional Bedrock endpoints).
func compositeModelForUpstream(urlInferredPrefix string, bodyModel string) string {
	if prov, _ := splitModel(bodyModel); prov != "" {
		return bodyModel
	}
	if urlInferredPrefix != "" {
		return urlInferredPrefix + "/" + bodyModel
	}
	return bodyModel
}

// providerHTTPClient is used for passthrough upstream requests in the proxy.
// No client-level Timeout is set because each call site passes a
// context.WithTimeout — a client-level timeout would race with that.
//
// DialContext re-resolves the destination at connect time and refuses
// private / link-local / cloud-metadata / CGNAT / IPv6-ULA targets,
// closing the DNS-rebinding window that the validate-once application
// checks (isPrivateHost / guardUpstreamTargetURL) leave open: a host
// that resolved to a public IP during validation could otherwise rebind
// to 169.254.169.254 (cloud IMDS) or an internal RFC1918 service by the
// time providerHTTPClient.Do actually dials. allowLoopback is true so
// local Ollama (127.0.0.1) and httptest targets keep working; isUnsafeIP
// still blocks every link-local/metadata address regardless of that flag.
var providerHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext:         secureDialContext(true, 10*time.Second),
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// ResolveAPIKey reads the API key from the named environment variable,
// optionally loading a .env file first (for daemon contexts where the
// user's shell env is not inherited).
// Returns "" immediately when local key resolution has been disabled via
// DisableLocalKeyResolution (enterprise credential-management mode).
func ResolveAPIKey(envVar string, dotenvPath string) string {
	if localKeyResolutionDisabled {
		return ""
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	if dotenvPath != "" {
		if dotenv, err := loadDotEnv(dotenvPath); err == nil {
			if v, ok := dotenv[envVar]; ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// isUnsafeIP returns true when an IP address points at a destination
// the gateway must refuse to dial: loopback, link-local, multicast,
// the private RFC1918 ranges, IPv6 ULA, ECS metadata, and the CGNAT
// space. Mirrors the dial-side guard so isPrivateHost (shape.go) and
// the dial guard share one predicate, closing the application-check
// vs dial-resolution split documented inline at the call site.
func isUnsafeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Hardcoded deny: loopback, link-local (includes 169.254.x.x cloud
	// metadata), multicast, unspecified are never allowed regardless of
	// operator allowlist.
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() {
		return true
	}
	// Operator allowlist: specific private IPs that are explicitly trusted.
	if netguard.IsAllowedPrivateIP(ip) {
		return false
	}
	if ip.IsPrivate() {
		return true
	}
	// CGNAT: 100.64.0.0/10
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	// IPv6 ULA: fc00::/7
	if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
		return true
	}
	return false
}

// passthroughAllowPrivateForTest is a test-only seam letting the
// passthrough integration tests simulate a "known provider" pointed
// at httptest.NewServer (which binds 127.0.0.1). Production code MUST
// leave this at false; the dedicated SSRF tests still route private
// targets through the shape-branch which is not subject to this gate.
var passthroughAllowPrivateForTest bool

// secureDialContext returns a DialContext that re-resolves the
// destination at dial time and rejects private/loopback/link-local/
// cloud-metadata IPs (closes F-1306 DNS rebinding). When
// allowLoopback is true, loopback destinations are permitted (used
// for test webhooks pointing at httptest.Server).
func secureDialContext(allowLoopback bool, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if isUnsafeIP(ip.IP) {
				if allowLoopback && ip.IP.IsLoopback() {
					continue
				}
				return nil, fmt.Errorf("secureDialContext: refusing dial to %s (resolved to unsafe IP %s)", host, ip.IP)
			}
		}
		// Use the first safe IP literal so we don't re-resolve and
		// give an attacker a second chance to return a private IP.
		for _, ip := range ips {
			if !isUnsafeIP(ip.IP) || (allowLoopback && ip.IP.IsLoopback()) {
				return d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			}
		}
		return nil, fmt.Errorf("secureDialContext: no safe IP for %s", host)
	}
}

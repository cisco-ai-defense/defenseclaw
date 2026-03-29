package sandbox

// Endpoint represents a network endpoint with host and port.
type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// KnownChannelEndpoints maps OpenClaw channel names to their required network endpoints.
// Used by the policy diff tool to detect missing policy entries.
var KnownChannelEndpoints = map[string][]Endpoint{
	"telegram": {
		{Host: "**.telegram.org", Port: 443},
	},
	"slack": {
		{Host: "**.slack.com", Port: 443},
		{Host: "hooks.slack.com", Port: 443},
	},
	"discord": {
		{Host: "**.discord.com", Port: 443},
		{Host: "gateway.discord.gg", Port: 443},
	},
}

// KnownLLMProviderEndpoints maps LLM provider names to their API endpoints.
var KnownLLMProviderEndpoints = map[string][]Endpoint{
	"openai": {
		{Host: "api.openai.com", Port: 443},
	},
	"anthropic": {
		{Host: "api.anthropic.com", Port: 443},
	},
	"google": {
		{Host: "generativelanguage.googleapis.com", Port: 443},
	},
}

package providers

import (
	"net"
	"strings"
	"sync"
)

type Provider struct {
	Name    string
	Domains []string
}

type Registry struct {
	mu        sync.RWMutex
	providers []Provider
	domainSet map[string]string // domain → provider name
}

func NewRegistry() *Registry {
	r := &Registry{
		domainSet: make(map[string]string),
	}
	r.loadDefaults()
	return r
}

func (r *Registry) loadDefaults() {
	defaults := []Provider{
		{Name: "anthropic", Domains: []string{
			"api.anthropic.com",
		}},
		{Name: "openai", Domains: []string{
			"api.openai.com",
		}},
		{Name: "google", Domains: []string{
			"generativelanguage.googleapis.com",
		}},
		{Name: "azure-openai", Domains: []string{
			".openai.azure.com",
		}},
		{Name: "bedrock", Domains: []string{
			".bedrock-runtime.amazonaws.com",
			".bedrock.amazonaws.com",
		}},
		{Name: "ollama", Domains: []string{
			"localhost:11434",
			"127.0.0.1:11434",
		}},
		{Name: "mistral", Domains: []string{
			"api.mistral.ai",
		}},
		{Name: "cohere", Domains: []string{
			"api.cohere.com",
		}},
		{Name: "groq", Domains: []string{
			"api.groq.com",
		}},
		{Name: "together", Domains: []string{
			"api.together.xyz",
		}},
		{Name: "fireworks", Domains: []string{
			"api.fireworks.ai",
		}},
		{Name: "deepseek", Domains: []string{
			"api.deepseek.com",
		}},
		{Name: "openrouter", Domains: []string{
			"openrouter.ai",
		}},
		{Name: "perplexity", Domains: []string{
			"api.perplexity.ai",
		}},
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers = defaults
	for _, p := range defaults {
		for _, d := range p.Domains {
			r.domainSet[d] = p.Name
		}
	}
}

func (r *Registry) MatchHost(host string) (providerName string, matched bool) {
	h := strings.ToLower(host)
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Exact match first (includes host:port entries).
	if name, ok := r.domainSet[strings.ToLower(host)]; ok {
		return name, true
	}
	if name, ok := r.domainSet[h]; ok {
		return name, true
	}

	// Suffix match for wildcard domains (entries starting with ".").
	for domain, name := range r.domainSet {
		if strings.HasPrefix(domain, ".") && strings.HasSuffix(h, domain) {
			return name, true
		}
	}

	return "", false
}

func (r *Registry) AddProvider(name string, domains []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers = append(r.providers, Provider{Name: name, Domains: domains})
	for domain := range domains {
		r.domainSet[domains[domain]] = name
	}
}

func (r *Registry) Providers() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Provider, len(r.providers))
	copy(out, r.providers)
	return out
}

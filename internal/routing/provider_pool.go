// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"fmt"
	"os"
	"sync"
)

// ResolvedProvider holds the resolved endpoint details for a backend.
type ResolvedProvider struct {
	Model    string
	Provider string
	BaseURL  string
	APIKey   string
}

// ProviderPool resolves and caches model backends.
type ProviderPool struct {
	backends map[string]ModelBackend
	cache    map[string]*ResolvedProvider
	mu       sync.RWMutex
}

// NewProviderPool creates a pool from model backends.
func NewProviderPool(models []ModelBackend) *ProviderPool {
	backends := make(map[string]ModelBackend, len(models))
	for _, m := range models {
		backends[m.Name] = m
	}
	return &ProviderPool{
		backends: backends,
		cache:    make(map[string]*ResolvedProvider),
	}
}

// Get resolves a backend by name, caching the result.
func (p *ProviderPool) Get(name string) (*ResolvedProvider, error) {
	p.mu.RLock()
	if cached, ok := p.cache[name]; ok {
		p.mu.RUnlock()
		return cached, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	if cached, ok := p.cache[name]; ok {
		return cached, nil
	}

	backend, ok := p.backends[name]
	if !ok {
		return nil, fmt.Errorf("unknown backend %q", name)
	}

	var apiKey string
	if backend.APIKeyEnv != "" {
		apiKey = os.Getenv(backend.APIKeyEnv)
	}

	resolved := &ResolvedProvider{
		Model:    backend.Model,
		Provider: backend.Provider,
		BaseURL:  backend.BaseURL,
		APIKey:   apiKey,
	}
	p.cache[name] = resolved
	return resolved, nil
}

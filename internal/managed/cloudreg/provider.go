// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package cloudreg is the OSS-safe registration point for cloud
// credential providers used by managed_enterprise deployments.
//
// It exposes a narrow Provider interface (Token / Refresh / Invalidate)
// and a Register/New pair. The default OSS build ships without a
// registered factory — Sidecar callers therefore see
// ErrNoProviderRegistered when managed_enterprise mode is enabled on an
// OSS binary, which is the intended fail-closed behavior.
//
// Managed release builds pass -tags cmid, which pulls in the sibling
// file provider_cisco.go. That file's release-time content imports the
// private cloud auth module and registers its Provider in an init().
// No OSS build ever imports that private module — the file in the OSS
// tree is a no-op stub.
package cloudreg

import (
	"context"
	"errors"
	"sync"
)

// Provider is the credential source consumed by the sidecar's managed
// inspection client.
type Provider interface {
	// Token returns the currently cached bearer token, fetching one on
	// first use.
	Token(ctx context.Context) (string, error)
	// Refresh forces a fresh fetch, bypassing the cache.
	Refresh(ctx context.Context) error
	// Invalidate drops the cached token; the next Token call re-fetches.
	// Call this on HTTP 401 from the consuming API.
	Invalidate()
}

// Config is the per-instance settings passed by the sidecar to whatever
// factory has been registered. LibPath is optional; a nil / empty value
// means "use whatever default the factory defines."
type Config struct {
	LibPath string
}

// Factory produces a Provider for the given Config. Factories are
// installed via Register during package init in a build-tagged file.
type Factory func(cfg Config) (Provider, error)

// ErrNoProviderRegistered is returned by New when the running binary
// was built without any cloud provider registered — i.e. the standard
// OSS build.
var ErrNoProviderRegistered = errors.New("cloudreg: no cloud credential provider registered — this build was compiled without managed-cloud support")

var (
	mu      sync.RWMutex
	factory Factory
)

// Register installs f as the single active factory. Later calls replace
// earlier ones. Intended to be called from an init() in a build-tagged
// file (e.g. provider_cisco.go under //go:build cmid).
func Register(f Factory) {
	mu.Lock()
	defer mu.Unlock()
	factory = f
}

// New constructs a Provider using the registered factory. Returns
// ErrNoProviderRegistered when no factory has been installed.
func New(cfg Config) (Provider, error) {
	mu.RLock()
	f := factory
	mu.RUnlock()
	if f == nil {
		return nil, ErrNoProviderRegistered
	}
	return f(cfg)
}

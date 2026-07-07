// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// URLKind identifies a URL returned by cmid_get_url. Values match the
// cmid_url_type_e enum defined in the CMIDAPI header.
type URLKind int32

const (
	URLKindEvent   URLKind = 1
	URLKindCheckin URLKind = 2
	URLKindCatalog URLKind = 3
)

// Provider yields identity + endpoint values sourced from the Cisco Cloud
// Management module. All methods are safe for concurrent use.
type Provider interface {
	// Token returns the cached CMID-bound token, refreshing if none is cached.
	Token(ctx context.Context) (string, error)
	// BusinessID returns the cached opaque business identifier.
	BusinessID(ctx context.Context) (string, error)
	// URL returns the requested service URL, refreshing if none is cached.
	URL(ctx context.Context, kind URLKind) (string, error)
	// Refresh forces a fresh fetch from the underlying library.
	Refresh(ctx context.Context) error
	// Invalidate drops the in-memory cache; the next Token/BusinessID/URL
	// call will trigger a Refresh. Callers should invoke this when the
	// cloud rejects the current token (e.g. HTTP 401).
	Invalidate()
}

// Sentinel errors. Wrapped errors returned by Provider methods can be
// checked with errors.Is.
var (
	// ErrUnsupportedPlatform indicates the library is not available on
	// this GOOS. This is a permanent condition; do not retry.
	ErrUnsupportedPlatform = errors.New("cmid: unsupported platform")

	// ErrNotAvailable indicates the library or a required value could not
	// be loaded / found (e.g. the dylib path does not exist, or the API
	// reported CMID_RES_NOT_INITED). May resolve after the Cisco agent
	// finishes initializing.
	ErrNotAvailable = errors.New("cmid: not available")

	// ErrInvalidArg indicates a programming error in this package
	// (CMID_RES_INVALID_ARG). Not user-actionable.
	ErrInvalidArg = errors.New("cmid: invalid argument")

	// ErrAgentUnavailable indicates the local Cisco cloud-management
	// agent could not be reached (CMID_RES_AGENT_ERROR) or its cloud
	// link is broken (CMID_RES_CLOUD_ERROR). Retryable.
	ErrAgentUnavailable = errors.New("cmid: agent unavailable")

	// ErrCloudFailure indicates the cloud rejected the refresh request
	// (CMID_RES_CLOUD_FAILURE). Not immediately retryable — usually
	// signals an enrollment / identity problem.
	ErrCloudFailure = errors.New("cmid: cloud failure")
)

// Config is the config-file mirror of the runtime provider settings. It is
// deliberately a subset of internal/config.CloudAuthConfig so this package
// stays free of a dependency on the top-level config type.
type Config struct {
	// LibPath overrides the OS-default library path. Empty falls back to
	// the DEFENSECLAW_CMID_LIB_PATH env var, then the OS default.
	LibPath string
}

// Options carry runtime knobs supplied by the caller (as opposed to
// user-facing config).
type Options struct {
	// Logger receives diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
	// Now is used for sleep computation in tests. Defaults to time.Now.
	Now func() time.Time
	// Sleep waits for d or until ctx is cancelled. Defaults to
	// context-aware time.Sleep. Overridden in tests.
	Sleep func(ctx context.Context, d time.Duration) error
	// newCallerFn allows tests to substitute the OS-specific caller.
	// Only set from _test.go files.
	newCallerFn func(path string) (caller, error)
}

// Option mutates Options in a NewProvider call.
type Option func(*Options)

// WithLogger overrides the default slog.Logger.
func WithLogger(l *slog.Logger) Option {
	return func(o *Options) {
		if l != nil {
			o.Logger = l
		}
	}
}

// WithSleep replaces the sleep implementation. Intended for tests.
func WithSleep(fn func(ctx context.Context, d time.Duration) error) Option {
	return func(o *Options) {
		if fn != nil {
			o.Sleep = fn
		}
	}
}

// NewProvider constructs a Provider for the current platform.
//
// On darwin the provider binds libcmidapi.dylib via purego at Refresh time.
// On windows a stub returns ErrUnsupportedPlatform (real binding lives in
// a follow-up). On other OSes the provider always returns
// ErrUnsupportedPlatform.
//
// NewProvider never dlopens the library — that happens lazily on the first
// Refresh so callers can construct a provider even on hosts where the
// Cisco Cloud Management module is not installed, and only fail if/when
// the cloud client actually needs a token.
func NewProvider(cfg Config, opts ...Option) Provider {
	options := Options{
		Logger: slog.Default(),
		Now:    time.Now,
		Sleep:  contextAwareSleep,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Sleep == nil {
		options.Sleep = contextAwareSleep
	}
	newCaller := options.newCallerFn
	if newCaller == nil {
		newCaller = newLibCaller
	}
	path := resolveLibPath(cfg)
	return &libProvider{
		path:      path,
		newCaller: newCaller,
		log:       options.Logger,
		sleep:     options.Sleep,
		urls:      map[URLKind]string{},
	}
}

// resolveLibPath picks the effective library path in the documented
// precedence: explicit config > env override > OS default.
func resolveLibPath(cfg Config) string {
	if p := strings.TrimSpace(cfg.LibPath); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv(managed.CMIDLibPathEnv)); p != "" {
		return p
	}
	return defaultLibPath
}

func contextAwareSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

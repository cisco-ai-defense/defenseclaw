// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrLibraryUnavailable is returned by every DeferredProvider operation
// until the Cloud Management identity library can be located and
// validated. It is a "not yet" answer, never a permanent one: the next
// call re-attempts discovery.
//
// The broker reports this to the gateway as an ordinary provider error,
// so managed inspection stays fail-closed while the library is missing
// rather than silently allowing traffic.
var ErrLibraryUnavailable = errors.New(
	"the Cloud Management identity library is not available yet",
)

// DefaultRediscoveryInterval throttles the directory walk that looks for
// a late-arriving library. Discovery is a handful of ReadDir calls, but
// it sits behind every hook decision, so a failed attempt is not
// repeated more often than this.
const DefaultRediscoveryInterval = 15 * time.Second

// DeferredProviderConfig wires a DeferredProvider to its discovery,
// trust, and construction steps. Every step is injected so this file
// carries no Windows-only dependency and its tests run on any platform.
type DeferredProviderConfig struct {
	// PinnedLibraryPath is the path the installer recorded, when it
	// found one. It is preferred over discovery for as long as it still
	// passes Validate; a Cloud Management upgrade that moves the
	// version-nested tree out from under the pin falls back to
	// discovery rather than wedging on a dead path.
	PinnedLibraryPath string
	// Discover locates the newest installed library, returning "" when
	// Cloud Management has not landed yet.
	Discover func() string
	// Validate applies the deployment's path-trust rules to a candidate.
	// A discovered path is loaded into the broker's service account, so
	// it faces exactly the same checks as an installer-pinned one.
	Validate func(path string) error
	// Construct builds the real provider for a validated path.
	Construct func(path string) (Provider, error)
	// OnResolved, when set, is called once each time a library is
	// adopted, for the broker's log.
	OnResolved func(path string)
	// RediscoveryInterval overrides DefaultRediscoveryInterval.
	RediscoveryInterval time.Duration
	// now overrides the clock in tests.
	now func() time.Time
}

// DeferredProvider is a Provider that resolves its underlying library
// lazily, so the broker service can start and stay running before Cloud
// Management is installed.
//
// Windows needs this even though the CMID module already retries its own
// LoadLibrary on every call: that retry is pinned to one immutable path,
// and the path cannot be known at install time. Secure Client nests the
// library under two version directories
// (CM\<ver>\CMID\<ver>\<arch>\cmidapi.dll) that move on its own upgrade
// schedule, and the module's built-in default points at the flat
// CM\cmidapi.dll location instead. Re-running discovery is what turns a
// missing library into a recoverable state.
type DeferredProvider struct {
	discover  func() string
	validate  func(string) error
	construct func(string) (Provider, error)
	notify    func(string)
	// interval throttles failed resolution attempts.
	interval time.Duration
	now      func() time.Time

	mu           sync.Mutex
	inner        Provider
	resolvedPath string
	pinnedPath   string
	lastAttempt  time.Time
	attempted    bool
}

// NewDeferredProvider validates the configuration and returns a provider
// that is immediately usable, whether or not the library exists yet.
func NewDeferredProvider(config DeferredProviderConfig) (*DeferredProvider, error) {
	if config.Discover == nil {
		return nil, errors.New("cmid broker deferred provider requires a discovery function")
	}
	if config.Validate == nil {
		return nil, errors.New("cmid broker deferred provider requires a validation function")
	}
	if config.Construct == nil {
		return nil, errors.New("cmid broker deferred provider requires a construction function")
	}
	interval := config.RediscoveryInterval
	if interval <= 0 {
		interval = DefaultRediscoveryInterval
	}
	clock := config.now
	if clock == nil {
		clock = time.Now
	}
	return &DeferredProvider{
		discover:   config.Discover,
		validate:   config.Validate,
		construct:  config.Construct,
		notify:     config.OnResolved,
		interval:   interval,
		now:        clock,
		pinnedPath: config.PinnedLibraryPath,
	}, nil
}

// Available reports whether a library has been adopted. The broker uses
// this for its startup log line only; callers must not gate requests on
// it, because resolution is retried inside every operation.
func (provider *DeferredProvider) Available() bool {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.inner != nil
}

// ResolvedPath reports the adopted library path, or "" when none has
// been adopted yet.
func (provider *DeferredProvider) ResolvedPath() string {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.resolvedPath
}

// Token resolves the library if needed, then delegates.
func (provider *DeferredProvider) Token(ctx context.Context) (string, error) {
	inner, err := provider.ensure()
	if err != nil {
		return "", err
	}
	token, err := inner.Token(ctx)
	if err != nil {
		provider.dropIfLibraryVanished()
		return "", err
	}
	return token, nil
}

// Refresh resolves the library if needed, then delegates.
func (provider *DeferredProvider) Refresh(ctx context.Context) error {
	inner, err := provider.ensure()
	if err != nil {
		return err
	}
	if err := inner.Refresh(ctx); err != nil {
		provider.dropIfLibraryVanished()
		return err
	}
	return nil
}

// Invalidate drops the cached token when a provider exists. With no
// library yet there is no token to drop, so this is a no-op — reporting
// an error would turn a successful 401 recovery into a broker failure.
func (provider *DeferredProvider) Invalidate() {
	provider.mu.Lock()
	inner := provider.inner
	provider.mu.Unlock()
	if inner != nil {
		inner.Invalidate()
	}
}

// ensure returns the underlying provider, resolving one on first use and
// re-attempting on later calls while the library is still missing.
func (provider *DeferredProvider) ensure() (Provider, error) {
	inner, adopted, err := provider.resolve()
	if err != nil {
		return nil, err
	}
	// Announce outside the lock. OnResolved is caller-supplied, so it may
	// legitimately call Available or ResolvedPath — which take the same
	// non-reentrant mutex — and it may block on a log write that no other
	// token request should be made to wait behind.
	if adopted != "" && provider.notify != nil {
		provider.notify(adopted)
	}
	return inner, nil
}

// resolve returns the underlying provider and, when this call is the one
// that adopted it, the path to announce. Only the adopting caller gets a
// non-empty path back, so concurrent callers still produce exactly one
// announcement per adoption.
//
// It holds provider.mu for its whole body, which does mean the injected
// discover, validate, and construct steps run locked. That is deliberate:
// serializing them collapses a concurrent burst into a single directory
// walk, and none of the three has any reason to read this provider's state.
// OnResolved is the opposite case — it is an observer, so it is the one
// callback a caller may reasonably expect to be able to query. It is
// invoked from ensure after the unlock for exactly that reason.
func (provider *DeferredProvider) resolve() (Provider, string, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.inner != nil {
		return provider.inner, "", nil
	}
	// Throttle only repeat failures. The first call always tries, so a
	// broker that starts after Cloud Management is already installed
	// serves its very first request.
	now := provider.now()
	if provider.attempted && now.Sub(provider.lastAttempt) < provider.interval {
		return nil, "", ErrLibraryUnavailable
	}
	provider.attempted = true
	provider.lastAttempt = now

	path := provider.selectPathLocked()
	if path == "" {
		return nil, "", ErrLibraryUnavailable
	}
	inner, err := provider.construct(path)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrLibraryUnavailable, err)
	}
	if inner == nil {
		return nil, "", ErrLibraryUnavailable
	}
	provider.inner = inner
	provider.resolvedPath = path
	return inner, path, nil
}

// selectPathLocked picks the library to load: the installer's pin while
// it still validates, otherwise a freshly discovered one. Returns "" when
// nothing trustworthy is on disk. Caller must hold provider.mu.
func (provider *DeferredProvider) selectPathLocked() string {
	if provider.pinnedPath != "" && provider.validate(provider.pinnedPath) == nil {
		return provider.pinnedPath
	}
	discovered := provider.discover()
	if discovered == "" {
		return ""
	}
	if provider.validate(discovered) != nil {
		return ""
	}
	return discovered
}

// dropIfLibraryVanished releases the adopted provider when its library
// is no longer on a trusted path, so the next operation re-discovers.
// A Cloud Management upgrade retires the version directory the current
// provider dlopened; without this the broker would keep calling into a
// path that can never succeed again.
//
// Operation failures that are not about the library (an offline agent,
// a cloud transport error) leave the provider in place, because the path
// still validates.
func (provider *DeferredProvider) dropIfLibraryVanished() {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.inner == nil || provider.resolvedPath == "" {
		return
	}
	if provider.validate(provider.resolvedPath) == nil {
		return
	}
	provider.inner = nil
	provider.resolvedPath = ""
	// Let the next call re-resolve immediately: the library moving is a
	// distinct event from a steady-state failure, not something to sit
	// behind the rediscovery throttle.
	provider.attempted = false
}

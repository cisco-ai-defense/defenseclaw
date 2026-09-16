// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubProvider is a Provider whose every call outcome is scripted.
type stubProvider struct {
	mu           sync.Mutex
	token        string
	tokenErr     error
	refreshErr   error
	tokenCalls   int
	refreshCalls int
	invalidated  int
}

func (provider *stubProvider) Token(context.Context) (string, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.tokenCalls++
	return provider.token, provider.tokenErr
}

func (provider *stubProvider) Refresh(context.Context) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.refreshCalls++
	return provider.refreshErr
}

func (provider *stubProvider) Invalidate() {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.invalidated++
}

// deferredHarness scripts discovery, trust, and construction for a
// DeferredProvider and counts how often each step ran.
type deferredHarness struct {
	discovered     string
	trusted        map[string]bool
	inner          *stubProvider
	constructErr   error
	discoverCalls  int
	validateCalls  int
	constructCalls int
	resolved       []string
	clock          time.Time
}

func newDeferredHarness() *deferredHarness {
	return &deferredHarness{
		trusted: map[string]bool{},
		inner:   &stubProvider{token: "bearer"},
		clock:   time.Unix(1_700_000_000, 0),
	}
}

func (harness *deferredHarness) build(t *testing.T, pinned string) *DeferredProvider {
	t.Helper()
	provider, err := NewDeferredProvider(DeferredProviderConfig{
		PinnedLibraryPath: pinned,
		Discover: func() string {
			harness.discoverCalls++
			return harness.discovered
		},
		Validate: func(path string) error {
			harness.validateCalls++
			if harness.trusted[path] {
				return nil
			}
			return errors.New("untrusted path")
		},
		Construct: func(path string) (Provider, error) {
			harness.constructCalls++
			if harness.constructErr != nil {
				return nil, harness.constructErr
			}
			return harness.inner, nil
		},
		OnResolved: func(path string) {
			harness.resolved = append(harness.resolved, path)
		},
		RediscoveryInterval: 15 * time.Second,
		now:                 func() time.Time { return harness.clock },
	})
	if err != nil {
		t.Fatalf("NewDeferredProvider: %v", err)
	}
	return provider
}

// The XDR install order: DefenseClaw installs with no library on disk, so
// the broker must stay serving and answer requests with a retryable error
// until Cloud Management lands — then enable itself with no restart.
func TestDeferredProviderEnablesWhenLibraryArrivesLater(t *testing.T) {
	harness := newDeferredHarness()
	provider := harness.build(t, "")
	ctx := context.Background()

	if _, err := provider.Token(ctx); !errors.Is(err, ErrLibraryUnavailable) {
		t.Fatalf("Token before Cloud Management = %v, want ErrLibraryUnavailable", err)
	}
	if provider.Available() {
		t.Fatal("provider reported available with no library on disk")
	}
	if harness.constructCalls != 0 {
		t.Fatalf("construct ran %d times with no library", harness.constructCalls)
	}

	// Cloud Management installs; the next attempt past the throttle adopts it.
	harness.discovered = `C:\Program Files\Cisco\Cisco Secure Client\CM\5.1.2\CMID\1.0.4\x64\cmidapi.dll`
	harness.trusted[harness.discovered] = true
	harness.clock = harness.clock.Add(16 * time.Second)

	token, err := provider.Token(ctx)
	if err != nil {
		t.Fatalf("Token after Cloud Management arrived: %v", err)
	}
	if token != "bearer" {
		t.Fatalf("token = %q, want %q", token, "bearer")
	}
	if !provider.Available() {
		t.Fatal("provider not available after adopting the library")
	}
	if got := provider.ResolvedPath(); got != harness.discovered {
		t.Fatalf("ResolvedPath = %q, want %q", got, harness.discovered)
	}
	if len(harness.resolved) != 1 || harness.resolved[0] != harness.discovered {
		t.Fatalf("OnResolved = %v, want one entry for the discovered path", harness.resolved)
	}
}

// Repeated failures must not re-walk the Secure Client tree on every hook.
func TestDeferredProviderThrottlesFailedDiscovery(t *testing.T) {
	harness := newDeferredHarness()
	provider := harness.build(t, "")
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := provider.Token(ctx); !errors.Is(err, ErrLibraryUnavailable) {
			t.Fatalf("attempt %d: err = %v, want ErrLibraryUnavailable", i, err)
		}
	}
	if harness.discoverCalls != 1 {
		t.Fatalf("discover ran %d times inside the throttle window, want 1", harness.discoverCalls)
	}

	harness.clock = harness.clock.Add(15 * time.Second)
	if _, err := provider.Token(ctx); !errors.Is(err, ErrLibraryUnavailable) {
		t.Fatalf("err after throttle window = %v, want ErrLibraryUnavailable", err)
	}
	if harness.discoverCalls != 2 {
		t.Fatalf("discover ran %d times, want 2 after the window elapsed", harness.discoverCalls)
	}
}

// A broker started after Cloud Management is already installed must serve
// its very first request rather than waiting out a throttle interval.
func TestDeferredProviderResolvesOnFirstCall(t *testing.T) {
	harness := newDeferredHarness()
	harness.discovered = `C:\cm\cmidapi.dll`
	harness.trusted[harness.discovered] = true
	provider := harness.build(t, "")

	if err := provider.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh on first call: %v", err)
	}
	if harness.inner.refreshCalls != 1 {
		t.Fatalf("inner Refresh calls = %d, want 1", harness.inner.refreshCalls)
	}
}

// Once adopted, the library is not re-discovered on every call.
func TestDeferredProviderCachesResolvedProvider(t *testing.T) {
	harness := newDeferredHarness()
	harness.discovered = `C:\cm\cmidapi.dll`
	harness.trusted[harness.discovered] = true
	provider := harness.build(t, "")
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := provider.Token(ctx); err != nil {
			t.Fatalf("Token %d: %v", i, err)
		}
	}
	if harness.discoverCalls != 1 {
		t.Fatalf("discover ran %d times, want 1", harness.discoverCalls)
	}
	if harness.constructCalls != 1 {
		t.Fatalf("construct ran %d times, want 1", harness.constructCalls)
	}
	if harness.inner.tokenCalls != 3 {
		t.Fatalf("inner Token calls = %d, want 3", harness.inner.tokenCalls)
	}
}

// The installer's pin is preferred while it still validates.
func TestDeferredProviderPrefersPinnedLibrary(t *testing.T) {
	harness := newDeferredHarness()
	pinned := `C:\pinned\cmidapi.dll`
	harness.trusted[pinned] = true
	harness.discovered = `C:\discovered\cmidapi.dll`
	harness.trusted[harness.discovered] = true
	provider := harness.build(t, pinned)

	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got := provider.ResolvedPath(); got != pinned {
		t.Fatalf("ResolvedPath = %q, want the pinned path %q", got, pinned)
	}
	if harness.discoverCalls != 0 {
		t.Fatal("discovery ran even though the pinned path validated")
	}
}

// A Cloud Management upgrade retires the pinned version directory; the
// broker must fall back to discovery instead of wedging on a dead pin.
func TestDeferredProviderFallsBackWhenPinIsStale(t *testing.T) {
	harness := newDeferredHarness()
	pinned := `C:\Program Files\Cisco\Cisco Secure Client\CM\5.1.1\CMID\1.0.3\x64\cmidapi.dll`
	harness.discovered = `C:\Program Files\Cisco\Cisco Secure Client\CM\5.1.2\CMID\1.0.4\x64\cmidapi.dll`
	harness.trusted[harness.discovered] = true // the pin is deliberately absent
	provider := harness.build(t, pinned)

	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got := provider.ResolvedPath(); got != harness.discovered {
		t.Fatalf("ResolvedPath = %q, want the discovered path %q", got, harness.discovered)
	}
}

// Path trust is not weakened by moving discovery to runtime: an untrusted
// discovered path is never handed to the loader.
func TestDeferredProviderRejectsUntrustedDiscoveredPath(t *testing.T) {
	harness := newDeferredHarness()
	harness.discovered = `C:\Users\attacker\cmidapi.dll` // absent from trusted set
	provider := harness.build(t, "")

	if _, err := provider.Token(context.Background()); !errors.Is(err, ErrLibraryUnavailable) {
		t.Fatalf("err = %v, want ErrLibraryUnavailable", err)
	}
	if harness.constructCalls != 0 {
		t.Fatalf("construct ran %d times for an untrusted path, want 0", harness.constructCalls)
	}
}

// A construction failure is retryable, not terminal.
func TestDeferredProviderRetriesAfterConstructionFailure(t *testing.T) {
	harness := newDeferredHarness()
	harness.discovered = `C:\cm\cmidapi.dll`
	harness.trusted[harness.discovered] = true
	harness.constructErr = errors.New("loader busy")
	provider := harness.build(t, "")
	ctx := context.Background()

	err := provider.Refresh(ctx)
	if !errors.Is(err, ErrLibraryUnavailable) {
		t.Fatalf("err = %v, want it to wrap ErrLibraryUnavailable", err)
	}
	if !errors.Is(err, harness.constructErr) {
		t.Fatalf("err = %v, want it to wrap the construction cause", err)
	}

	harness.constructErr = nil
	harness.clock = harness.clock.Add(16 * time.Second)
	if err := provider.Refresh(ctx); err != nil {
		t.Fatalf("Refresh after the loader recovered: %v", err)
	}
}

// A steady-state provider error (offline agent, transport failure) must not
// discard a provider whose library is still present.
func TestDeferredProviderKeepsProviderOnUnrelatedError(t *testing.T) {
	harness := newDeferredHarness()
	harness.discovered = `C:\cm\cmidapi.dll`
	harness.trusted[harness.discovered] = true
	harness.inner.tokenErr = errors.New("agent unavailable")
	provider := harness.build(t, "")
	ctx := context.Background()

	if _, err := provider.Token(ctx); err == nil {
		t.Fatal("Token succeeded despite an inner error")
	}
	if !provider.Available() {
		t.Fatal("provider was dropped even though its library still validates")
	}
	if _, err := provider.Token(ctx); err == nil {
		t.Fatal("Token succeeded despite an inner error")
	}
	if harness.constructCalls != 1 {
		t.Fatalf("construct ran %d times, want 1 — the provider should be reused", harness.constructCalls)
	}
}

// When the loaded library disappears, the next call re-discovers instead of
// calling forever into a path that can no longer succeed.
func TestDeferredProviderRediscoversWhenLibraryVanishes(t *testing.T) {
	harness := newDeferredHarness()
	stale := `C:\Program Files\Cisco\Cisco Secure Client\CM\5.1.1\CMID\1.0.3\x64\cmidapi.dll`
	harness.discovered = stale
	harness.trusted[stale] = true
	provider := harness.build(t, "")
	ctx := context.Background()

	if _, err := provider.Token(ctx); err != nil {
		t.Fatalf("Token: %v", err)
	}

	// Cloud Management upgrades: the loaded path goes away mid-flight.
	harness.inner.tokenErr = errors.New("library handle is stale")
	delete(harness.trusted, stale)
	if _, err := provider.Token(ctx); err == nil {
		t.Fatal("Token succeeded despite an inner error")
	}
	if provider.Available() {
		t.Fatal("provider retained a library that no longer validates")
	}

	// The new tree is adopted immediately — a moved library is not made to
	// wait out the rediscovery throttle.
	fresh := `C:\Program Files\Cisco\Cisco Secure Client\CM\5.1.2\CMID\1.0.4\x64\cmidapi.dll`
	harness.discovered = fresh
	harness.trusted[fresh] = true
	harness.inner.tokenErr = nil
	if _, err := provider.Token(ctx); err != nil {
		t.Fatalf("Token after the library moved: %v", err)
	}
	if got := provider.ResolvedPath(); got != fresh {
		t.Fatalf("ResolvedPath = %q, want %q", got, fresh)
	}
}

// Invalidate must never fail the broker: with no library there is no cached
// token to drop, and a 401 recovery still has to succeed.
func TestDeferredProviderInvalidate(t *testing.T) {
	harness := newDeferredHarness()
	provider := harness.build(t, "")

	provider.Invalidate() // no library yet: must be a silent no-op
	if harness.inner.invalidated != 0 {
		t.Fatalf("inner Invalidate calls = %d, want 0", harness.inner.invalidated)
	}
	if harness.discoverCalls != 0 {
		t.Fatal("Invalidate triggered discovery")
	}

	harness.discovered = `C:\cm\cmidapi.dll`
	harness.trusted[harness.discovered] = true
	harness.clock = harness.clock.Add(16 * time.Second)
	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	provider.Invalidate()
	if harness.inner.invalidated != 1 {
		t.Fatalf("inner Invalidate calls = %d, want 1", harness.inner.invalidated)
	}
}

func TestNewDeferredProviderRequiresItsSteps(t *testing.T) {
	discover := func() string { return "" }
	validate := func(string) error { return nil }
	construct := func(string) (Provider, error) { return &stubProvider{}, nil }

	for name, config := range map[string]DeferredProviderConfig{
		"no discover":  {Validate: validate, Construct: construct},
		"no validate":  {Discover: discover, Construct: construct},
		"no construct": {Discover: discover, Validate: validate},
	} {
		if _, err := NewDeferredProvider(config); err == nil {
			t.Fatalf("%s: NewDeferredProvider succeeded, want an error", name)
		}
	}

	provider, err := NewDeferredProvider(DeferredProviderConfig{
		Discover:  discover,
		Validate:  validate,
		Construct: construct,
	})
	if err != nil {
		t.Fatalf("NewDeferredProvider with every step: %v", err)
	}
	if provider.interval != DefaultRediscoveryInterval {
		t.Fatalf("interval = %s, want the default %s", provider.interval, DefaultRediscoveryInterval)
	}
}

// The server holds providerMu across operations, but Available /
// ResolvedPath are read outside it; keep the provider race-free.
func TestDeferredProviderConcurrentUse(t *testing.T) {
	harness := newDeferredHarness()
	harness.discovered = `C:\cm\cmidapi.dll`
	harness.trusted[harness.discovered] = true
	provider := harness.build(t, "")

	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_ = provider.Available()
			_ = provider.ResolvedPath()
			provider.Invalidate()
		}()
	}
	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	wait.Wait()
}

// runWithDeadline runs a provider operation that must not block. A deadlock
// would otherwise hang until the whole test binary panics, which reports the
// symptom but buries the cause, so name the cause here instead.
func runWithDeadline(t *testing.T, cause string, operation func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- operation() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("operation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal(cause)
	}
}

// Every injected callback is supplied by the caller, so any of them may
// reasonably query the provider they are resolving for. None may be invoked
// under the provider's non-reentrant mutex: the first successful Token would
// deadlock on Available or ResolvedPath.
func TestDeferredProviderInjectedCallbacksMayQueryProvider(t *testing.T) {
	library := `C:\Program Files\Cisco\Cisco Secure Client\CM\5.1.2\CMID\1.0.4\x64\cmidapi.dll`

	for _, callback := range []string{"Discover", "Validate", "Construct", "OnResolved"} {
		t.Run(callback, func(t *testing.T) {
			harness := newDeferredHarness()
			var (
				provider *DeferredProvider
				probed   bool
			)
			// Both accessors take provider.mu.
			probe := func() {
				probed = true
				_ = provider.Available()
				_ = provider.ResolvedPath()
			}

			config := DeferredProviderConfig{
				Discover:  func() string { return library },
				Validate:  func(string) error { return nil },
				Construct: func(string) (Provider, error) { return harness.inner, nil },
				now:       func() time.Time { return harness.clock },
			}
			switch callback {
			case "Discover":
				config.Discover = func() string { probe(); return library }
			case "Validate":
				config.Validate = func(string) error { probe(); return nil }
			case "Construct":
				config.Construct = func(string) (Provider, error) { probe(); return harness.inner, nil }
			case "OnResolved":
				config.OnResolved = func(string) { probe() }
			}

			provider, err := NewDeferredProvider(config)
			if err != nil {
				t.Fatalf("NewDeferredProvider: %v", err)
			}
			runWithDeadline(t, callback+" deadlocked: it ran while holding provider.mu", func() error {
				_, tokenErr := provider.Token(context.Background())
				return tokenErr
			})
			if !probed {
				t.Fatalf("%s never ran, so this test proved nothing", callback)
			}
		})
	}
}

// OnResolved is an observer, so what it sees has to be the committed state
// rather than a half-written one.
func TestDeferredProviderOnResolvedObservesCommittedState(t *testing.T) {
	harness := newDeferredHarness()
	harness.discovered = `C:\Program Files\Cisco\Cisco Secure Client\CM\5.1.2\CMID\1.0.4\x64\cmidapi.dll`
	harness.trusted[harness.discovered] = true

	var (
		provider      *DeferredProvider
		seenAvailable bool
		seenPath      string
	)
	provider, err := NewDeferredProvider(DeferredProviderConfig{
		Discover:  func() string { return harness.discovered },
		Validate:  func(string) error { return nil },
		Construct: func(string) (Provider, error) { return harness.inner, nil },
		OnResolved: func(string) {
			seenAvailable = provider.Available()
			seenPath = provider.ResolvedPath()
		},
		now: func() time.Time { return harness.clock },
	})
	if err != nil {
		t.Fatalf("NewDeferredProvider: %v", err)
	}
	runWithDeadline(t, "Token deadlocked: OnResolved ran while holding provider.mu", func() error {
		_, tokenErr := provider.Token(context.Background())
		return tokenErr
	})

	if !seenAvailable {
		t.Fatal("OnResolved saw Available() == false; adoption was not committed before the callback")
	}
	if seenPath != harness.discovered {
		t.Fatalf("OnResolved saw ResolvedPath() = %q, want %q", seenPath, harness.discovered)
	}
}

// Validate runs on the drop path too, when an operation fails and the
// adopted library is re-checked. That call site must not hold mu either.
func TestDeferredProviderValidateMayQueryProviderWhileDropping(t *testing.T) {
	harness := newDeferredHarness()
	library := `C:\Program Files\Cisco\Cisco Secure Client\CM\5.1.1\CMID\1.0.3\x64\cmidapi.dll`

	var (
		provider *DeferredProvider
		vanished bool
	)
	provider, err := NewDeferredProvider(DeferredProviderConfig{
		Discover: func() string { return library },
		Validate: func(string) error {
			_ = provider.Available()
			_ = provider.ResolvedPath()
			if vanished {
				return errors.New("library is gone")
			}
			return nil
		},
		Construct: func(string) (Provider, error) { return harness.inner, nil },
		now:       func() time.Time { return harness.clock },
	})
	if err != nil {
		t.Fatalf("NewDeferredProvider: %v", err)
	}
	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}

	// Cloud Management upgrades out from under the adopted path.
	harness.inner.tokenErr = errors.New("library handle is stale")
	vanished = true
	runWithDeadline(t, "Token deadlocked: Validate ran while holding provider.mu on the drop path", func() error {
		if _, tokenErr := provider.Token(context.Background()); tokenErr == nil {
			return errors.New("Token succeeded despite an inner error")
		}
		return nil
	})
	if provider.Available() {
		t.Fatal("provider retained a library that no longer validates")
	}
}

// Resolution runs unlocked, so the re-check under resolveMu is the only
// thing that still collapses a concurrent burst into one adoption. Drop it
// and the queued callers either each dlopen their own handle, or — once the
// first one has recorded the attempt — get turned away by the rediscovery
// throttle and answer ErrLibraryUnavailable for a library that is present
// and already adopted. Both are regressions; which one shows up is a matter
// of timing, so assert the invariant that rules out either.
func TestDeferredProviderResolvesOnceUnderConcurrentBurst(t *testing.T) {
	harness := newDeferredHarness()
	library := `C:\Program Files\Cisco\Cisco Secure Client\CM\5.1.2\CMID\1.0.4\x64\cmidapi.dll`

	var discovers, constructs atomic.Int64
	provider, err := NewDeferredProvider(DeferredProviderConfig{
		Discover: func() string {
			discovers.Add(1)
			// Widen the window a serialized implementation would close for
			// free, so a missing re-check actually loses the race.
			time.Sleep(10 * time.Millisecond)
			return library
		},
		Validate: func(string) error { return nil },
		Construct: func(string) (Provider, error) {
			constructs.Add(1)
			return harness.inner, nil
		},
		now: func() time.Time { return harness.clock },
	})
	if err != nil {
		t.Fatalf("NewDeferredProvider: %v", err)
	}

	var wait sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if _, tokenErr := provider.Token(context.Background()); tokenErr != nil {
				errs <- tokenErr
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for tokenErr := range errs {
		t.Fatalf("Token in burst: %v", tokenErr)
	}

	if got := constructs.Load(); got != 1 {
		t.Fatalf("construct ran %d times for a concurrent burst, want 1", got)
	}
	if got := discovers.Load(); got != 1 {
		t.Fatalf("discover ran %d times for a concurrent burst, want 1", got)
	}
}

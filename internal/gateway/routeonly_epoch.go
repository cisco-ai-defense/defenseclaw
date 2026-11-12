// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"maps"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// routeEpochPlatform says whether managed route credentials carry the
// gateway-owned route epoch: Windows, whose lifecycle does not rotate the
// per-user credential key (S1 DESIGN 19). Replaceable in tests.
var routeEpochPlatform = runtime.GOOS == "windows"

// routeEpochState is the route rotation of a managed Windows gateway. The
// gateway starts a new epoch each time it owns its API port (rotate), so a
// route credential another account captured while it held the port during
// a restart stops at once; and it bumps the generation of an account whose
// enrollment for a route-capable connector ended and came back (observe),
// so a credential from before the gap stops too. Unlike the Unix lifecycle
// key rotation (enterpriseunix/rotation.go) nothing keeps the replaced key:
// the guardian re-renders the agent files from the published epoch.
type routeEpochState struct {
	dataDir func() string
	write   func(dataDir string, epoch connector.RouteEpoch) error

	mu      sync.Mutex
	epoch   *connector.RouteEpoch
	version uint64
	// seen and present hold identity 0 connector pairs: every pair enrolled
	// at some point under this epoch, and the pairs enrolled now.
	seen    map[string]bool
	present map[string]bool
	// dirty marks an epoch the last write could not publish.
	dirty bool
}

func newRouteEpochState(dataDir func() string) *routeEpochState {
	return &routeEpochState{dataDir: dataDir, write: connector.WriteRouteEpoch, seen: map[string]bool{}}
}

// rotate starts a new epoch and publishes it.
func (s *routeEpochState) rotate() error {
	if s == nil {
		return nil
	}
	fresh, err := connector.NewRouteEpoch()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch = &fresh
	s.version++
	s.seen = maps.Clone(s.present)
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	return s.publishLocked()
}

// observe records the route enrollments of the current ledger and bumps
// the generation of each account whose enrollment came back.
func (s *routeEpochState) observe(present map[string]bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch == nil {
		s.present = present
		return
	}
	next := *s.epoch
	next.Generations = maps.Clone(s.epoch.Generations)
	if next.Generations == nil {
		next.Generations = map[string]int{}
	}
	changed := false
	for pair := range present {
		if s.seen[pair] && !s.present[pair] {
			identity, _, _ := strings.Cut(pair, "\x00")
			next.Generations[identity]++
			changed = true
		}
		s.seen[pair] = true
	}
	s.present = present
	if changed {
		s.epoch = &next
		s.version++
		s.dirty = true
	}
	if s.dirty {
		_ = s.publishLocked()
	}
}

// snapshot returns the current epoch (nil before the first rotation) and
// its version.
func (s *routeEpochState) snapshot() (*connector.RouteEpoch, uint64) {
	if s == nil {
		return nil, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch == nil {
		return nil, s.version
	}
	copy := *s.epoch
	copy.Generations = maps.Clone(s.epoch.Generations)
	return &copy, s.version
}

func (s *routeEpochState) publishLocked() error {
	dir := strings.TrimSpace(s.dataDir())
	if dir == "" || s.epoch == nil {
		s.dirty = s.epoch != nil
		return nil
	}
	if err := s.write(dir, *s.epoch); err != nil {
		// The in-memory epoch stays the authority: the old credentials stay
		// refused, and the guardian renders once a later write lands.
		s.dirty = true
		fmt.Fprintf(os.Stderr, "[sidecar-api] route epoch not published (route-only callers are refused until it is): %v\n", err)
		return err
	}
	s.dirty = false
	return nil
}

// rotateRouteEpoch runs when this gateway owns its API port: a managed
// Windows gateway starts a new route epoch, so every route credential from
// before (including one captured by another account that held the port
// while the gateway restarted) is refused from the first request on.
func (a *APIServer) rotateRouteEpoch() {
	if !a.userScopedCredentialsRequired() {
		return
	}
	store := a.userScopedCredentialStore()
	if store == nil || store.routeEpoch == nil {
		return
	}
	if err := store.routeEpoch.rotate(); err == nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] route epoch rotated: route-only credentials from before this start are refused\n")
	}
	store.invalidate()
}

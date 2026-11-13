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
	load    func(dataDir string) (*connector.RouteEpoch, error)

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
	return &routeEpochState{dataDir: dataDir, write: connector.WriteRouteEpoch, load: connector.LoadRouteEpoch, seen: map[string]bool{}}
}

// start runs each time the gateway owns its API port. A normal restart
// keeps the published epoch, so running agents keep their rendered route
// credential (S1 REVIEW-code-slice4 P2-3). A new epoch starts when the
// port was held by another process while the gateway restarted (a
// credential sent to it is refused from the first request on), and when
// no trusted, valid published epoch exists. It reports whether it rotated.
func (s *routeEpochState) start(portWasHeld bool) (bool, error) {
	if s == nil {
		return false, nil
	}
	if !portWasHeld && s.adoptPublished() {
		return false, nil
	}
	return true, s.rotate()
}

// adoptPublished keeps the epoch this process already has, or takes the
// one an earlier gateway run published; false when there is none.
func (s *routeEpochState) adoptPublished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch != nil {
		return true
	}
	dir := strings.TrimSpace(s.dataDir())
	if dir == "" || s.load == nil {
		return false
	}
	published, err := s.load(dir)
	if err != nil || published == nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar-api] published route epoch not used (a new one starts): %v\n", err)
		}
		return false
	}
	s.epoch = published
	if s.epoch.Generations == nil {
		s.epoch.Generations = map[string]int{}
	}
	s.version++
	s.seen = maps.Clone(s.present)
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	s.dirty = false
	return true
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

// startRouteEpoch runs when this gateway owns its API port. A managed
// Windows gateway keeps its published route epoch across a normal restart
// and starts a new one when the bind found the port held during the
// restart (portWasHeld: the Windows bind-owner check
// isAPIPortHeldByAnotherAccount or an address in use), so a route
// credential sent to whoever held the port is refused from the first
// request on. The kernel SID factor already refuses that credential for
// any other account (decideWindowsRouteCaller); the rotation is defence
// in depth. Enrollment return bumps the account generation (observe).
func (a *APIServer) startRouteEpoch(portWasHeld bool) {
	if !a.userScopedCredentialsRequired() {
		return
	}
	store := a.userScopedCredentialStore()
	if store == nil || store.routeEpoch == nil {
		return
	}
	rotated, err := store.routeEpoch.start(portWasHeld)
	switch {
	case rotated && err == nil && portWasHeld:
		fmt.Fprintf(os.Stderr, "[sidecar-api] route epoch rotated: the API port was held by another process during the restart; route-only credentials from before are refused\n")
	case rotated && err == nil:
		fmt.Fprintf(os.Stderr, "[sidecar-api] route epoch started: no published epoch to keep\n")
	}
	store.invalidate()
}

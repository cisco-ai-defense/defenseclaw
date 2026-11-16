// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// namedGroupIDs resolves every distinct assignment group name. A failed or
// timed-out lookup fails the whole answer; a partial group list must never
// select a profile. Names with @ cannot name a macOS group and are skipped.
func namedGroupIDs(ctx context.Context, names []string, lookup func(context.Context, string) (int, bool, error)) ([]int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	seen := map[string]bool{}
	var unique []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		key := strings.ToLower(name)
		if name == "" || strings.Contains(name, "@") || seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, name)
	}
	ids := make([]int, len(unique))
	found := make([]bool, len(unique))
	g, groupCtx := errgroup.WithContext(ctx)
	g.SetLimit(16)
	for i, name := range unique {
		if err := groupCtx.Err(); err != nil {
			if waitErr := g.Wait(); waitErr != nil {
				return nil, waitErr
			}
			return nil, err
		}
		i, name := i, name
		g.Go(func() error {
			gid, ok, err := lookup(groupCtx, name)
			if err != nil {
				return fmt.Errorf("unixidentity: look up group %q: %w", name, err)
			}
			ids[i], found[i] = gid, ok
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []int
	for i, gid := range ids {
		if found[i] {
			out = append(out, gid)
		}
	}
	return out, nil
}

// namedGroupMemoryTTL is how long an assignment group name that resolved keeps
// its gid after the directory stops naming it.
const namedGroupMemoryTTL = 15 * time.Minute

// namedGroupMemory remembers the gid each assignment group name last resolved
// to. Open Directory answers "no such group" also while part of a bound
// directory does not answer, and nothing in that answer says so: the group
// was dropped from a successful answer and a looser profile could match
// (GAP-0592). A name that resolved within namedGroupMemoryTTL keeps its gid,
// so the uid membership check still decides whether the account is in the
// group; a name that never resolved, or has not resolved for longer than the
// TTL (deleted or renamed in the directory), is gone. A failed lookup stays a
// failure.
type namedGroupMemory struct {
	now  func() time.Time
	mu   sync.Mutex
	gids map[string]rememberedNamedGroup
}

type rememberedNamedGroup struct {
	gid int
	at  time.Time
}

// lookup wraps a named group lookup with the memory.
func (m *namedGroupMemory) lookup(next func(context.Context, string) (int, bool, error)) func(context.Context, string) (int, bool, error) {
	return func(ctx context.Context, name string) (int, bool, error) {
		gid, ok, err := next(ctx, name)
		if err != nil {
			return gid, ok, err
		}
		key := strings.ToLower(strings.TrimSpace(name))
		now := m.now()
		m.mu.Lock()
		defer m.mu.Unlock()
		if ok {
			if m.gids == nil {
				m.gids = map[string]rememberedNamedGroup{}
			}
			m.gids[key] = rememberedNamedGroup{gid: gid, at: now}
			return gid, true, nil
		}
		if known, found := m.gids[key]; found {
			if age := now.Sub(known.at); age >= 0 && age < namedGroupMemoryTTL {
				return known.gid, true, nil
			}
			delete(m.gids, key)
		}
		return 0, false, nil
	}
}

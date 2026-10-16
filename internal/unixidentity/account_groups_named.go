// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"fmt"
	"strings"

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

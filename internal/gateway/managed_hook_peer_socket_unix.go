// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"os"
	"time"
)

// The standalone hook socket (api_uds_unix.go) is a unix socket: these
// helpers bind a connection's kernel-verified caller to its requests and
// read the refused surfaces the unix enumerator publishes.

// withManagedHookConnPeer binds a hook-socket connection's caller, resolved
// on its first request (managedHookConnPeer).
func withManagedHookConnPeer(ctx context.Context, resolve func() managedHookPeer) context.Context {
	return context.WithValue(ctx, managedHookConnPeerContextKey{}, &managedHookConnPeer{resolve: resolve})
}

// newManagedHookRefusedLoader caches the refused-surfaces file like the
// ledger.
func newManagedHookRefusedLoader(path string) *managedHookLedgerLoader {
	return &managedHookLedgerLoader{path: path, ttl: 2 * time.Second, now: time.Now, read: readManagedHookRefusedSurfaces}
}

// readManagedHookRefusedSurfaces reads the refused-surfaces file; a missing
// file means nothing is refused.
func readManagedHookRefusedSurfaces(path string) (managedHookLedger, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return managedHookLedger{}, nil
	}
	return readManagedHookLedger(path)
}

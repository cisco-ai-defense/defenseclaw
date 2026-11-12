// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

func init() {
	ownStatusWindowsAccount = func(sid string) (string, string) {
		account, err := lsaAccountBySID(sid)
		if err != nil {
			return "", ""
		}
		return account.Name, account.Domain
	}
}

// serveOwnStatusPipe answers a standard account's own `defenseclaw status`
// on the own-status pipe of the Windows standalone managed gateway
// (cowork-1-0-8 GAP-0060) until ctx ends. Other profiles, Secure Client
// included, do not serve it. A failure only leaves users without their own
// status; it never affects the API.
func (a *APIServer) serveOwnStatusPipe(ctx context.Context) {
	if _, ok := standaloneManagedServiceAccount(); !ok {
		return
	}
	logged := false
	for ctx.Err() == nil {
		err := refusalpipe.ServeOwnStatus(ctx, func(sid string) []byte {
			return a.ownStatusForWindowsAccount(ctx, sid)
		}, a.windowsAccountExcludedNow)
		if err != nil && !logged {
			fmt.Fprintf(os.Stderr, "[sidecar-api] own-status pipe unavailable, retrying: %v\n", err)
			logged = true
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

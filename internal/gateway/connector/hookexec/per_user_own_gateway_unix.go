// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package hookexec

import (
	"context"
	"net"
	"os"
	"path/filepath"
)

// ownGatewayHoldsQueue reports whether the listener that took a connection to
// server, and never accepted it, is this account's gateway: the process its
// gateway.pid record names, still the same live process (kernel start
// identity), and the only holder of every listening socket on that port. A
// listener of another account, another process of this account (a decoy
// bound to the port), a stale record, or a listener nobody can read is not
// proof.
func ownGatewayHoldsQueue(ctx context.Context, server *net.TCPAddr) bool {
	for _, home := range perUserGatewayHomes(ctx) {
		if pid, ok := recordedGatewayPID(home); ok && listenersHeldOnlyByPID(pid, server) {
			return true
		}
	}
	return false
}

// perUserGatewayHomes names the folders that may hold the record of the
// gateway of the call under ctx: the ones the call named, else this
// account's data folder and the one the environment names.
func perUserGatewayHomes(ctx context.Context) []string {
	if homes, _ := ctx.Value(perUserGatewayHomesKey{}).(func() []string); homes != nil {
		return homes()
	}
	var out []string
	if account := perUserAccountHome(); account != "" {
		out = append(out, filepath.Join(account, ".defenseclaw"))
	}
	if env := os.Getenv("DEFENSECLAW_HOME"); filepath.IsAbs(env) {
		out = append(out, filepath.Clean(env))
	}
	return out
}

// ownerScanSupported is true where a connection that was not accepted gets an
// owner scan of its listener (ownGatewayHoldsQueue), whose answer the connect
// deadline waits for.
const ownerScanSupported = true

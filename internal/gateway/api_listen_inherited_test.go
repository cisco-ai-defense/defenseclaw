// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"strings"
	"testing"
)

// GAP-0963: the macOS plist makes launchd hold the default API address. A
// gateway an administrator moved to another api_port binds that port itself
// instead of failing; on Linux a socket unit that names another address than
// the config still fails closed.
func TestInheritedAPIListenerOnAnotherAddress(t *testing.T) {
	restoreAPI, restoreMismatch := inheritedAPIListener, apiInheritedMismatchBinds
	t.Cleanup(func() { inheritedAPIListener, apiInheritedMismatchBinds = restoreAPI, restoreMismatch })
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	inheritedAPIListener = func() (net.Listener, bool, error) { return held, true, nil }
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	configured := probe.Addr().String()
	_ = probe.Close()
	api := &APIServer{addr: configured}

	apiInheritedMismatchBinds = false
	if listener, err := api.acquireAPIListener(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match configured") {
		if listener != nil {
			_ = listener.Close()
		}
		t.Fatalf("a socket unit on another address = %v, want the mismatch refusal", err)
	}

	apiInheritedMismatchBinds = true
	listener, err := api.acquireAPIListener(context.Background())
	if err != nil {
		t.Fatalf("launchd socket on the default address with another configured port: %v", err)
	}
	defer listener.Close()
	if listener.Addr().String() != configured {
		t.Fatalf("listener %s, want the configured %s", listener.Addr(), configured)
	}

	// The configured address itself is adopted on every platform.
	inheritedAPIListener = func() (net.Listener, bool, error) { return listener, true, nil }
	adopted, err := api.acquireAPIListener(context.Background())
	if err != nil || adopted != listener {
		t.Fatalf("the inherited configured address was not adopted: %v", err)
	}
}

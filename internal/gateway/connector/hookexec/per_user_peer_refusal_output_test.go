// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// Both per-user post transports print this one text after a refused
// listener. It is the diagnosis of a root-run gateway of the calling account,
// found from the folder the shell hook named (a moved store) and the folders
// the account layout records, and nothing for any other failure or listener.
func TestPerUserPeerRefusalOutputFramesOnlyTheRootGatewayDiagnosis(t *testing.T) {
	account := t.TempDir()
	installHome := filepath.Join(account, ".defenseclaw")
	store := filepath.Join(account, "store")
	for _, dir := range []string{installHome, filepath.Join(store, "hooks")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldHome, oldHolder, oldClass := perUserAccountHome, perUserPortHolder, perUserListenerClass
	t.Cleanup(func() { perUserAccountHome, perUserPortHolder, perUserListenerClass = oldHome, oldHolder, oldClass })
	perUserAccountHome = func() string { return account }
	perUserPortHolder = func(string, int) (daemon.PortHolder, error) { return daemon.PortHolder{PID: 1234, UID: 0}, nil }
	rootRun := true
	perUserListenerClass = func(_ string, _ int, home string, _ daemon.PortHolder, _ error, _ bool) daemon.PerUserListenerClass {
		if rootRun && home == installHome {
			return daemon.PerUserListenerOwnGatewayRunAsRoot
		}
		return daemon.PerUserListenerForeign
	}
	refused := fmt.Errorf("%w: connected gateway socket belongs to another account", errPerUserPeerUnverified)
	const addr = "127.0.0.1:19100"

	want := "DCPOSTROOT1:" + daemon.RootGatewayListenerReason + " " + daemon.RootGatewayListenerRemedy(installHome)
	for _, dir := range []string{installHome, store} {
		if got := PerUserPeerRefusalOutput(refused, addr, dir); got != want {
			t.Fatalf("folder %s: output %q, want %q", dir, got, want)
		}
	}
	if got := PerUserPeerRefusalOutput(errors.New("connection refused"), addr, store); got != "" {
		t.Fatalf("an error that is not a refused listener printed %q", got)
	}
	if got := PerUserPeerRefusalOutput(nil, addr, store); got != "" {
		t.Fatalf("no error printed %q", got)
	}
	rootRun = false
	if got := PerUserPeerRefusalOutput(refused, addr, store); got != "" {
		t.Fatalf("a listener that is no root gateway of this account printed %q", got)
	}
}

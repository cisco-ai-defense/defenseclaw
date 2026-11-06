//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The installer verifies the registration under both host probe capabilities.
// The no-probe path needs the newly rendered script's persisted digest, while
// a host with a contained probe still verifies after the same seal step.
func TestGAP0083HermesInstallSealsBeforeRegistrationReadback(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)

	for _, tc := range []struct {
		name           string
		containedProbe bool
	}{
		{name: "contained probe", containedProbe: true},
		{name: "sealed readback", containedProbe: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := newTestHome(t)
			opts := hermesStandaloneOptions(t, home)
			previous := installOwnedHooksPresent
			t.Cleanup(func() { installOwnedHooksPresent = previous })
			var observedSeal bool
			installOwnedHooksPresent = func(conn connector.Connector, setup connector.SetupOpts) (bool, error) {
				if conn.Name() != "hermes" {
					return previous(conn, setup)
				}
				entry := connector.LoadHookContractLockEntry(setup.DataDir, "hermes")
				want := entry.HookScriptDigests["hermes-hook.sh"]
				body, err := os.ReadFile(filepath.Join(setup.DataDir, "hooks", "hermes-hook.sh"))
				if err != nil {
					return false, err
				}
				digest := sha256.Sum256(body)
				observedSeal = want != "" && want == fmt.Sprintf("sha256:%x", digest)
				if !tc.containedProbe {
					return observedSeal, nil
				}
				return true, nil
			}
			if _, err := Install(context.Background(), opts); err != nil {
				t.Fatalf("fresh Hermes Install: %v", err)
			}
			if !observedSeal {
				t.Fatal("registration read-back preceded the persisted script seal")
			}
			if _, err := Verify(context.Background(), opts); err != nil {
				t.Fatalf("Hermes Verify after Install: %v", err)
			}
		})
	}
}

func TestGAP0083RejectedReadbackRestoresFreshInstallLock(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	previous := installOwnedHooksPresent
	t.Cleanup(func() { installOwnedHooksPresent = previous })
	var observedSeal bool
	installOwnedHooksPresent = func(conn connector.Connector, setup connector.SetupOpts) (bool, error) {
		observedSeal = connector.LoadHookContractLockEntry(setup.DataDir, conn.Name()).HookScriptDigests["hermes-hook.sh"] != ""
		return false, nil
	}
	if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "hook verification failed") {
		t.Fatalf("rejected registration read-back = %v, want install refusal", err)
	}
	if !observedSeal {
		t.Fatal("registration read-back preceded the new lock entry")
	}
	if entry := connector.LoadHookContractLockEntry(filepath.Join(home, ".defenseclaw"), "hermes"); entry.Connector != "" {
		t.Fatalf("failed fresh install retained hook contract entry for %s", entry.Connector)
	}
}

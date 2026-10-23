// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// damageCurrentVersion overwrites config.yaml of the current version
// directory, so the current bundle no longer reads.
func damageCurrentVersion(t *testing.T, b *bundleHost) {
	t.Helper()
	dir := b.env.bundleStore().VersionDir(b.state().Current.Dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, enterprisebundle.ConfigName)
	if err := os.Chmod(config, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("damaged: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The confirmed manifest still proves the release floor when a bundle file
// is damaged. Ensure restores only config bytes matching the deployment
// record; an unsigned --config and a run without that copy are refused.
func TestBundleDamagedCurrentVersionRecoversOnlyCommittedConfig(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, _ := bundleConfigs(b.testHost)
			initial := b.dir(1, v1)
			raw, err := os.ReadFile(filepath.Join(initial, enterprisebundle.ManifestName))
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := enterprisebundle.DecodeManifest(raw)
			if err != nil {
				t.Fatal(err)
			}
			manifest.MinProductVersion = "1.0.0"
			raw, err = manifest.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			sig, err := enterprisebundle.Sign(raw, b.key, "k1")
			if err != nil {
				t.Fatal(err)
			}
			signed, err := sig.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			writeRooted(t, filepath.Join(initial, enterprisebundle.ManifestName), string(raw))
			writeRooted(t, filepath.Join(initial, enterprisebundle.SignatureName), string(signed))
			requireOK(t, b.apply(initial))
			installed := b.read(b.env.Layout.ConfigPath)
			damageCurrentVersion(t, b)
			if err := b.env.BundleProductFloorRefusal("0.8.10"); errorCode(err, "") != codeProductFloor {
				t.Fatalf("damaged config lowered the signed release floor: %v", err)
			}
			edited := installed + "\n# an unsigned edit\n"
			writeRooted(t, b.env.P(b.env.Layout.ConfigPath), edited)

			r := b.run(Options{Action: ActionEnsure})
			requireOK(t, r)
			if !hasWarning(r, codeBundleStateUnreadable) {
				t.Fatalf("warnings = %+v", r.Warnings)
			}
			if got := b.read(b.env.Layout.ConfigPath); got != installed {
				t.Fatalf("ensure did not restore the committed config:\n%s", got)
			}
			other := filepath.Join(t.TempDir(), "config.yaml")
			writeRooted(t, other, v2)
			requireError(t, b.run(Options{Action: ActionEnsure, ConfigFile: other}), codeBundleStateUnreadable)

			if err := os.Remove(b.env.committedConfigPath()); err != nil {
				t.Fatal(err)
			}
			writeRooted(t, b.env.P(b.env.Layout.ConfigPath), edited)
			from := len(b.services.calls)
			requireError(t, b.run(Options{Action: ActionEnsure}), codeBundleStateUnreadable)
			if gatewayTouched(b.testHost, from) {
				t.Fatal("a run with no verified config touched the gateway")
			}
			requireOK(t, b.apply(b.dir(2, v2)))
		})
	}
}

// A deferred inbox bundle is retried: the run keeps it and the lower
// versions in the inbox and writes no superseded receipt; the next run
// without --defer-restart takes it and supersedes the lower one.
func TestBundleInboxDeferredRestartKeepsTheInbox(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, restart := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	var inbox []string
	for version, cfg := range map[uint64]string{2: v2, 3: restart} {
		var buf bytes.Buffer
		if err := enterprisebundle.WriteArchive(&buf, b.signed(version, cfg)); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(b.env.bundleInboxDir(), fmt.Sprintf("v%d.dcbundle", version))
		writeRooted(t, path, buf.String())
		inbox = append(inbox, path)
	}

	b.env.DeferRestart = true
	r := b.run(Options{Action: ActionEnsure, BundleInbox: true})
	requireError(t, r, string(enterprisebundle.CodeRestartDeferred))
	if r.ExitCode != enterprisestatus.BusyExitCode(b.env.GOOS) {
		t.Fatalf("exit %d, want the retry exit", r.ExitCode)
	}
	for _, path := range inbox {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("a deferred inbox run removed %s: %v", filepath.Base(path), err)
		}
	}
	receipts, err := b.env.bundleStore().Receipts()
	if err != nil {
		t.Fatal(err)
	}
	for _, rc := range receipts {
		if rc.BundleID == bundleID(2) {
			t.Fatalf("a deferred inbox run gave the lower version a receipt: %+v", rc)
		}
	}

	b.env.DeferRestart = false
	requireOK(t, b.run(Options{Action: ActionEnsure, BundleInbox: true}))
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(3) {
		t.Fatalf("state after the retry = %+v", st)
	}
	if rc := b.receipt(bundleID(2)); rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeSuperseded {
		t.Fatalf("lower inbox version receipt = %+v", rc)
	}
	for _, path := range inbox {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("the inbox kept %s after the retry: %v", filepath.Base(path), err)
		}
	}
}

// A repeated delivery of the current bundle over an installed config that
// drifted in a restart-required setting is deferred with --defer-restart
// before any transaction; without the flag it restores the bundle config.
func TestBundleRepeatedDeliveryDefersARestartForDrift(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, _, restart := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			current := b.dir(2, restart)
			requireOK(t, b.apply(current))
			installed := b.read(b.env.Layout.ConfigPath)
			drifted := strings.Replace(installed, "  hook_self_heal: false\n", "", 1)
			if drifted == installed {
				t.Fatal("the restart bundle config has no hook_self_heal line")
			}
			writeRooted(t, b.env.P(b.env.Layout.ConfigPath), drifted)

			b.env.DeferRestart = true
			from := len(b.services.calls)
			r := b.apply(current)
			requireError(t, r, string(enterprisebundle.CodeRestartDeferred))
			if r.ExitCode != enterprisestatus.BusyExitCode(goos) {
				t.Fatalf("exit %d, want the retry exit", r.ExitCode)
			}
			if b.read(b.env.Layout.ConfigPath) != drifted || gatewayTouched(b.testHost, from) {
				t.Fatal("a deferred repeat changed the config or touched the gateway")
			}
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(2) {
				t.Fatalf("current = %+v", st.Current)
			}

			b.env.DeferRestart = false
			requireOK(t, b.apply(current))
			if b.read(b.env.Layout.ConfigPath) != installed {
				t.Fatal("the repeat without --defer-restart did not restore the bundle config")
			}
		})
	}
}

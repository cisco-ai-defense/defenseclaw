//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// rel-1-0-6:GAP-0036: Windows ensure takes --device-group (Setup
// DEVICEGROUP=) with --trust-anchors and installs the anchors pinned to that
// one group, as `enterprise bundle anchors install --device-group` does on
// Linux and macOS; a group alone or a malformed one is refused before
// anything changes.
func TestWindowsEnsureDeviceGroupPinsTheInstalledTrustAnchors(t *testing.T) {
	stubWindowsBundleHost(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	dst := filepath.Join(t.TempDir(), "trust", enterprisebundle.AnchorsName)
	if _, _, err := installWindowsBundleAnchorsPinned(e.anchors, dst, "eng"); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := enterprisebundle.DecodeAnchors(written)
	if err != nil || len(pinned.DeviceGroups) != 1 || pinned.DeviceGroups[0] != "eng" {
		t.Fatalf("installed anchors %+v (%v), want device_groups [eng]", pinned, err)
	}

	ensure := newWindowsEnterpriseLifecycleCommand("ensure")
	if ensure.Flags().Lookup("device-group") == nil || ensure.Flags().Lookup("device-group").Hidden {
		t.Fatal("ensure has no visible --device-group")
	}
	for _, opts := range []windowsEnterpriseLifecycleOptions{
		{deviceGroup: "eng"},
		{deviceGroup: "-eng", trustAnchors: e.anchors},
	} {
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", &opts)
		if !done || err == nil || !strings.Contains(out.String()+err.Error(), "DEVICEGROUP=") {
			t.Fatalf("%+v: done %v, err %v, out %s", opts, done, err, out.String())
		}
	}
}

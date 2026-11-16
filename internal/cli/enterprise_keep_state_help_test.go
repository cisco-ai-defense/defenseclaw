// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestEnterpriseUninstallKeepStateHelpNamesKeptSandboxException(t *testing.T) {
	for _, platform := range []string{"linux", "macos"} {
		t.Run(platform, func(t *testing.T) {
			flag := newUnixLifecycleCommand(platform, "uninstall", "").Flags().Lookup("keep-state")
			if flag == nil {
				t.Fatal("--keep-state is missing")
			}
			goos := map[string]string{"linux": "linux", "macos": "darwin"}[platform]
			layout, err := managed.StandaloneLayoutFor(goos)
			if err != nil {
				t.Fatal(err)
			}
			// The help names each kept path, as the uninstall summary does
			// (GAP-0067).
			store, key, record := layout.KeptSandboxStatePaths()
			for _, phrase := range []string{"sandbox registrations (" + store + ")", "their key (" + key + ")", "sandbox setup record (" + record + ")",
				"while an account keeps sandboxes", "--purge removes those too"} {
				if !strings.Contains(flag.Usage, phrase) {
					t.Errorf("--keep-state help omits %q: %s", phrase, flag.Usage)
				}
			}
			// --keep-state does not keep the deployment record, the snapshots or
			// the pending intent, so the help does not promise lifecycle state
			// (GAP-0643).
			if strings.Contains(flag.Usage, "lifecycle state") || !strings.Contains(flag.Usage, "the deployment record goes either way") {
				t.Errorf("--keep-state help misstates the lifecycle state it keeps: %s", flag.Usage)
			}
			if strings.Contains(flag.Usage, "removes all of it") {
				t.Errorf("--keep-state help promises total removal: %s", flag.Usage)
			}
		})
	}
}

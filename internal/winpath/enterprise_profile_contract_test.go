// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package winpath_test

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// winpath cannot import internal/managed, so it mirrors the profile
// contract; this test keeps the copies identical.
func TestEnterpriseProfileContractMatchesManaged(t *testing.T) {
	if winpath.EnterpriseProfileEnv != managed.EnterpriseProfileEnv {
		t.Fatalf("profile env %q != %q", winpath.EnterpriseProfileEnv, managed.EnterpriseProfileEnv)
	}
	if winpath.EnterpriseProfileSecureClient != managed.ProfileSecureClient ||
		winpath.EnterpriseProfileStandalone != managed.ProfileStandalone {
		t.Fatal("winpath profile names drifted from internal/managed")
	}
	layout, err := managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := winpath.EnterpriseRootsFor(winpath.EnterpriseProfileStandalone, `C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	if layout.InstallRoot != roots.InstallRoot || layout.HookSocketDir != roots.ManagedIPCDir {
		t.Fatalf("standalone layout %+v disagrees with roots %+v", layout, roots)
	}
	if want := roots.StateRoot + `\etc\config.yaml`; layout.ConfigPath != want {
		t.Fatalf("standalone config %q, want %q", layout.ConfigPath, want)
	}
}

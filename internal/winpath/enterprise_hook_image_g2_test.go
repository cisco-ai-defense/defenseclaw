// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"strings"
	"testing"
)

func TestResolveEnterpriseHookLaunchSetLegacyReadsNoImage(t *testing.T) {
	f := &fakeHookImageFS{}
	f.put(testBin+`\defenseclaw-hook.exe`, fakeHookFile{size: 10, digest: testHookSHA})
	got := ResolveEnterpriseHookLaunchSetWith(f, testBin)
	if got.State != EnterpriseHookImageLegacyLayout || got.Hook != testBin+`\defenseclaw-hook.exe` || got.Guard != "" {
		t.Fatalf("legacy launch set = %+v", got)
	}
	if f.hashes != 0 {
		t.Fatalf("a layout without bin\\hooks read %d image(s); it must cost one Lstat as before", f.hashes)
	}
	f.put(testBin+`\defenseclaw-hook-guard.exe`, fakeHookFile{size: 5, digest: testGuardSHA})
	if got := ResolveEnterpriseHookLaunchSetWith(f, testBin); got.Guard != testBin+`\defenseclaw-hook-guard.exe` {
		t.Fatalf("legacy guard = %q", got.Guard)
	}
}

func TestResolveEnterpriseHookLaunchSetStaged(t *testing.T) {
	got := ResolveEnterpriseHookLaunchSetWith(stagedFS(t), testBin)
	if got.State != EnterpriseHookImageStaged || got.Hook != testBin+`\hooks\0123456789abcdef\defenseclaw-hook.exe` {
		t.Fatalf("staged launch set = %+v", got)
	}
	// A process started from a launch folder resolves itself: its folder
	// has no hooks folder below it.
	self := ResolveEnterpriseHookLaunchSetWith(stagedFS(t), testBin+`\hooks\0123456789abcdef`)
	if self.Hook != testBin+`\hooks\0123456789abcdef\defenseclaw-hook.exe` || self.State != EnterpriseHookImageLegacyLayout {
		t.Fatalf("launch folder self resolve = %+v", self)
	}
}

func TestEnterpriseHookStagingAndBackupNames(t *testing.T) {
	suffix := strings.Repeat("ab", 16)
	if name := EnterpriseHookStagingDirName(strings.ToUpper(suffix)); name != ".staging-"+suffix || !IsEnterpriseHookStagingDirName(name) {
		t.Fatalf("staging name %q", name)
	}
	for _, bad := range []string{".staging-", ".staging-" + suffix + "0", "staging-" + suffix, ".staging-" + strings.Repeat("g", 32), "0123456789abcdef"} {
		if IsEnterpriseHookStagingDirName(bad) {
			t.Errorf("IsEnterpriseHookStagingDirName(%q) accepted", bad)
		}
	}
	for _, good := range []string{"defenseclaw-hook.exe.backup." + suffix, "DefenseClaw-Hook-Guard.exe.backup." + suffix} {
		if !IsEnterpriseHookImageBackupName(good) {
			t.Errorf("IsEnterpriseHookImageBackupName(%q) refused", good)
		}
	}
	for _, bad := range []string{"defenseclaw-hook.exe", "defenseclaw-hook.exe.backup.", "defenseclaw.exe.backup." + suffix, "defenseclaw-hook.exe.backup." + suffix + "x"} {
		if IsEnterpriseHookImageBackupName(bad) {
			t.Errorf("IsEnterpriseHookImageBackupName(%q) accepted", bad)
		}
	}
}

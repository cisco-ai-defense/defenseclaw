// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import "testing"

func TestEnterpriseInstallBinOf(t *testing.T) {
	for _, tc := range []struct {
		path, want string
	}{
		{testBin + `\defenseclaw-gateway.exe`, testBin},
		{testBin + `\defenseclaw.exe`, testBin},
		{testBin + `\defenseclaw-hook.exe`, testBin},
		{testBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`, testBin},
		{testBin + `\hooks\0123456789abcdef\defenseclaw-hook-guard.exe`, testBin},
		// Only the hook launch set lives in a launch folder.
		{testBin + `\hooks\0123456789abcdef\defenseclaw-gateway.exe`, ""},
		{testBin + `\hooks\defenseclaw-hook.exe`, ""},
		{`C:\Program Files\Cisco\DefenseClaw\libexec\defenseclaw.exe`, ""},
		{`C:\bin`, ""},
		{`bin\defenseclaw.exe`, ""},
		{"", ""},
	} {
		if got := EnterpriseInstallBinOf(tc.path); got != tc.want {
			t.Errorf("EnterpriseInstallBinOf(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestSameEnterpriseHookImageFamilyExact(t *testing.T) {
	fixed := testBin + `\defenseclaw-hook.exe`
	launch := testBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	older := testBin + `\hooks\aaaaaaaaaaaaaaaa\defenseclaw-hook.exe`
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{fixed, launch, true},
		{older, launch, true},
		// A recorded path keeps its exact spelling.
		{`C:\PROGRAM FILES\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, launch, false},
		{testBin + `\DefenseClaw-Hook.exe`, launch, false},
		{testBin + `/hooks/aaaaaaaaaaaaaaaa/defenseclaw-hook.exe`, launch, false},
		{testBin + `\hooks\aaaaaaaaaaaaaaaa\defenseclaw-hook-guard.exe`, launch, false},
		{`C:\Other\bin\defenseclaw-hook.exe`, launch, false},
	} {
		if got := SameEnterpriseHookImageFamilyExact(tc.a, tc.b); got != tc.want {
			t.Errorf("SameEnterpriseHookImageFamilyExact(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestSameEnterpriseHookImageDirFamily(t *testing.T) {
	if !SameEnterpriseHookImageDirFamily(testBin, testBin+`\hooks\0123456789abcdef`) ||
		!SameEnterpriseHookImageDirFamily(testBin+`\hooks\aaaaaaaaaaaaaaaa`, testBin+`\hooks\0123456789abcdef`) {
		t.Fatal("launch folders of one bin are one family")
	}
	if SameEnterpriseHookImageDirFamily(`C:\Other\bin`, testBin) ||
		SameEnterpriseHookImageDirFamily(testBin+`\hooks`, testBin) ||
		SameEnterpriseHookImageDirFamily(testBin+`\lib`, testBin) {
		t.Fatal("a folder outside the launch set family was admitted")
	}
}

func TestEnterpriseHookImagePathsIn(t *testing.T) {
	launch := testBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	fixed := testBin + `\defenseclaw-hook.exe`
	text := `"C:\Windows\System32\cmd.exe" /d /s /c ""` + launch + `" hook --connector codex"; & '` + fixed + `' 'hook'; ` +
		`D:\elsewhere\notes\defenseclaw-hook.exe.txt; x:defenseclaw-hook.exe`
	got := EnterpriseHookImagePathsIn(text)
	if len(got) != 2 || got[0] != launch || got[1] != fixed {
		t.Fatalf("EnterpriseHookImagePathsIn = %q", got)
	}
	if got := EnterpriseHookImagePathsIn("no paths here"); len(got) != 0 {
		t.Fatalf("EnterpriseHookImagePathsIn(no paths) = %q", got)
	}
}

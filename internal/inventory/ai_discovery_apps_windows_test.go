// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"slices"
	"strings"
	"testing"
)

func TestWindowsPackageIdentityNameAcceptsOnlyPathFreeAppUserModelIDs(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: `OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0!App`, want: "package-id:OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0"},
		{value: `shell:AppsFolder\Claude_abcdefghjkmnp!Claude`, want: "package-id:Claude_abcdefghjkmnp"},
		{value: `shell:::{4234D49B-0245-4DF3-B780-3893943456E1}\Jan_8wekyb3d8bbwe!Jan`, want: "package-id:Jan_8wekyb3d8bbwe"},
		{value: `::{4234d49b-0245-4df3-b780-3893943456e1}\GPT4All_8wekyb3d8bbwe!App`, want: "package-id:GPT4All_8wekyb3d8bbwe"},
		{value: `OpenAI.Codex_2p2nqsd0c76g0!Codex`, want: "package-id:OpenAI.Codex_2p2nqsd0c76g0"},
		{value: `C:\Program Files\ChatGPT\ChatGPT.exe`, want: ""},
		{value: `https://example.invalid/ChatGPT`, want: ""},
		{value: `OpenAI.ChatGPT_8wekyb3d8bbwe`, want: ""},
		{value: `OpenAI.ChatGPT_8wekyb3d8bbwe!`, want: ""},
		{value: `OpenAI.ChatGPT_8wekyb3d8bbwe!App!Other`, want: ""},
		{value: `OpenAI.Chat GPT_8wekyb3d8bbwe!App`, want: ""},
		{value: `OpenAI.ChatGPT_short!App`, want: ""},
		{value: `OpenAI.ChatGPT_8wekyb3d8bbwu!App`, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			if got := windowsPackageIdentityName(tc.value); got != tc.want {
				t.Fatalf("windowsPackageIdentityName(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestCollectWindowsShellApplicationNamesUsesDisplayAndStablePackageIdentity(t *testing.T) {
	identities := []windowsShellApplicationIdentity{
		{DisplayName: "ChatGPT", PackageIdentity: "package-id:OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0"},
		{DisplayName: "Claude", PackageIdentity: "package-id:Claude_abcdefghjkmnp"},
		{DisplayName: "chatgpt"},
		{
			DisplayName:     "package-id:OpenAI.Codex",
			PackageIdentity: "package-id:Unrelated.Package_8wekyb3d8bbwe",
		},
	}
	got := collectWindowsShellApplicationNames(identities, maxWindowsApplicationNames)
	for _, want := range []string{"ChatGPT", "package-id:OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0", "Claude"} {
		if !slices.Contains(got, want) {
			t.Errorf("AppsFolder names missing %q: %v", want, got)
		}
	}
	if slices.Contains(got, `C:\Program Files\ChatGPT\ChatGPT.exe`) {
		t.Fatalf("AppsFolder inventory retained an executable path: %v", got)
	}
	if count := countStringFold(got, "chatgpt"); count != 1 {
		t.Fatalf("case-insensitive display-name count = %d, want 1: %v", count, got)
	}
	if slices.Contains(got, "package-id:OpenAI.Codex") {
		t.Fatalf("package-controlled display name crossed the package identity boundary: %v", got)
	}
	if !slices.Contains(got, "package-id:Unrelated.Package_8wekyb3d8bbwe") {
		t.Fatalf("sanitized package identity missing after spoofed display name: %v", got)
	}
}

func TestWithoutReservedWindowsApplicationNamesProtectsPackageIdentityMarker(t *testing.T) {
	got := withoutReservedWindowsApplicationNames([]string{
		"Cursor",
		" package-id:OpenAI.Codex ",
		"PACKAGE-ID:OpenAI.ChatGPT-Desktop",
	})
	if !slices.Equal(got, []string{"Cursor"}) {
		t.Fatalf("ordinary application names retained a package identity marker: %v", got)
	}
}

func TestWindowsStorePackageIdentitiesMatchBuiltInAISignatures(t *testing.T) {
	signatures, err := LoadAISignatures()
	if err != nil {
		t.Fatalf("LoadAISignatures: %v", err)
	}
	for wantSignatureID, identity := range map[string]string{
		"codex":           "package-id:OpenAI.Codex_2p2nqsd0c76g0",
		"chatgpt-desktop": "package-id:OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0",
	} {
		var matchedSignatureIDs []string
		for _, signature := range signatures {
			for _, applicationName := range signature.ApplicationNames {
				if applicationNameMatches(identity, applicationName) {
					matchedSignatureIDs = append(matchedSignatureIDs, signature.ID)
					break
				}
			}
		}
		if len(matchedSignatureIDs) != 1 || matchedSignatureIDs[0] != wantSignatureID {
			t.Errorf("Store package identity %q matched signatures %v, want only %q", identity, matchedSignatureIDs, wantSignatureID)
		}
	}

	for lookalike, trustedAlias := range map[string]string{
		"package-id:OpenAI.ChatGPT-Desktop_8wekyb3d8bbwe": "package-id:OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0",
		"package-id:Fake.OpenAI.ChatGPT_2p2nqsd0c76g0":    "package-id:OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0",
		"package-id:OpenAI.ChatGPT_2p2nqsd0c76g0":         "package-id:OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0",
		"package-id:OpenAI.Codex_8wekyb3d8bbwe":           "package-id:OpenAI.Codex_2p2nqsd0c76g0",
	} {
		if applicationNameMatches(lookalike, trustedAlias) {
			t.Errorf("Store lookalike %q matched trusted package alias %q", lookalike, trustedAlias)
		}
	}
}

func TestCollectWindowsShellApplicationNamesIsBounded(t *testing.T) {
	identities := make([]windowsShellApplicationIdentity, maxWindowsApplicationNames+32)
	for i := range identities {
		identities[i].DisplayName = strings.Repeat("a", 16) + string(rune(0x1000+i))
	}
	got := collectWindowsShellApplicationNames(identities, maxWindowsApplicationNames+100)
	if len(got) != maxWindowsApplicationNames {
		t.Fatalf("AppsFolder name count = %d, want cap %d", len(got), maxWindowsApplicationNames)
	}
}

func TestCollectWindowsShellApplicationNamesDoesNotStarvePackageIdentities(t *testing.T) {
	const limit = 32
	identities := make([]windowsShellApplicationIdentity, limit)
	for i := range identities {
		identities[i].DisplayName = strings.Repeat("d", i+1)
	}
	identities[len(identities)-1].PackageIdentity = "package-id:OpenAI.Codex_2p2nqsd0c76g0"

	got := collectWindowsShellApplicationNames(identities, limit)
	if len(got) != limit {
		t.Fatalf("AppsFolder name count = %d, want %d: %v", len(got), limit, got)
	}
	if !slices.Contains(got, identities[len(identities)-1].PackageIdentity) {
		t.Fatalf("late package identity was starved by display names: %v", got)
	}
}

func TestWindowsShellApplicationNamesNativeSmokeIsBounded(t *testing.T) {
	identities, err := enumerateWindowsShellApplicationIdentities(8)
	if err != nil {
		t.Fatalf("enumerate native current-user AppsFolder: %v", err)
	}
	if len(identities) > 8 {
		t.Fatalf("native AppsFolder identity count = %d, requested cap 8", len(identities))
	}

	got := windowsShellApplicationNames()
	if len(got) > maxWindowsApplicationNames {
		t.Fatalf("native AppsFolder name count = %d, cap %d", len(got), maxWindowsApplicationNames)
	}
	for _, name := range got {
		if strings.TrimSpace(name) == "" {
			t.Fatalf("native AppsFolder returned an empty name: %v", got)
		}
	}
}

func countStringFold(values []string, want string) int {
	count := 0
	for _, value := range values {
		if strings.EqualFold(value, want) {
			count++
		}
	}
	return count
}

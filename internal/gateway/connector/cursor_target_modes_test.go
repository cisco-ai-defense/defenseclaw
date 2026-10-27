// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestWindowsCursorLegacyAdapterByteIdentity(t *testing.T) {
	// Captured from the preceding v9 renderer. Protected legacy policies hash
	// exact bytes; changing their template would break upgrade and rollback.
	// Hash the actual adapter: normalizing it here would conceal CRLF embedded
	// by a Windows checkout and permit an incompatible gateway build.
	for mode, want := range map[string]string{
		"open":   "4cf85a72a4a999f724a534bd2cc576f5365159e22d3e645dd068110ad940ede6",
		"closed": "150a2721dc97a703a038b52cd7d7bf4a27da6e5b55b79af72f565ed963600917",
	} {
		current, err := RenderWindowsCursorEnterpriseAdapter(testWindowsHookBinary, mode)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(current)
		if got := hex.EncodeToString(digest[:]); got != want {
			t.Fatalf("legacy %s adapter hash=%s want=%s", mode, got, want)
		}
	}
}

func TestWindowsCursorEmbeddedTemplateUsesCanonicalLF(t *testing.T) {
	template, err := hookFS.ReadFile("hooks/cursor-hook.ps1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsRune(template, '\r') {
		t.Fatal("embedded Cursor template contains CR; rebuild from an LF checkout")
	}
}

func TestWindowsCursorTargetModesCanonicalAdapter(t *testing.T) {
	modes := map[string]string{"S-1-5-21-1000-1000-1000-1001": "closed", "S-1-5-21-1000-1000-1000-1002": "open"}
	adapter, err := RenderWindowsCursorEnterpriseAdapterForTargets(testWindowsHookBinary, modes)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsRune(adapter, '\r') {
		t.Fatal("mapped Cursor adapter contains CR; its identity would differ across platforms")
	}
	decoded, err := WindowsCursorEnterpriseAdapterTargetModes(adapter, testWindowsHookBinary)
	if err != nil || !reflect.DeepEqual(decoded, modes) {
		t.Fatalf("decoded=%v err=%v", decoded, err)
	}
	for _, marker := range []string{"$failMode = 'closed'", "if ($null -eq $targetMode)", "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value", "$targetModes.PSObject.Properties[$currentSID]", "if ($failMode -ceq 'open')", "WARNING hook fail-open; inspection bypassed connector=cursor", `{"continue":true}`, `"permission":"deny"`} {
		if !bytes.Contains(adapter, []byte(marker)) {
			t.Errorf("missing %q", marker)
		}
	}
	reordered, err := RenderWindowsCursorEnterpriseAdapterForTargets(testWindowsHookBinary, map[string]string{"S-1-5-21-1000-1000-1000-1002": "open", "S-1-5-21-1000-1000-1000-1001": "closed"})
	if err != nil || !bytes.Equal(adapter, reordered) {
		t.Fatal("target order changes canonical adapter")
	}
	for name, changed := range map[string][]byte{
		"appended script":       append(append([]byte(nil), adapter...), []byte("\nWrite-Output evil")...),
		"changed policy branch": bytes.ReplaceAll(adapter, []byte("$failMode -ceq 'open'"), []byte("$failMode -ne 'closed'")),
		"oversized":             bytes.Repeat([]byte(" "), (1<<20)+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := WindowsCursorEnterpriseAdapterTargetModes(changed, testWindowsHookBinary); err == nil {
				t.Fatal("noncanonical adapter accepted")
			}
		})
	}
	if _, err := WindowsCursorEnterpriseAdapterTargetModes(adapter, `C:\Other\defenseclaw-hook.exe`); err == nil {
		t.Fatal("wrong launcher accepted")
	}
}

func TestWindowsCursorTargetModesRejectInvalidInput(t *testing.T) {
	for _, modes := range []map[string]string{nil, {}, {"S-1-5-21-1": "typo"}, {"S-1-5-21-1': $(evil)": "open"}, {"s-1-5-21-1": "open"}, {strings.Repeat("S-1-", 50): "open"}} {
		if _, err := RenderWindowsCursorEnterpriseAdapterForTargets(testWindowsHookBinary, modes); err == nil {
			t.Fatalf("invalid map accepted: %v", modes)
		}
	}
	for _, mode := range []string{"open", "closed"} {
		legacy, err := RenderWindowsCursorEnterpriseAdapter(testWindowsHookBinary, mode)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(legacy, []byte("targetModesJSON64")) || bytes.Contains(legacy, []byte("WindowsIdentity")) {
			t.Fatal("legacy adapter changed to mapped policy")
		}
		if _, err := WindowsCursorEnterpriseAdapterTargetModes(legacy, testWindowsHookBinary); err == nil {
			t.Fatal("legacy adapter mistaken for mapped adapter")
		}
	}
}

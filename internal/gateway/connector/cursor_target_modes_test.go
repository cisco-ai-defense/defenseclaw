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

func TestWindowsCursorAdapterByteIdentity(t *testing.T) {
	// Pin the current canonical adapter bytes. Protected earlier adapters are
	// upgrade-readable through the recorded digest in their ownership state;
	// reconciliation writes this template before strict verify passes.
	// Hash actual bytes so a CRLF checkout cannot silently change identity.
	for mode, want := range map[string]string{
		"open":   "fff3f22e19f5f22ff3a0c7f68c4d713e1e283b493f48d2e8059db36db064eda4",
		"closed": "5135f7d863ec596641e7c10270409131c8a07c79b9d8ab89823194c92f8978c7",
	} {
		current, err := RenderWindowsCursorEnterpriseAdapter(testWindowsHookBinary, mode)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(current)
		if got := hex.EncodeToString(digest[:]); got != want {
			t.Fatalf("%s adapter hash=%s want=%s", mode, got, want)
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
	for _, marker := range []string{"$failMode = 'closed'", "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value", "$targetModes.PSObject.Properties[$currentSID]", "if ($failMode -ceq 'open')", "open gateway-outage mode does not apply to local Cursor adapter failure", `"permission":"deny"`} {
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

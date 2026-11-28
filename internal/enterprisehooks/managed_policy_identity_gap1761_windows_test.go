//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1761 (RV-1713): the recorded-form renderings warmed before the Claude
// policy transaction lock are reused under it. The render reads the hook
// delivery mode (secureClientHookDelivery), and the cache key left it out,
// so a rendering made for one delivery mode could answer for the other.
// Fails on rel af37fd1338: the second render came from the cache.
func TestGAP1761RecordedRenderCacheKeysOnTheHookDelivery(t *testing.T) {
	setStandaloneProfileForTest(t, false)
	verified, render := connector.SecureClientDeploymentVerified, windowsClaudeRecordedPolicyRender
	t.Cleanup(func() {
		connector.SecureClientDeploymentVerified, windowsClaudeRecordedPolicyRender = verified, render
	})
	delivery := false
	connector.SecureClientDeploymentVerified = func() bool { return delivery }
	windowsClaudeRecordedPolicyRender = func(windowsClaudeManagedPolicyState, string, bool, windowsClaudeRecordedForm) ([]byte, error) {
		return []byte(fmt.Sprintf("secure-client-delivery=%v", secureClientHookDelivery())), nil
	}
	renders := &windowsClaudeRecordedRenders{}
	record := windowsClaudeManagedPolicyState{HookExecutable: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe`, GatewayAddr: "127.0.0.1:18970"}
	first, err := renders.render(record, "claudecode-hooks-v1", true, windowsClaudeFormCurrent)
	if err != nil {
		t.Fatal(err)
	}
	delivery = true
	second, err := renders.render(record, "claudecode-hooks-v1", true, windowsClaudeFormCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatalf("the render cache answered %q for the other hook delivery mode", second)
	}
	again, err := renders.render(record, "claudecode-hooks-v1", true, windowsClaudeFormCurrent)
	if err != nil || !bytes.Equal(again, second) {
		t.Fatalf("the same delivery mode was not served from the cache: %q, %v", again, err)
	}
}

// GAP-1761 (RV-1713): keep is decided on an unlocked read of the drop-in and
// that decision may be used under the lock only for the same bytes. A drop-in
// that read as this deployment's before the lock and was replaced by foreign
// bytes before the lock was taken is asked again, and refused.
func TestGAP1761KeepDecidedBeforeTheLockAsksAgainForForeignBytes(t *testing.T) {
	requireGAP633Elevated(t)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	setStandaloneProfileForTest(t, true)
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	foreign := append(bytes.Clone(current[:len(current)-1]), []byte(" \n")...)
	calls := map[string]int{}
	keep := func(published []byte) bool {
		if bytes.Equal(published, current) {
			calls["current"]++
			return true
		}
		calls["other"]++
		return false
	}
	decided := windowsClaudeKeepDecidedBeforeLock(keep)
	if calls["current"] != 1 {
		t.Fatalf("fixture: the unlocked read did not decide the current drop-in: %v", calls)
	}
	// Under the lock the drop-in now holds foreign bytes.
	if decided(foreign) {
		t.Fatal("a drop-in that changed to foreign bytes after the unlocked read was kept")
	}
	if calls["other"] != 1 {
		t.Fatalf("the foreign bytes were not asked again: %v", calls)
	}
	// The same bytes as the unlocked read are answered from it.
	if !decided(current) || calls["current"] != 1 {
		t.Fatalf("the unchanged drop-in was asked again: %v", calls)
	}
}

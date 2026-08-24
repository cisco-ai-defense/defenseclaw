// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

func TestWindowsManagedHookRuntimeFormattingRedactsScopedToken(t *testing.T) {
	const secret = "must-not-appear-in-diagnostics"
	runtime := WindowsManagedHookRuntime{
		Connector:          "codex",
		DataDir:            `C:\Users\developer\.defenseclaw`,
		PolicyActive:       true,
		Registered:         true,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway-Test",
		ScopedToken:        secret,
		GenerationID:       strings.Repeat("a", 32),
	}
	encoded, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{
		string(encoded),
		fmt.Sprint(runtime),
		fmt.Sprintf("%+v", runtime),
		fmt.Sprintf("%#v", runtime),
	} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("managed runtime diagnostic disclosed scoped token: %s", rendered)
		}
	}
}

func TestVerifyWindowsManagedRuntimeGenerationForInstallDoesNotImpersonate(t *testing.T) {
	t.Setenv(connector.WindowsGatewayServiceNameEnv, "DefenseClawGateway-Test")
	targetSID, err := windows.StringToSid("S-1-5-21-1000-1000-1000-1001")
	if err != nil {
		t.Fatal(err)
	}

	originalVerify := windowsManagedRuntimeGenerationVerify
	originalImpersonation := windowsEnterpriseTargetImpersonation
	var captured WindowsManagedRuntimeGenerationDesired
	windowsManagedRuntimeGenerationVerify = func(
		desired WindowsManagedRuntimeGenerationDesired,
	) error {
		captured = desired
		return nil
	}
	windowsEnterpriseTargetImpersonation = func(*windows.SID, string, func() error) error {
		t.Fatal("read-only managed runtime generation verification attempted target impersonation")
		return nil
	}
	t.Cleanup(func() {
		windowsManagedRuntimeGenerationVerify = originalVerify
		windowsEnterpriseTargetImpersonation = originalImpersonation
	})

	want := WindowsManagedRuntimeGenerationDesired{
		Connector:                  "codex",
		TargetSID:                  targetSID.String(),
		DataDir:                    `C:\Users\developer\.defenseclaw`,
		HookExecutable:             `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`,
		GatewayAddr:                "127.0.0.1:18970",
		GatewayServiceName:         "DefenseClawGateway-Test",
		ScopedToken:                "scoped-test-token",
		HookContractID:             "codex-hooks-v1",
		HookContractLockUpdatedAt:  "2026-08-23T10:00:00Z",
		HookContractEntryUpdatedAt: "2026-08-23T10:00:00Z",
	}
	if err := verifyWindowsManagedRuntimeGenerationForInstall(
		" CoDeX ",
		targetSID,
		want.DataDir,
		want.HookExecutable,
		want.GatewayAddr,
		want.ScopedToken,
		want.HookContractID,
		want.HookContractLockUpdatedAt,
		want.HookContractEntryUpdatedAt,
	); err != nil {
		t.Fatal(err)
	}
	if captured.ScopedToken != want.ScopedToken {
		t.Fatal("privileged verifier did not receive the exact scoped token")
	}
	captured.ScopedToken = ""
	want.ScopedToken = ""
	if !reflect.DeepEqual(captured, want) {
		t.Fatalf("privileged verifier input = %+v, want %+v", captured, want)
	}
}

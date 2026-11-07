// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0044: a CONFIG= change of only the managed_hooks_only lock restarts
// the hook guardian, then the gateway, and runs no transaction. A guardian
// that does not prove the targets puts the previous config back, proves the
// guardian on it, and leaves the change to the transaction; any other
// start-only key still goes to the transaction without a write.
func TestWindowsEnterpriseEnsureRestartsOnlyTheGuardianAndGatewayForTheHooksOnlyLock(t *testing.T) {
	const previous = "config_version: 9\nenterprise:\n  machine_policy:\n    default:\n      managed_hooks_only: enforce\n"
	next := strings.Replace(previous, "enforce", "preserve", 1)
	const key = "enterprise.machine_policy.default.managed_hooks_only"
	stubServices := func(t *testing.T, host *hotConfigHost, guardianErrs ...error) *[]string {
		t.Helper()
		restartSeam, guardianSeam := windowsEnterpriseHotConfigRestart, windowsEnterpriseHotConfigGuardianReconcile
		t.Cleanup(func() {
			windowsEnterpriseHotConfigRestart, windowsEnterpriseHotConfigGuardianReconcile = restartSeam, guardianSeam
		})
		var order []string
		windowsEnterpriseHotConfigRestart = func() (bool, error) { order = append(order, "gateway"); return true, nil }
		windowsEnterpriseHotConfigGuardianReconcile = func(_ context.Context, _ managed.StandaloneLayout, restore bool) error {
			if restore != (len(order) > 0) {
				t.Errorf("guardian reconcile restore=%t after %v", restore, order)
			}
			installed, _ := os.ReadFile(host.configPath)
			order = append(order, "guardian:"+map[bool]string{true: "next", false: "previous"}[string(installed) == host.next])
			if len(guardianErrs) == 0 {
				return nil
			}
			err := guardianErrs[0]
			guardianErrs = guardianErrs[1:]
			return err
		}
		return &order
	}

	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	order := stubServices(t, host)
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
	result := runHotConfigEnsure(t, host, opts, stub)
	if got, _ := os.ReadFile(host.configPath); string(got) != next || len(stub.calls) != 2 || stub.calls[1][1] != "Verify" ||
		fmt.Sprint(*order) != "[guardian:next gateway]" {
		t.Fatalf("narrow restart: config %q, installer runs %q, service order %v", got, stub.calls, *order)
	}
	warnings := fmt.Sprint(result.Warnings)
	if !result.OK || !strings.Contains(warnings, windowsEnterpriseConfigRestartCode) || !strings.Contains(warnings, key) ||
		!strings.Contains(warnings, "restarted the hook guardian and then the gateway") {
		t.Fatalf("narrow restart result: ok=%t warnings %v", result.OK, result.Warnings)
	}

	host, opts = newHotConfigHost(t, previous, next)
	host.adopted = true
	order = stubServices(t, host, errors.New("no verified DefenseClaw hook for dcadmin claudecode"))
	stub = &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
	result = runHotConfigEnsure(t, host, opts, stub)
	if got, _ := os.ReadFile(host.configPath); string(got) != previous || len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" ||
		fmt.Sprint(*order) != "[guardian:next guardian:previous]" || !strings.Contains(fmt.Sprint(result.Warnings), key) {
		t.Fatalf("unproven guardian: config %q, installer runs %q, service order %v, warnings %v", got, stub.calls, *order, result.Warnings)
	}

	host, opts = newHotConfigHost(t, previous, strings.Replace(next, "preserve\n", "preserve\n      foreign_hooks: report\n", 1))
	host.adopted = true
	order = stubServices(t, host)
	stub = &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
	runHotConfigEnsure(t, host, opts, stub)
	if len(host.writes) != 0 || len(*order) != 0 || len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" {
		t.Fatalf("key outside the allowlist: writes %q, service order %v, installer runs %q", host.writes, *order, stub.calls)
	}
}

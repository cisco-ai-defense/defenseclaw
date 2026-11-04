// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// cowork-1-0-8 GAP-0060: on a managed Windows computer a standard account's
// `defenseclaw status` shows its own Claude Code and Cowork protection from
// the gateway service's own-status pipe instead of refusing; --json keeps
// deployment_mode managed_enterprise. An elevated administrator keeps the
// managed answer.
func TestManagedWindowsStatusShowsOwnState(t *testing.T) {
	previousStandalone, previousElevated, previousFetch := managedHostWindowsStandalone, windowsEnterpriseIsElevated, ownStatusPipeFetch
	t.Cleanup(func() {
		managedHostWindowsStandalone, windowsEnterpriseIsElevated, ownStatusPipeFetch = previousStandalone, previousElevated, previousFetch
		gatewayStatusJSON, gatewayStatusOwnState = false, false
	})
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.ConfigPathEnv, "")
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`, true }
	elevated := false
	windowsEnterpriseIsElevated = func() bool { return elevated }
	answer := `{"own":true,"managed":true,"managed_by":"your organization","account":{"sid":"S-1-5-21-1-2-3-1001","name":"WIN11\\dcadmin"},` +
		`"claude_code":{"protected":true},"cowork":{"protected":true,"state":"protected: Cowork runs the Claude Code hooks your organization manages","last_event_at":"2026-11-04T13:00:00Z"}}`
	ownStatusPipeFetch = func(context.Context) ([]byte, error) { return []byte(answer), nil }
	run := func(asJSON bool) (string, error) {
		var out bytes.Buffer
		cmd := &cobra.Command{Use: "status"}
		cmd.SetOut(&out)
		gatewayStatusJSON = asJSON
		if err := statusCmd.PersistentPreRunE(cmd, nil); err != nil {
			return out.String(), err
		}
		return out.String(), statusCmd.RunE(cmd, nil)
	}
	stdout, err := run(false)
	if err != nil || !strings.Contains(stdout, "This computer is managed by your organization.") ||
		!strings.Contains(stdout, `Account       WIN11\dcadmin`) || !strings.Contains(stdout, "Claude Code   protected") ||
		!strings.Contains(stdout, "Cowork        protected") || strings.Contains(stdout, "none from you yet") ||
		!strings.Contains(stdout, "enterprise policy show --user") {
		t.Fatalf("status = %v\n%s", err, stdout)
	}
	stdout, err = run(true)
	var out map[string]any
	if err != nil || json.Unmarshal([]byte(stdout), &out) != nil || out["deployment_mode"] != "managed_enterprise" || out["own"] != true {
		t.Fatalf("status --json = %v %s", err, stdout)
	}

	// A gateway service that does not answer is an error that says so, and
	// the JSON still says the computer is managed.
	ownStatusPipeFetch = func(context.Context) ([]byte, error) {
		return nil, errors.New("service DefenseClawGateway is not running")
	}
	stdout, err = run(true)
	out = nil
	if err == nil || json.Unmarshal([]byte(stdout), &out) != nil || out["deployment_mode"] != "managed_enterprise" ||
		!strings.Contains(err.Error(), "the managed gateway service did not answer") {
		t.Fatalf("status --json without the gateway = %v %s", err, stdout)
	}

	// The administrator's status, a named config and an unmanaged computer
	// keep their answers.
	elevated = true
	if statusShowsOwnState() {
		t.Fatal("an elevated administrator's status shows a standard account's own view")
	}
	elevated = false
	t.Setenv(managed.ConfigPathEnv, `C:\cfg\config.yaml`)
	if statusShowsOwnState() {
		t.Fatal("status with DEFENSECLAW_CONFIG shows the own view")
	}
	t.Setenv(managed.ConfigPathEnv, "")
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	if statusShowsOwnState() {
		t.Fatal("status on an unmanaged computer shows the own view")
	}
}

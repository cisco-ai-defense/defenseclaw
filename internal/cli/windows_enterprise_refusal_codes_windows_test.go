// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0314: Setup's preflight refused a rule pack the gateway service cannot
// read as invalid_arguments; the documented code is rule_pack_unreadable,
// and the exit stays the invalid-arguments 1639. Any other invalid argument
// keeps invalid_arguments.
func TestWindowsStandalonePreflightRulePackUnreadableCode(t *testing.T) {
	for _, tc := range []struct {
		cause error
		code  string
	}{
		{fmt.Errorf("%w: %s that C:\\cfg\\config.yaml names: guardrail.rule_pack C:\\packs\\strict: the gateway service account NT SERVICE\\DefenseClawGateway cannot read C:\\packs\\strict; fix it and run again (nothing was changed)",
			errWindowsEnterpriseInvalidArguments, standaloneRulePackUnreadableText), "rule_pack_unreadable"},
		{fmt.Errorf("%w: the config does not compile", errWindowsEnterpriseInvalidArguments), "invalid_arguments"},
	} {
		var out, stderr bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		cmd.SetErr(&stderr)
		err := writeWindowsEnterpriseStandaloneRefusal(cmd, "install", &windowsEnterpriseLifecycleOptions{jsonOutput: true}, tc.cause,
			func(*enterprisestatus.Result) {})
		var exit interface{ ExitCode() int }
		if !errors.As(err, &exit) || exit.ExitCode() != enterprisestatus.WindowsExitInvalidArgs {
			t.Fatalf("%s: err = %v, want exit %d", tc.code, err, enterprisestatus.WindowsExitInvalidArgs)
		}
		var result enterprisestatus.Result
		if decodeErr := json.Unmarshal(out.Bytes(), &result); decodeErr != nil {
			t.Fatalf("%s: decode %q: %v", tc.code, out.String(), decodeErr)
		}
		if len(result.Errors) != 1 || result.Errors[0].Code != tc.code {
			t.Fatalf("errors = %+v, want %s", result.Errors, tc.code)
		}
	}
}

// GAP-0750: a stopped guardian was not_ready in status and lifecycle_error
// in verify. Verify now reports not_ready too; an install that fails the
// same way keeps lifecycle_error.
func TestWindowsStandaloneVerifyStoppedServiceIsNotReady(t *testing.T) {
	for action, want := range map[string]string{"verify": "not_ready", "install": "lifecycle_error"} {
		report, err := parseWindowsEnterpriseInstallerReport([]byte(
			`{"schema_version":1,"ok":false,"action":"` + action + `","installed":false,"transaction_pending":false,"errors":["guardian SCM process is not running"]}`))
		if err != nil {
			t.Fatal(err)
		}
		result := enterprisestatus.New(action, "standalone", "windows", "test")
		applyWindowsEnterpriseInstallerReport(result, nil, report, windowsEnterpriseStandaloneRun{})
		if len(result.Errors) == 0 || result.Errors[0].Code != want {
			t.Fatalf("%s: errors = %+v, want %s", action, result.Errors, want)
		}
	}
}

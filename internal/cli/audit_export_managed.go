// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Seams for the managed administrator environment (audit export and the
// enterprise policy commands); the platform files set the production values.
var (
	auditExportManagedHost = func() bool {
		_, ok := managedHostWindowsStandalone()
		return ok
	}
	auditExportCallerIsAdministrator = platformAuditExportCallerIsAdministrator
	auditExportManagedLayout         = platformAuditExportManagedLayout
)

// prepareManagedAuditExportEnvironment points `audit export` at a standalone
// managed Windows deployment. There the audit database belongs to the
// gateway service under ProgramData, not to the caller's profile, so without
// this an administrator's export looked for %USERPROFILE%\.defenseclaw and
// failed. An administrator (elevated, or LocalSystem for an MDM
// agent) gets the managed configuration, data directory and service
// identity pins, the same values the lifecycle passes to gateway commands;
// the export then reads the database read-only. A standard account is told
// to use an elevated prompt: the managed audit log is administrator-only.
// An explicit DEFENSECLAW_CONFIG or DEFENSECLAW_HOME is the operator's
// choice and is left alone, as is every host without a managed deployment.
func prepareManagedAuditExportEnvironment() error {
	return pinManagedAdministratorEnvironment("audit export", func() string {
		return windowsManagedStandardUserViewAnswer("the audit log", "audit export -o <file>")
	})
}

// pinManagedAdministratorEnvironment gives a read-only administrator command
// (command names it in errors) the managed deployment's environment on a
// standalone managed Windows host, as described above; refusal builds the
// elevation_required answer a standard account gets, with the exit code
// (5) status and verify give it (GAP-2039). Every other host, and an
// explicit DEFENSECLAW_CONFIG or DEFENSECLAW_HOME, is left alone.
func pinManagedAdministratorEnvironment(command string, refusal func() string) error {
	if strings.TrimSpace(os.Getenv(managed.ConfigPathEnv)) != "" ||
		strings.TrimSpace(os.Getenv("DEFENSECLAW_HOME")) != "" {
		return nil
	}
	if !auditExportManagedHost() {
		return nil
	}
	if !auditExportCallerIsAdministrator() {
		return withExitCode(errors.New(refusal()), enterprisestatus.WindowsExitAccessDenied)
	}
	layout, err := auditExportManagedLayout()
	if err != nil {
		return fmt.Errorf("%s: resolve the managed deployment: %w", command, err)
	}
	for _, entry := range [][2]string{
		{"DEFENSECLAW_HOME", layout.DataDir},
		{managed.ConfigPathEnv, layout.ConfigPath},
		{managed.DeploymentModeEnv, "managed_enterprise"},
		{managed.EnterpriseProfileEnv, managed.ProfileStandalone},
		{managed.WindowsServiceAccountEnv, layout.ServiceUser},
		{connector.WindowsGatewayServiceNameEnv, managed.StandaloneWindowsGatewaySvc},
	} {
		if strings.TrimSpace(entry[1]) == "" {
			return fmt.Errorf("%s: the managed deployment layout has no %s value", command, entry[0])
		}
		if err := os.Setenv(entry[0], entry[1]); err != nil {
			return fmt.Errorf("%s: set %s: %w", command, entry[0], err)
		}
	}
	return nil
}

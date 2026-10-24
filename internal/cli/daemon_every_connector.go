// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// requireEveryConnectorFlag makes start exit 3 (running, a connector needs
// attention) unless every configured connector is guarded. The installers
// pass it to a gateway that has it: a boot that skipped one connector (its
// agent probe timed out, the active roster could not be read) printed OK,
// exited 0, and the install or upgrade ended with that connector unprotected
// (GAP-0878, GAP-0899). A hook that starts the gateway and the setup commands
// do not pass it: one connector that needs attention must not fail the start
// that guards the others.
const requireEveryConnectorFlag = "require-every-connector"

func requireEveryConnectorRequested(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	enabled, err := cmd.Flags().GetBool(requireEveryConnectorFlag)
	return err == nil && enabled
}

// everyConnectorGuardedError is nil when the running gateway guards every
// connector cfg turns on, else an exit-3 error that names each connector it
// does not guard and the step that fixes it.
func everyConnectorGuardedError(cfg *config.Config, snap gateway.HealthSnapshot) error {
	if refused, ok := guardrailHookContractAdmissionRefusal(snap.Guardrail); ok {
		return hookContractAdmissionStartError(refused, snap.Guardrail.LastError)
	}
	if !configuredGuardrailExpectedRunning(cfg) {
		return nil
	}
	if snap.Guardrail.State != gateway.StateRunning {
		detail := strings.TrimSpace(snap.Guardrail.LastError)
		if detail == "" {
			detail = string(snap.Guardrail.State)
		}
		return withExitCode(fmt.Errorf(
			"gateway is running, but it guards no connector yet (guardrail: %s); check: defenseclaw-gateway status",
			detail,
		), gatewayStartAdmissionRefusedExitCode)
	}
	notStarted := guardrailConnectorsNotStarted(snap.Guardrail.Details)
	if len(notStarted) == 0 {
		return nil
	}
	refusedBySettings := guardrailAgentSettingsRefusals(snap.Guardrail.Details)
	causes := make([]string, 0, len(notStarted))
	for _, name := range notStarted {
		if reason := strings.TrimSpace(refusedBySettings[name]); reason != "" {
			causes = append(causes, fmt.Sprintf("%s: %s", name, reason))
			continue
		}
		causes = append(causes, fmt.Sprintf("%s: its setup failed (see gateway.log), then run: defenseclaw setup %s", name, name))
	}
	return withExitCode(fmt.Errorf(
		"gateway is running, but it does not guard %s; %s",
		strings.Join(notStarted, ", "), strings.Join(causes, "; "),
	), gatewayStartAdmissionRefusedExitCode)
}

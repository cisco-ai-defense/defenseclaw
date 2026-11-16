// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// enterpriseSetupBusySampleWindow is how long Setup measures how busy the
// processors are before an upgrade.
var enterpriseSetupBusySampleWindow = 6 * time.Second

// enterpriseSetupBusyIdlePercent is the idle share of the processors below
// which Setup does not start an upgrade. Ten hook drivers at one call a
// second each left a managed 8-processor computer 14-18% idle, and an
// upgrade there ran past TIMEOUTSECONDS (GAP-2265); a quiet one is 98-100%
// idle.
const enterpriseSetupBusyIdlePercent = 25

// enterpriseSetupHostIdlePercent measures the idle share of all processors
// over window; ok is false where it is unknown. Replaceable in tests.
var enterpriseSetupHostIdlePercent = platformHostIdlePercent

// enterpriseSetupHostBusy is the refusal of an upgrade on a computer whose
// processors are saturated. It is a retryable lifecycle_busy (1618).
type enterpriseSetupHostBusy struct {
	idle     int
	window   time.Duration
	from, to string
}

func (e enterpriseSetupHostBusy) Error() string {
	return fmt.Sprintf("lifecycle_busy: the processors of this computer were only %d%% idle over %s, so Setup did not start the upgrade from %s to %s. "+
		"The upgrade runs below normal priority so that agent hooks keep answering, and on a computer this busy it cannot finish within TIMEOUTSECONDS. "+
		"Nothing was changed. Next step: run Setup /ensure again when the computer is less busy (an MDM retries exit 1618 by itself)",
		e.idle, e.window, e.from, e.to)
}

// Is makes the refusal the retryable busy result (exit 1618, lifecycle_busy).
func (enterpriseSetupHostBusy) Is(target error) bool { return target == errEnterpriseSetupEnsureBusy }

// requireEnterpriseSetupHostCapacity refuses, before Setup stages anything,
// a standalone /ensure or /upgrade that would replace the installed release
// while the processors are saturated. Such an upgrade ran three to four times
// as long as on a quiet computer and stopped with lifecycle_timeout after
// TIMEOUTSECONDS (GAP-2265); refusing at once with the retryable 1618 is the
// clear result. A no-op /ensure of the installed release, /repair, /uninstall
// and a fresh install are not measured, and an unknown idle share never
// blocks Setup.
func requireEnterpriseSetupHostCapacity(action string, deployment winpath.EnterpriseDeployment, payloadVersion string) error {
	if action != "ensure" && action != "upgrade" {
		return nil
	}
	installed := strings.TrimSpace(deployment.ProductVersion)
	target := strings.TrimSpace(payloadVersion)
	if deployment.State != winpath.EnterpriseDeploymentInstalled || installed == "" || target == "" ||
		strings.EqualFold(installed, target) {
		return nil
	}
	idle, ok := enterpriseSetupHostIdlePercent(enterpriseSetupBusySampleWindow)
	if !ok || idle >= enterpriseSetupBusyIdlePercent {
		return nil
	}
	return enterpriseSetupHostBusy{idle: idle, window: enterpriseSetupBusySampleWindow, from: installed, to: target}
}

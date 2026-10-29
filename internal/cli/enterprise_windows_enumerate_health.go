// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const enterpriseWindowsEnumerateRetryMin = 15 * time.Second

// enterpriseWindowsEnumerateHealth tracks consecutive enumerator failures.
// The first failure of a streak is logged once as degraded; the streak is
// retried on a doubling backoff capped at the normal interval; the first
// success after a streak logs the recovery.
type enterpriseWindowsEnumerateHealth struct {
	interval time.Duration
	failing  bool
	delay    time.Duration
}

func (health *enterpriseWindowsEnumerateHealth) observe(
	w io.Writer,
	manifestPath string,
	err error,
) (time.Duration, bool) {
	if err == nil {
		if health.failing {
			fmt.Fprintf(w, "[hook-enumerator] recovered after degraded cycles\n")
		}
		health.failing = false
		health.delay = 0
		return 0, false
	}
	if !health.failing {
		managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
			"component": "hook-enumerator",
			"path":      manifestPath,
			"reason":    err.Error(),
		})
	}
	health.failing = true
	switch {
	case health.delay < enterpriseWindowsEnumerateRetryMin:
		health.delay = enterpriseWindowsEnumerateRetryMin
	default:
		health.delay *= 2
	}
	if health.interval > 0 && health.delay >= health.interval {
		// The regular ticker already covers this cadence.
		return 0, false
	}
	return health.delay, true
}

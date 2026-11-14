// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"fmt"
)

// CodeHookOverCapacity warns that managed hook calls ran out of their answer
// budget in the last hour: the host got more tool calls than DefenseClaw can
// check in time (S8 DESIGN 18, H1 option B). A warning, never an error:
// status and verify exit codes do not change under load.
const CodeHookOverCapacity = "hook_over_capacity"

// HookCapacityWarning reads the hook_capacity object of a gateway /health or
// /status document and returns the warning text when the window holds a
// deadline deny or a late allow. A document without it (an older gateway,
// an ordinary account) gives no warning.
func HookCapacityWarning(body []byte) (string, bool) {
	var doc struct {
		HookCapacity *struct {
			WindowMinutes int `json:"window_minutes"`
			Window        struct {
				Answered       uint64 `json:"answered"`
				DeadlineDenies uint64 `json:"deadline_denies"`
				LateAllows     uint64 `json:"late_allows"`
				Shed           uint64 `json:"shed"`
			} `json:"window"`
			PeakMinuteStart string `json:"peak_minute_start"`
			SizingDoc       string `json:"sizing_doc"`
		} `json:"hook_capacity"`
	}
	if json.Unmarshal(body, &doc) != nil || doc.HookCapacity == nil {
		return "", false
	}
	c := doc.HookCapacity
	if c.Window.DeadlineDenies+c.Window.LateAllows == 0 {
		return "", false
	}
	minutes := c.WindowMinutes
	if minutes <= 0 {
		minutes = 60
	}
	message := fmt.Sprintf("in the last %d min %d agent tool call(s) were blocked and %d ran unchecked because DefenseClaw "+
		"could not check them within their answer budget (%d answered in time, %d refused by the admission limits): "+
		"this host is over its hook capacity, not a policy result; run fewer agents at once or use a larger host",
		minutes, c.Window.DeadlineDenies, c.Window.LateAllows, c.Window.Answered, c.Window.Shed)
	if len(c.PeakMinuteStart) > 0 && len(c.PeakMinuteStart) <= 40 {
		message += "; busiest minute " + c.PeakMinuteStart
	}
	if len(c.SizingDoc) > 0 && len(c.SizingDoc) <= 200 {
		message += "; sizing: " + c.SizingDoc
	}
	return message, true
}

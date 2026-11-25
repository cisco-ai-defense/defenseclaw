// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"time"
)

// SubstrateActivityConfig is substrate.activity: what `substrate list` and
// `substrate status` say an agent is doing (B3.6), and the administrator's
// switch for the desktop notifications of `substrate watch`.
type SubstrateActivityConfig struct {
	// StatusWindow is how recent a model call or hook call must be for the
	// agent to show as thinking ("" = DefaultSubstrateStatusWindow). "0s"
	// turns the thinking state off: nothing is added to the model path.
	StatusWindow string `mapstructure:"status_window" yaml:"status_window,omitempty"`
	// Notifications is auto (default: on, the person's own
	// notifications.substrate keys decide) or off (the administrator's
	// switch: `substrate watch` and the attached launcher show lines only).
	Notifications string `mapstructure:"notifications" yaml:"notifications,omitempty"`
}

const (
	// DefaultSubstrateStatusWindow is the recent-activity window of the
	// thinking state (D3-13).
	DefaultSubstrateStatusWindow = 20 * time.Second
	maxSubstrateStatusWindow     = 10 * time.Minute

	// SubstrateNotificationsAuto and SubstrateNotificationsOff are the two
	// values of substrate.activity.notifications.
	SubstrateNotificationsAuto = "auto"
	SubstrateNotificationsOff  = "off"
)

// EffectiveStatusWindow is status_window, 20s when unset, 0 when "0s".
func (c SubstrateActivityConfig) EffectiveStatusWindow() time.Duration {
	return durationOr(c.StatusWindow, DefaultSubstrateStatusWindow)
}

// NotificationsOn reports whether the cluster lets agents' asks and task
// ends raise desktop notifications (anything but an explicit off).
func (c SubstrateActivityConfig) NotificationsOn() bool {
	return !strings.EqualFold(strings.TrimSpace(c.Notifications), SubstrateNotificationsOff)
}

func (c SubstrateActivityConfig) validate(bad func(key, format string, a ...any)) {
	if v := strings.TrimSpace(c.StatusWindow); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 || d > maxSubstrateStatusWindow {
			bad("activity.status_window", "%q must be a Go duration from 0s to 10m", c.StatusWindow)
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Notifications)) {
	case "", SubstrateNotificationsAuto, SubstrateNotificationsOff:
	default:
		bad("activity.notifications", "%q is not auto or off", c.Notifications)
	}
}

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
	"runtime"
	"time"
)

// NotificationsConfig controls user-session OS notifications fired
// by the gateway when blocks happen or HITL approval is requested.
//
// The notifier dispatcher in internal/gateway/notifier consumes this
// struct directly. Defaults are intentionally permissive (all
// categories on, modest throttle) so that operators who turn the
// feature on with a single Y/n at setup get useful coverage without
// further tuning. Operators dialing noise down can disable
// individual categories or sources.
//
// All durations are expressed in seconds in YAML (mapstructure
// decodes time.Duration from strings like "30s" — but we keep the
// Go field as a Duration so callers do not deal with units).
type NotificationsConfig struct {
	// Enabled is the master switch. When false, the dispatcher is a
	// total no-op regardless of category settings. The setup wizard
	// flips this to true after asking the user.
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// BlockEnforced fires a notification when a request is actually
	// denied (mode=action, action=block).
	BlockEnforced bool `mapstructure:"block_enforced" yaml:"block_enforced"`

	// BlockWouldBlock fires a notification when a verdict would have
	// blocked under enforcement but observe mode let it through, OR
	// when a confirm verdict was downgraded because the connector
	// cannot natively ask for that event (see BlockEvent.WouldAsk in
	// internal/gateway/notifier). Default OFF: a fresh install only
	// notifies for things that actually happened (enforced block or
	// a real chat-side ask). Operators tuning policy in observe mode
	// can opt in by setting this to true.
	BlockWouldBlock bool `mapstructure:"block_would_block" yaml:"block_would_block"`

	// HITLApproval fires a notification when a HITL/confirm prompt
	// is awaiting a user reply on the chat surface.
	HITLApproval bool `mapstructure:"hitl_approval" yaml:"hitl_approval"`

	// Sources gates events by emission source so an operator can,
	// e.g., keep guardrail notifications and silence the chatty
	// asset-policy ones while a registry is being filled in.
	Sources NotificationSourceFilter `mapstructure:"sources" yaml:"sources,omitempty"`

	// DedupWindow suppresses identical notifications (same
	// category/source/target/reason hash) seen within this window.
	// Zero or negative falls back to NotificationsDefaultDedupWindow.
	DedupWindow time.Duration `mapstructure:"dedup_window" yaml:"dedup_window,omitempty"`

	// MaxPerMinute caps the global rate of delivered notifications.
	// When exhausted within the minute, the dispatcher emits a
	// single roll-up ("DefenseClaw suppressed N notifications") at
	// minute boundaries. Zero or negative falls back to
	// NotificationsDefaultMaxPerMinute.
	MaxPerMinute int `mapstructure:"max_per_minute" yaml:"max_per_minute,omitempty"`
}

// NotificationSourceFilter toggles the three block-decision sources.
// All default to true so a fresh enable reports everything, and
// operators turn off only what's noisy.
type NotificationSourceFilter struct {
	Hook        bool `mapstructure:"hook"         yaml:"hook"`
	Guardrail   bool `mapstructure:"guardrail"    yaml:"guardrail"`
	AssetPolicy bool `mapstructure:"asset_policy" yaml:"asset_policy"`
}

// NotificationsDefaultDedupWindow is the dedup window applied when
// the operator did not set one. Identical (category, source, target,
// reason) tuples within this window are collapsed into a single
// notification.
const NotificationsDefaultDedupWindow = 30 * time.Second

// NotificationsDefaultMaxPerMinute is the global rate cap applied
// when the operator did not set one. The dispatcher emits at most
// this many notifications per minute and rolls excess into a single
// summary line at the minute boundary.
const NotificationsDefaultMaxPerMinute = 12

// DefaultNotificationsEnabled is the platform-conditional master
// default for the notification dispatcher. macOS and native Windows both
// provide an attended consumer desktop surface owned by the interactive user,
// so fresh installs opt in there. Headless Linux and other GOOS values wait for
// an explicit operator opt-in via `defenseclaw setup notifications on`.
// Exposed as a package-level var so tests and the Python config helper can pin
// the matrix without taking a build-tag dependency.
var DefaultNotificationsEnabled = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// DefaultNotificationsConfig returns the recommended starting point
// for fresh installs: master switch defaults to true on macOS and Windows and
// false elsewhere (see DefaultNotificationsEnabled). Categories
// favor signal over noise — a fresh install only notifies for
// things that ACTUALLY happened (enforced block, real native ask).
// BlockWouldBlock defaults to false; observe-mode "would have
// blocked" / "would have asked" toasts are off by default and are
// an explicit opt-in for operators tuning a strict policy. Sources
// remain on so opting BlockWouldBlock back in still hits every
// emission site without a second tuning pass.
func DefaultNotificationsConfig() NotificationsConfig {
	return NotificationsConfig{
		Enabled:         DefaultNotificationsEnabled,
		BlockEnforced:   true,
		BlockWouldBlock: false,
		HITLApproval:    true,
		Sources: NotificationSourceFilter{
			Hook:        true,
			Guardrail:   true,
			AssetPolicy: true,
		},
		DedupWindow:  NotificationsDefaultDedupWindow,
		MaxPerMinute: NotificationsDefaultMaxPerMinute,
	}
}

// EffectiveDedupWindow returns DedupWindow when set, otherwise the
// package default. Used by the dispatcher so callers do not
// distinguish unset from explicit-zero (zero is interpreted as
// "use the default" rather than "do not dedup at all" — operators
// who genuinely want no dedup can set a tiny value like 1ms).
func (n NotificationsConfig) EffectiveDedupWindow() time.Duration {
	if n.DedupWindow > 0 {
		return n.DedupWindow
	}
	return NotificationsDefaultDedupWindow
}

// EffectiveMaxPerMinute mirrors EffectiveDedupWindow for the rate cap.
func (n NotificationsConfig) EffectiveMaxPerMinute() int {
	if n.MaxPerMinute > 0 {
		return n.MaxPerMinute
	}
	return NotificationsDefaultMaxPerMinute
}

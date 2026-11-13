// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

// SecretFlowConfig is guardrail.secret_flow: the Secret flow tracking feature
// (S7, 1.0.10). The feature's rollout rides the shared guardrail.effects_rules
// lane key (off|shadow|on); these are the feature's own settings. Additive and
// omitempty, so a config that never names the block loads with the shipped
// defaults and round-trips unchanged. On managed standalone hosts the whole
// guardrail.* tree is authoritative from the signed bundle and local writers
// are refused, so these settings lock through the existing managed path with
// no extra handling here.
type SecretFlowConfig struct {
	// Mode selects the step: off (skip, no cost), shadow (compute and log a
	// verdict beside today's, never change the answer) or on (the verdict
	// participates). Ships shadow until the real-trace alert rate is measured.
	Mode string `mapstructure:"mode" yaml:"mode,omitempty"`
	// LabelSets selects which secret sources are labeled.
	LabelSets SecretFlowLabelSets `mapstructure:"label_sets" yaml:"label_sets,omitempty"`
	// SinkAction is the action per mode when a labeled secret reaches an
	// external sink. Default is validated never to block (balanced defaults);
	// strict and managed may block.
	SinkAction SecretFlowSinkAction `mapstructure:"sink_action" yaml:"sink_action,omitempty"`
	// Reencodings indexes base64/hex/URL-encoded forms of each secret value so
	// a re-encoded secret still matches. On by default.
	Reencodings bool `mapstructure:"reencodings" yaml:"reencodings,omitempty"`
	// Memory bounds the per-session state.
	Memory SecretFlowMemory `mapstructure:"memory" yaml:"memory,omitempty"`
	// DestinationAllowlist holds hosts (and dotted suffixes) that do not count
	// as external sinks: your own git remote, a package registry.
	DestinationAllowlist []string `mapstructure:"destination_allowlist" yaml:"destination_allowlist,omitempty"`
}

// SecretFlowLabelSets selects the secret sources to label.
type SecretFlowLabelSets struct {
	// Credentials turns on the built-in credential set (.env, SSH private
	// keys, cloud/token files, keychain exports, /proc/*/environ). On by
	// default.
	Credentials bool `mapstructure:"credentials" yaml:"credentials,omitempty"`
	// ExtraPathGlobs are extra absolute or ~ path globs labeled as secret.
	ExtraPathGlobs []string `mapstructure:"extra_path_globs" yaml:"extra_path_globs,omitempty"`
	// ExtraSecretPatterns are extra basename globs labeled as secret.
	ExtraSecretPatterns []string `mapstructure:"extra_secret_patterns" yaml:"extra_secret_patterns,omitempty"`
}

// SecretFlowSinkAction is the action per mode. Empty inherits the shipped
// default for that mode (alert, block, block).
type SecretFlowSinkAction struct {
	Default string `mapstructure:"default" yaml:"default,omitempty"`
	Strict  string `mapstructure:"strict" yaml:"strict,omitempty"`
	Managed string `mapstructure:"managed" yaml:"managed,omitempty"`
}

// SecretFlowMemory bounds the per-session state.
type SecretFlowMemory struct {
	MaxLabeledPaths int `mapstructure:"max_labeled_paths" yaml:"max_labeled_paths,omitempty"`
	MaxValueDigests int `mapstructure:"max_value_digests" yaml:"max_value_digests,omitempty"`
}

// SecretFlowModes is the closed set for guardrail.secret_flow.mode.
var SecretFlowModes = []string{"off", "shadow", "on"}

// maxSecretFlowMemory caps the per-session bounds so a config cannot ask the
// gateway to hold an unbounded amount of state per session.
const maxSecretFlowMemory = 100000

func validSecretFlowMode(m string) bool {
	switch m {
	case "", "off", "shadow", "on":
		return true
	}
	return false
}

// Validate checks guardrail.secret_flow. The default sink can never block
// (balanced defaults); strict and managed may be alert or block.
func (s SecretFlowConfig) Validate() error {
	if !validSecretFlowMode(s.Mode) {
		return fmt.Errorf("guardrail.secret_flow.mode %q must be one of off, shadow, on", s.Mode)
	}
	if a := s.SinkAction.Default; a != "" && a != "alert" {
		return fmt.Errorf("guardrail.secret_flow.sink_action.default %q is not allowed: the default profile never blocks (balanced defaults); use \"alert\", or set mode off to disable", a)
	}
	if err := validSecretFlowSink("guardrail.secret_flow.sink_action.strict", s.SinkAction.Strict); err != nil {
		return err
	}
	if err := validSecretFlowSink("guardrail.secret_flow.sink_action.managed", s.SinkAction.Managed); err != nil {
		return err
	}
	if s.Memory.MaxLabeledPaths < 0 || s.Memory.MaxLabeledPaths > maxSecretFlowMemory {
		return fmt.Errorf("guardrail.secret_flow.memory.max_labeled_paths %d must be between 0 and %d (0 uses the default)", s.Memory.MaxLabeledPaths, maxSecretFlowMemory)
	}
	if s.Memory.MaxValueDigests < 0 || s.Memory.MaxValueDigests > maxSecretFlowMemory {
		return fmt.Errorf("guardrail.secret_flow.memory.max_value_digests %d must be between 0 and %d (0 uses the default)", s.Memory.MaxValueDigests, maxSecretFlowMemory)
	}
	return nil
}

func validSecretFlowSink(field, v string) error {
	switch v {
	case "", "alert", "block":
		return nil
	}
	return fmt.Errorf("%s %q must be \"alert\" or \"block\"", field, v)
}

// CredentialsEnabled reports whether the built-in credential set is on. It is
// on unless explicitly turned off; the loader seeds the default to true.
func (s SecretFlowConfig) CredentialsEnabled() bool { return s.LabelSets.Credentials }

// SinkActionFor returns the configured (or shipped-default) action for a mode.
func (s SecretFlowConfig) SinkActionFor(strict, managed bool) string {
	switch {
	case managed:
		if s.SinkAction.Managed != "" {
			return s.SinkAction.Managed
		}
		return "block"
	case strict:
		if s.SinkAction.Strict != "" {
			return s.SinkAction.Strict
		}
		return "block"
	default:
		if s.SinkAction.Default != "" {
			return s.SinkAction.Default
		}
		return "alert"
	}
}

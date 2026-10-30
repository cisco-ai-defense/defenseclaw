// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// DefenseClawDecisionModelKeyEnv is the canonical environment variable for
// the decision model's bearer token, the way DEFENSECLAW_LLM_KEY is for the
// unified LLM. Local decision-model servers need no key.
const DefenseClawDecisionModelKeyEnv = "DEFENSECLAW_DECISION_MODEL_KEY"

// Decision model routing defaults. They are the operating point the System
// One benchmark recommends (two-sided routing, allow at risk <= 0.30, decide
// at risk >= 0.75); see docs-site/content/docs/guardrail/decision-model.mdx.
const (
	DefaultDecisionModelAllowThreshold = 0.30
	DefaultDecisionModelBlockThreshold = 0.75
	DefaultDecisionModelTimeoutSeconds = 3.0
	maxDecisionModelTimeoutSeconds     = 30.0

	// DecisionModelEscalate sends a confident block to the LLM judge and
	// keeps the decision model's finding as a floor the judge can raise.
	DecisionModelEscalate = "escalate"
	// DecisionModelDecide lets a confident block stand without the judge.
	DecisionModelDecide = "decide"
)

// DecisionModelConfig is the unified decision model: a small, fast model
// that speaks the System One protocol (POST {model, state, questions},
// answers carry calibrated probabilities). The guardrail runs it in front
// of the LLM judge on tool calls, and the skill scanner records its
// advisory score. Off by default.
//
// It is shaped like the unified llm: block. The key is never stored here:
// api_key_env names the variable (DEFENSECLAW_DECISION_MODEL_KEY when
// empty) that the environment or ~/.defenseclaw/.env holds. A standalone
// managed host reads the key only from the protected credential named by
// credential. Mirrors cli/defenseclaw/config.py::DecisionModelConfig.
type DecisionModelConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// Model is the model name sent in the request body.
	Model string `mapstructure:"model" yaml:"model,omitempty"`
	// BaseURL is the full endpoint URL, for example
	// http://127.0.0.1:8791/v1/systemone. https anywhere; plain http only to
	// a loopback host.
	BaseURL string `mapstructure:"base_url" yaml:"base_url,omitempty"`
	// APIKeyEnv names the variable that holds the bearer token. Empty uses
	// DEFENSECLAW_DECISION_MODEL_KEY; an unset variable sends no token.
	APIKeyEnv string `mapstructure:"api_key_env" yaml:"api_key_env,omitempty"`
	// Credential names the protected credential that holds the token on a
	// standalone managed host. Ignored elsewhere.
	Credential string `mapstructure:"credential" yaml:"credential,omitempty"`
	// Timeout caps one decision-model call in seconds (0 = 3s). The judge
	// keeps the rest of its own budget when the model is late.
	Timeout float64 `mapstructure:"timeout" yaml:"timeout,omitempty"`
	// AllowThreshold: a risk at or below it is a confident allow and skips
	// the judge (0 = 0.30). Risk is 1 - P(allow).
	AllowThreshold float64 `mapstructure:"allow_threshold" yaml:"allow_threshold,omitempty"`
	// BlockThreshold: a risk at or above it is a confident block
	// (0 = 0.75).
	BlockThreshold float64 `mapstructure:"block_threshold" yaml:"block_threshold,omitempty"`
	// OnConfidentBlock is escalate (default: the judge still runs and the
	// decision model's finding is a floor) or decide (the finding stands
	// without the judge).
	OnConfidentBlock string `mapstructure:"on_confident_block" yaml:"on_confident_block,omitempty"`
}

// Active reports whether the decision model should be called.
func (d DecisionModelConfig) Active() bool {
	return d.Enabled && strings.TrimSpace(d.BaseURL) != "" && strings.TrimSpace(d.Model) != ""
}

// EffectiveTimeoutSeconds returns Timeout or the default.
func (d DecisionModelConfig) EffectiveTimeoutSeconds() float64 {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return DefaultDecisionModelTimeoutSeconds
}

// EffectiveAllowThreshold returns AllowThreshold or the default.
func (d DecisionModelConfig) EffectiveAllowThreshold() float64 {
	if d.AllowThreshold > 0 {
		return d.AllowThreshold
	}
	return DefaultDecisionModelAllowThreshold
}

// EffectiveBlockThreshold returns BlockThreshold or the default.
func (d DecisionModelConfig) EffectiveBlockThreshold() float64 {
	if d.BlockThreshold > 0 {
		return d.BlockThreshold
	}
	return DefaultDecisionModelBlockThreshold
}

// EffectiveOnConfidentBlock returns OnConfidentBlock or escalate.
func (d DecisionModelConfig) EffectiveOnConfidentBlock() string {
	if v := strings.ToLower(strings.TrimSpace(d.OnConfidentBlock)); v != "" {
		return v
	}
	return DecisionModelEscalate
}

// EffectiveAPIKeyEnv returns APIKeyEnv or DEFENSECLAW_DECISION_MODEL_KEY.
func (d DecisionModelConfig) EffectiveAPIKeyEnv() string {
	if v := strings.TrimSpace(d.APIKeyEnv); v != "" {
		return v
	}
	return DefenseClawDecisionModelKeyEnv
}

// Validate checks the block. A disabled block is checked only for value
// ranges, so an operator can stage settings before turning it on.
func (d DecisionModelConfig) Validate() error {
	allow, block := d.EffectiveAllowThreshold(), d.EffectiveBlockThreshold()
	for name, v := range map[string]float64{"allow_threshold": d.AllowThreshold, "block_threshold": d.BlockThreshold} {
		if math.IsNaN(v) || v < 0 || v > 1 {
			return fmt.Errorf("%s must be between 0 and 1, got %v", name, v)
		}
	}
	if allow >= block {
		return fmt.Errorf("allow_threshold (%v) must be lower than block_threshold (%v)", allow, block)
	}
	if math.IsNaN(d.Timeout) || d.Timeout < 0 || d.Timeout > maxDecisionModelTimeoutSeconds {
		return fmt.Errorf("timeout must be between 0 and %v seconds, got %v", maxDecisionModelTimeoutSeconds, d.Timeout)
	}
	switch d.EffectiveOnConfidentBlock() {
	case DecisionModelEscalate, DecisionModelDecide:
	default:
		return fmt.Errorf("on_confident_block must be %q or %q, got %q", DecisionModelEscalate, DecisionModelDecide, d.OnConfidentBlock)
	}
	if strings.TrimSpace(d.BaseURL) != "" {
		if err := ValidateDecisionModelURL(d.BaseURL); err != nil {
			return err
		}
	}
	if d.Enabled {
		if strings.TrimSpace(d.BaseURL) == "" {
			return fmt.Errorf("enabled needs base_url (the decision model endpoint, for example http://127.0.0.1:8791/v1/systemone)")
		}
		if strings.TrimSpace(d.Model) == "" {
			return fmt.Errorf("enabled needs model (the model name the endpoint serves)")
		}
	}
	return nil
}

// ValidateDecisionModelURL allows https anywhere and plain http only to a
// loopback host, so tool-call arguments and the bearer token never cross
// the network in clear text. Credentials in the URL are refused.
func ValidateDecisionModelURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("base_url must be an absolute http(s) URL")
	}
	if u.User != nil {
		return fmt.Errorf("base_url must not carry credentials; put the token in %s", DefenseClawDecisionModelKeyEnv)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if strings.EqualFold(host, "localhost") {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("base_url must use https, or plain http only to a loopback host (127.0.0.1, ::1, localhost)")
	default:
		return fmt.Errorf("base_url must use http or https, not %q", u.Scheme)
	}
}

// ResolvedDecisionModelKey returns the decision model's bearer token, or ""
// when none is configured. A standalone managed deployment reads only the
// protected credential named by decision_model.credential; elsewhere the key
// store, then the process environment, under EffectiveAPIKeyEnv.
func (c *Config) ResolvedDecisionModelKey() string {
	if c == nil {
		return ""
	}
	d := c.DecisionModel
	if c.StandaloneEnterprise() {
		name := strings.TrimSpace(d.Credential)
		if name == "" {
			return ""
		}
		value, err := resolveStandaloneLLMCredential(name, managed.StandaloneSecretsDirForConfig(runtime.GOOS, c.ConfigFilePath))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(value))
	}
	env := d.EffectiveAPIKeyEnv()
	if v, ok := GetKey(env); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(os.Getenv(env))
}

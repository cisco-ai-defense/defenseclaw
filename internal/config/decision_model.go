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
// the decision model's token (a bearer token, or the x-goog-api-key of
// protocol gemini-decisions), the way DEFENSECLAW_LLM_KEY is for the
// unified LLM. Local decision-model servers need no key.
const DefenseClawDecisionModelKeyEnv = "DEFENSECLAW_DECISION_MODEL_KEY"

// Decision model routing defaults. They are the operating point the System
// One benchmark recommends (two-sided routing, allow at risk <= 0.30, decide
// at risk >= 0.75); see docs-site/content/docs/guardrail/decision-model.mdx.
const (
	DefaultDecisionModelAllowThreshold = 0.30
	DefaultDecisionModelBlockThreshold = 0.75
	DefaultDecisionModelTimeoutSeconds = 1.0
	maxDecisionModelTimeoutSeconds     = 30.0
	// DefaultDecisionModelBlockRiskScore: a confident block also needs the
	// risk score answer (0 ordinary, 1 dual use, 2 clear serious harm) at or
	// above this (owner decision 2026-11-13, S7 SYSONE.md R4).
	DefaultDecisionModelBlockRiskScore = 1.5
	maxDecisionModelRiskScore          = 2.0

	// DecisionModelEscalate sends a confident block to the LLM judge and
	// keeps the decision model's finding as a floor the judge can raise.
	DecisionModelEscalate = "escalate"
	// DecisionModelDecide is retired (owner decision 2026-11-13: a decision
	// model block is never final). It is still accepted so a config written
	// by 1.0.9 loads, and it acts as escalate. Accepted until 1.1.
	DecisionModelDecide = "decide"

	// DecisionModelProtocolSystemOne is the System One wire protocol:
	// POST {model, state, questions} with a Bearer token. The default.
	DecisionModelProtocolSystemOne = "system-one"
	// DecisionModelProtocolGeminiDecisions is Google's Decisions API
	// (gemini-decision-1, POST .../v1beta/decisions): the same questions and
	// answers, but the state goes in a labeled "input" string and the key in
	// an x-goog-api-key header.
	DecisionModelProtocolGeminiDecisions = "gemini-decisions"
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
	// Protocol is the endpoint's wire protocol: system-one (the default:
	// {model, state, questions}, Bearer token) or gemini-decisions (Google's
	// Decisions API: {model, input, questions}, x-goog-api-key header).
	Protocol string `mapstructure:"protocol" yaml:"protocol,omitempty"`
	// APIKeyEnv names the variable that holds the bearer token. Empty uses
	// DEFENSECLAW_DECISION_MODEL_KEY; an unset variable sends no token.
	APIKeyEnv string `mapstructure:"api_key_env" yaml:"api_key_env,omitempty"`
	// Credential names the protected credential that holds the token on a
	// standalone managed host. Ignored elsewhere.
	Credential string `mapstructure:"credential" yaml:"credential,omitempty"`
	// Timeout caps one decision-model call in seconds (0 = 1s). The gateway
	// also caps it at a quarter of the judge's remaining time.
	Timeout float64 `mapstructure:"timeout" yaml:"timeout,omitempty"`
	// AllowThreshold: a risk at or below it is a confident allow and skips
	// the judge (0 = 0.30). Risk is 1 - P(allow).
	AllowThreshold float64 `mapstructure:"allow_threshold" yaml:"allow_threshold,omitempty"`
	// BlockThreshold: a risk at or above it is a confident block
	// (0 = 0.75).
	BlockThreshold float64 `mapstructure:"block_threshold" yaml:"block_threshold,omitempty"`
	// OnConfidentBlock is escalate: in cascade 3 the judge still runs on a
	// confident block and the decision model's finding is a floor. The
	// retired value decide is accepted and acts as escalate.
	OnConfidentBlock string `mapstructure:"on_confident_block" yaml:"on_confident_block,omitempty"`
	// BlockRiskScore: a confident block also needs the risk score answer
	// at or above it (0 = 1.5; range 0..2). Below it the call escalates.
	BlockRiskScore float64 `mapstructure:"block_risk_score" yaml:"block_risk_score,omitempty"`
	// EscalateRuleFlagged: a call the rules already flagged never gets a
	// decision-model confident block; it escalates (the judge, or a
	// confirmation in cascade 2). Unset = true.
	EscalateRuleFlagged *bool `mapstructure:"escalate_rule_flagged" yaml:"escalate_rule_flagged,omitempty"`
	// HookConnectors lists the connectors whose hook tool calls the
	// decision model answers on its own where the LLM judge does not judge
	// them (cascade 2: rules, then the decision model). "*" matches every
	// connector. Where the judge runs, the decision model stays in front of
	// it (cascade 3) whether or not the connector is listed. Empty, the
	// default, keeps the decision model in front of the judge only.
	HookConnectors []string `mapstructure:"hook_connectors" yaml:"hook_connectors,omitempty"`
	// CallEffects adds state.call_effects (version 1): the typed effects of
	// the current call (reads, writes, deletes, runs, sends), computed only
	// for calls sent to the model, within 50 ms. Off by default.
	CallEffects bool `mapstructure:"call_effects" yaml:"call_effects,omitempty"`
}

// Active reports whether the decision model should be called.
func (d DecisionModelConfig) Active() bool {
	return d.Enabled && strings.TrimSpace(d.BaseURL) != "" && strings.TrimSpace(d.Model) != ""
}

// AnswersAlone reports whether the decision model answers the connector's
// hook tool calls on its own where the LLM judge does not run (cascade 2).
// Names are matched in canonical form (NormalizeConnectorName: case and the
// claude-code alias folded, as the CLI's connector_paths.normalize does);
// "*" matches every connector and a blank entry matches none.
func (d DecisionModelConfig) AnswersAlone(connector string) bool {
	connector = NormalizeConnectorName(connector)
	if !d.Active() || connector == "" {
		return false
	}
	for _, entry := range d.HookConnectors {
		entry = strings.TrimSpace(entry)
		if entry == "*" || (entry != "" && NormalizeConnectorName(entry) == connector) {
			return true
		}
	}
	return false
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

// EffectiveBlockRiskScore returns BlockRiskScore or the default.
func (d DecisionModelConfig) EffectiveBlockRiskScore() float64 {
	if d.BlockRiskScore > 0 {
		return d.BlockRiskScore
	}
	return DefaultDecisionModelBlockRiskScore
}

// EffectiveEscalateRuleFlagged returns EscalateRuleFlagged, true when unset.
func (d DecisionModelConfig) EffectiveEscalateRuleFlagged() bool {
	return d.EscalateRuleFlagged == nil || *d.EscalateRuleFlagged
}

// EffectiveOnConfidentBlock returns OnConfidentBlock or escalate.
func (d DecisionModelConfig) EffectiveOnConfidentBlock() string {
	if v := strings.ToLower(strings.TrimSpace(d.OnConfidentBlock)); v != "" {
		return v
	}
	return DecisionModelEscalate
}

// EffectiveProtocol returns Protocol or system-one. Validate admits only
// the exact values, so no folding happens here.
func (d DecisionModelConfig) EffectiveProtocol() string {
	if d.Protocol != "" {
		return d.Protocol
	}
	return DecisionModelProtocolSystemOne
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
	if math.IsNaN(d.BlockRiskScore) || d.BlockRiskScore < 0 || d.BlockRiskScore > maxDecisionModelRiskScore {
		return fmt.Errorf("block_risk_score must be between 0 and %v, got %v", maxDecisionModelRiskScore, d.BlockRiskScore)
	}
	if math.IsNaN(d.Timeout) || d.Timeout < 0 || d.Timeout > maxDecisionModelTimeoutSeconds {
		return fmt.Errorf("timeout must be between 0 and %v seconds, got %v", maxDecisionModelTimeoutSeconds, d.Timeout)
	}
	switch d.EffectiveOnConfidentBlock() {
	case DecisionModelEscalate, DecisionModelDecide:
	default:
		return fmt.Errorf("on_confident_block must be %q or %q, got %q", DecisionModelEscalate, DecisionModelDecide, d.OnConfidentBlock)
	}
	// Exact values only, as the config schema has them (no case folding).
	switch d.Protocol {
	case "", DecisionModelProtocolSystemOne, DecisionModelProtocolGeminiDecisions:
	default:
		return fmt.Errorf("protocol must be %q or %q, got %q", DecisionModelProtocolSystemOne, DecisionModelProtocolGeminiDecisions, d.Protocol)
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

// decisionModelKeyQueryParams are query parameters that carry a key or a
// token (Google's examples put the AI Studio key in ?key=).
var decisionModelKeyQueryParams = map[string]bool{
	"key": true, "api_key": true, "apikey": true, "api-key": true, "x-goog-api-key": true,
	"access_token": true, "token": true, "auth_token": true, "auth": true, "secret": true,
	"client_secret": true, "password": true,
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
	for name := range u.Query() {
		if decisionModelKeyQueryParams[strings.ToLower(name)] {
			return fmt.Errorf("base_url must not carry a key in its query string (%s=); put the key in %s (decision_model.api_key_env)", name, DefenseClawDecisionModelKeyEnv)
		}
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

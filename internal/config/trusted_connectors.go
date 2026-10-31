// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Trusted connectors (enterprise.identity.trusted_connectors, issue #1392).
//
// A gateway that runs agents for many people calls DefenseClaw as one
// service account. A trusted connector entry names that account and the
// people it may say it acts for. The list is empty by default (the feature
// is off), it is a managed standalone setting only, and the gateway honours
// it only when the live configuration is the content of a signed bundle
// (trust anchors installed); on a CONFIG= install it is ignored with a
// status warning. Validation here is static: whether the account resolves,
// is an administrator or is in an admin group is checked by the gateway at
// start and on every directory refresh, where the account database is.

// TrustedConnectorRouteAgentGateway is the only route a trusted connector
// may assert identity on: /api/v1/agent-gateway/hook (issue #1394).
const TrustedConnectorRouteAgentGateway = "agent-gateway"

// TrustedConnectorsMinProductVersion is the first release that reads
// enterprise.identity.trusted_connectors, connectors.agent_gateway and
// guardrail.chains.root_scope. A bundle that sets any of them must carry
// at least this min_product_version (bundle sign refuses it otherwise).
const TrustedConnectorsMinProductVersion = "1.0.6"

// MaxTrustedConnectors bounds the list; an admin keeps it small.
const MaxTrustedConnectors = 16

// MaxTrustedConnectorPrincipals bounds each may_act_for list.
const MaxTrustedConnectorPrincipals = 256

// EnterpriseIdentityConfig is enterprise.identity.
type EnterpriseIdentityConfig struct {
	TrustedConnectors []TrustedConnectorConfig `mapstructure:"trusted_connectors" yaml:"trusted_connectors,omitempty"`
}

// TrustedConnectorConfig is one enterprise.identity.trusted_connectors entry.
type TrustedConnectorConfig struct {
	// Name labels the connector in audit and status (a token such as gas).
	Name string `mapstructure:"name" yaml:"name"`
	// Account is the service account the connector runs as: a name
	// (svc-gas, CORP\svc-gas, svc-gas@corp.example.com), a uid or a SID.
	// The gateway resolves it to one uid or SID.
	Account string `mapstructure:"account" yaml:"account"`
	// Route is the hook route the connector must use; only agent-gateway.
	Route string `mapstructure:"route" yaml:"route,omitempty"`
	// MayActFor lists the people the connector may act for, by group or
	// user. Group membership always comes from the directory.
	MayActFor TrustedConnectorScope `mapstructure:"may_act_for" yaml:"may_act_for"`
}

// TrustedConnectorScope is may_act_for.
type TrustedConnectorScope struct {
	Groups []string `mapstructure:"groups" yaml:"groups,omitempty"`
	Users  []string `mapstructure:"users"  yaml:"users,omitempty"`
}

// EffectiveRoute is Route with its default.
func (t TrustedConnectorConfig) EffectiveRoute() string {
	if route := strings.ToLower(strings.TrimSpace(t.Route)); route != "" {
		return route
	}
	return TrustedConnectorRouteAgentGateway
}

var trustedConnectorNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// trustedConnectorAdminAccounts are account spellings that are always an
// administrator or a system account, refused before any lookup.
var trustedConnectorAdminAccounts = map[string]bool{
	"root": true, "0": true, "system": true, "nt authority\\system": true,
	"localsystem": true, "administrator": true, "administrators": true,
	"local service": true, "nt authority\\local service": true,
	"network service": true, "nt authority\\network service": true,
	"s-1-5-18": true, "s-1-5-19": true, "s-1-5-20": true, "s-1-5-32-544": true,
}

// TrustedConnectorAccountRefusedStatically reports an account spelling that
// can never be a trusted connector: root and its uid, SYSTEM, LOCAL SERVICE,
// NETWORK SERVICE and their well-known SIDs, the Administrators group, and
// any NT SERVICE virtual account (by name or by its S-1-5-80 SID).
func TrustedConnectorAccountRefusedStatically(account string) bool {
	a := strings.ToLower(strings.TrimSpace(account))
	if a == "" {
		return true
	}
	if trustedConnectorAdminAccounts[a] {
		return true
	}
	if bare := a[strings.LastIndexByte(a, '\\')+1:]; trustedConnectorAdminAccounts[bare] {
		return true
	}
	return strings.HasPrefix(a, "nt service\\") || strings.HasPrefix(a, "s-1-5-80-")
}

// ValidateTrustedConnectors checks enterprise.identity statically.
func ValidateTrustedConnectors(identity EnterpriseIdentityConfig) error {
	entries := identity.TrustedConnectors
	if len(entries) > MaxTrustedConnectors {
		return fmt.Errorf("config: enterprise.identity.trusted_connectors lists %d entries; at most %d are allowed", len(entries), MaxTrustedConnectors)
	}
	names := map[string]bool{}
	accounts := map[string]bool{}
	for i, entry := range entries {
		at := fmt.Sprintf("enterprise.identity.trusted_connectors[%d]", i)
		name := strings.TrimSpace(entry.Name)
		if !trustedConnectorNamePattern.MatchString(name) {
			return fmt.Errorf("config: %s.name %q must be a short lowercase token (letters, digits, - and _)", at, entry.Name)
		}
		if names[name] {
			return fmt.Errorf("config: %s.name %q is listed twice", at, name)
		}
		names[name] = true
		account := strings.TrimSpace(entry.Account)
		if account == "" {
			return fmt.Errorf("config: %s.account is required", at)
		}
		if TrustedConnectorAccountRefusedStatically(account) {
			return fmt.Errorf("config: %s.account %q is an administrator or system account; a trusted connector runs as an ordinary service account", at, account)
		}
		key := strings.ToLower(account)
		if accounts[key] {
			return fmt.Errorf("config: %s.account %q is listed by another trusted connector", at, account)
		}
		accounts[key] = true
		if route := entry.EffectiveRoute(); route != TrustedConnectorRouteAgentGateway {
			return fmt.Errorf("config: %s.route %q is not supported; the only route is %s", at, entry.Route, TrustedConnectorRouteAgentGateway)
		}
		groups, users := entry.MayActFor.Groups, entry.MayActFor.Users
		if len(groups) == 0 && len(users) == 0 {
			return fmt.Errorf("config: %s.may_act_for lists no groups or users; an empty list would let the connector act for no one", at)
		}
		for field, list := range map[string][]string{"groups": groups, "users": users} {
			if len(list) > MaxTrustedConnectorPrincipals {
				return fmt.Errorf("config: %s.may_act_for.%s lists %d entries; at most %d are allowed", at, field, len(list), MaxTrustedConnectorPrincipals)
			}
			seen := map[string]bool{}
			for _, value := range list {
				v := strings.TrimSpace(value)
				if v == "" {
					return fmt.Errorf("config: %s.may_act_for.%s has an empty entry", at, field)
				}
				if seen[strings.ToLower(v)] {
					return fmt.Errorf("config: %s.may_act_for.%s lists %q twice", at, field, v)
				}
				seen[strings.ToLower(v)] = true
				if field == "users" && TrustedConnectorAccountRefusedStatically(v) {
					return fmt.Errorf("config: %s.may_act_for.users lists %q, an administrator or system account; no connector may act for one", at, v)
				}
			}
		}
	}
	// A connector may not act for any connector's service account.
	for i, entry := range entries {
		for _, user := range entry.MayActFor.Users {
			if accounts[strings.ToLower(strings.TrimSpace(user))] {
				return fmt.Errorf("config: enterprise.identity.trusted_connectors[%d].may_act_for.users lists %q, a trusted connector's own account", i, user)
			}
		}
	}
	return nil
}

// ConnectorsConfig is the top-level connectors block.
type ConnectorsConfig struct {
	AgentGateway AgentGatewayConnectorConfig `mapstructure:"agent_gateway" yaml:"agent_gateway,omitempty"`
}

// AgentGatewayConnectorConfig is connectors.agent_gateway (issue #1394): a
// hook route for gateways that call DefenseClaw for an agent. Off by
// default; the route is absent until enabled is true. On a managed device
// the setting comes only from the lifecycle or a signed bundle.
type AgentGatewayConnectorConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// InstanceName labels the calling gateway in audit on a per-user
	// install (a trusted connector's name does on a managed device).
	InstanceName string `mapstructure:"instance_name" yaml:"instance_name,omitempty"`
}

// GuardrailChainsConfig is guardrail.chains (issue #1391).
type GuardrailChainsConfig struct {
	// RootScope evaluates tool-call chains across the sessions of one
	// piece of work, keyed on the root_session_id a trusted connector
	// sends. Off by default; managed only, honoured under the same signed
	// bundle rule as trusted connectors. No effect on a per-user install.
	RootScope bool `mapstructure:"root_scope" yaml:"root_scope,omitempty"`
}

// ValidateIdentityChainSettings checks connectors.agent_gateway and
// guardrail.chains. The Secure Client integration takes neither.
func (c *Config) ValidateIdentityChainSettings() error {
	if c == nil {
		return nil
	}
	name := strings.TrimSpace(c.Connectors.AgentGateway.InstanceName)
	if name != "" && !trustedConnectorNamePattern.MatchString(name) {
		return fmt.Errorf("config: connectors.agent_gateway.instance_name %q must be a short lowercase token (letters, digits, - and _)", c.Connectors.AgentGateway.InstanceName)
	}
	if c.SecureClientIntegration() {
		if c.Connectors.AgentGateway.Enabled || name != "" {
			return fmt.Errorf("config: connectors.agent_gateway is not supported with the Secure Client integration")
		}
		if c.Guardrail.Chains.RootScope {
			return fmt.Errorf("config: guardrail.chains.root_scope is not supported with the Secure Client integration")
		}
	}
	return nil
}

// UsesMinProductVersion106Keys reports whether cfg sets a key that only
// 1.0.6 and later read, so a signed bundle that sets it must carry
// min_product_version 1.0.6 or later.
func (c *Config) UsesMinProductVersion106Keys() []string {
	if c == nil {
		return nil
	}
	var keys []string
	if len(c.Enterprise.Identity.TrustedConnectors) > 0 {
		keys = append(keys, "enterprise.identity.trusted_connectors")
	}
	if c.Connectors.AgentGateway != (AgentGatewayConnectorConfig{}) {
		keys = append(keys, "connectors.agent_gateway")
	}
	if c.Guardrail.Chains.RootScope {
		keys = append(keys, "guardrail.chains.root_scope")
	}
	return keys
}

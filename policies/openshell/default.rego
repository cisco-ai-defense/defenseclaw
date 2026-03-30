# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Default Rego policy for openshell-sandbox, managed by DefenseClaw.
# Loaded via --policy-rules on openshell-sandbox.
#
# This file matches the openshell-sandbox 0.0.16 embedded policy structure.
# The regorus OPA engine requires the `if` keyword but does NOT support
# `import rego.v1` or `import future.keywords`.

package openshell.sandbox

default allow_network = false

# --- Static policy data passthrough (queried at sandbox startup) ---
filesystem_policy := data.filesystem_policy
landlock_policy := data.landlock
process_policy := data.process

# --- Network access decision (queried per-CONNECT request) ---
allow_network if {
	network_policy_for_request
}

# --- Deny reasons (specific diagnostics for debugging policy denials) ---
deny_reason := "missing input.network" if {
	not input.network
}

deny_reason := "missing input.exec" if {
	input.network
	not input.exec
}

deny_reason := reason if {
	input.network
	input.exec
	not network_policy_for_request
	endpoint_misses := [r |
		some name
		policy := data.network_policies[name]
		not endpoint_allowed(policy, input.network)
		r := sprintf("endpoint %s:%d not in policy '%s'", [input.network.host, input.network.port, name])
	]
	ancestors_str := concat(" -> ", input.exec.ancestors)
	cmdline_str := concat(", ", input.exec.cmdline_paths)
	binary_misses := [r |
		some name
		policy := data.network_policies[name]
		endpoint_allowed(policy, input.network)
		not binary_allowed(policy, input.exec)
		r := sprintf("binary '%s' (ancestors: [%s], cmdline: [%s]) not allowed in policy '%s'", [input.exec.path, ancestors_str, cmdline_str, name])
	]
	all_reasons := array.concat(endpoint_misses, binary_misses)
	count(all_reasons) > 0
	reason := concat("; ", all_reasons)
}

deny_reason := "network connections not allowed by policy" if {
	input.network
	input.exec
	not network_policy_for_request
	count(data.network_policies) == 0
}

# --- Matched policy name (for audit logging) ---
_matching_policy_names contains name if {
	some name
	policy := data.network_policies[name]
	endpoint_allowed(policy, input.network)
	binary_allowed(policy, input.exec)
}

matched_network_policy := min(_matching_policy_names) if {
	count(_matching_policy_names) > 0
}

# --- Core matching logic ---
network_policy_for_request if {
	some name
	data.network_policies[name]
	endpoint_allowed(data.network_policies[name], input.network)
	binary_allowed(data.network_policies[name], input.exec)
}

# Endpoint matching: exact host (case-insensitive) + port in ports list.
endpoint_allowed(policy, network) if {
	some endpoint
	endpoint := policy.endpoints[_]
	not contains(endpoint.host, "*")
	lower(endpoint.host) == lower(network.host)
	endpoint.ports[_] == network.port
}

# Endpoint matching: glob host pattern + port in ports list.
endpoint_allowed(policy, network) if {
	some endpoint
	endpoint := policy.endpoints[_]
	contains(endpoint.host, "*")
	glob.match(lower(endpoint.host), ["."], lower(network.host))
	endpoint.ports[_] == network.port
}

# Endpoint matching: hostless with allowed_ips — match any host on port.
endpoint_allowed(policy, network) if {
	some endpoint
	endpoint := policy.endpoints[_]
	object.get(endpoint, "host", "") == ""
	count(object.get(endpoint, "allowed_ips", [])) > 0
	endpoint.ports[_] == network.port
}

# Binary matching: exact path.
binary_allowed(policy, exec) if {
	some b
	b := policy.binaries[_]
	not contains(b.path, "*")
	b.path == exec.path
}

# Binary matching: ancestor exact path (e.g., claude spawns node).
binary_allowed(policy, exec) if {
	some b
	b := policy.binaries[_]
	not contains(b.path, "*")
	ancestor := exec.ancestors[_]
	b.path == ancestor
}

# Binary matching: glob pattern against exe path or any ancestor.
binary_allowed(policy, exec) if {
	some b in policy.binaries
	contains(b.path, "*")
	all_paths := array.concat([exec.path], exec.ancestors)
	some p in all_paths
	glob.match(b.path, ["/"], p)
}

# --- Network action (allow / deny) ---
default network_action := "deny"

network_action := "allow" if {
	network_policy_for_request
}

# ===========================================================================
# L7 request evaluation (queried per-request within a tunnel)
# ===========================================================================
default allow_request = false

_policy_allows_l7(policy) if {
	some ep
	ep := policy.endpoints[_]
	endpoint_matches_request(ep, input.network)
	request_allowed_for_endpoint(input.request, ep)
}

allow_request if {
	some name
	policy := data.network_policies[name]
	endpoint_allowed(policy, input.network)
	binary_allowed(policy, input.exec)
	_policy_allows_l7(policy)
}

# --- L7 deny reason ---
request_deny_reason := reason if {
	input.request
	not allow_request
	reason := sprintf("%s %s not permitted by policy", [input.request.method, input.request.path])
}

# --- L7 rule matching: REST method + path ---
request_allowed_for_endpoint(request, endpoint) if {
	some rule
	rule := endpoint.rules[_]
	rule.allow.method
	method_matches(request.method, rule.allow.method)
	path_matches(request.path, rule.allow.path)
}

# --- L7 rule matching: SQL command ---
request_allowed_for_endpoint(request, endpoint) if {
	some rule
	rule := endpoint.rules[_]
	rule.allow.command
	command_matches(request.command, rule.allow.command)
}

method_matches(_, "*") if true
method_matches(actual, expected) if {
	expected != "*"
	upper(actual) == upper(expected)
}

path_matches(_, "**") if true
path_matches(actual, pattern) if {
	pattern != "**"
	glob.match(pattern, ["/"], actual)
}

command_matches(_, "*") if true
command_matches(actual, expected) if {
	expected != "*"
	upper(actual) == upper(expected)
}

# --- Matched endpoint config (for L7 and allowed_ips extraction) ---
_policy_endpoint_configs(policy) := [ep |
	some ep
	ep := policy.endpoints[_]
	endpoint_matches_request(ep, input.network)
	endpoint_has_extended_config(ep)
]

_matching_endpoint_configs := [cfg |
	some pname
	_matching_policy_names[pname]
	cfgs := _policy_endpoint_configs(data.network_policies[pname])
	cfg := cfgs[_]
]

matched_endpoint_config := _matching_endpoint_configs[0] if {
	count(_matching_endpoint_configs) > 0
}

endpoint_matches_request(ep, network) if {
	not contains(ep.host, "*")
	lower(ep.host) == lower(network.host)
	ep.ports[_] == network.port
}

endpoint_matches_request(ep, network) if {
	contains(ep.host, "*")
	glob.match(lower(ep.host), ["."], lower(network.host))
	ep.ports[_] == network.port
}

endpoint_matches_request(ep, network) if {
	object.get(ep, "host", "") == ""
	count(object.get(ep, "allowed_ips", [])) > 0
	ep.ports[_] == network.port
}

endpoint_has_extended_config(ep) if {
	ep.protocol
}

endpoint_has_extended_config(ep) if {
	count(object.get(ep, "allowed_ips", [])) > 0
}

endpoint_has_extended_config(ep) if {
	ep.tls
}

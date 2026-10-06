# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

package defenseclaw.firewall

import rego.v1

# Evaluates egress firewall rules for a given destination.
# Input fields:
#   target_type - "skill" or "mcp"
#   destination - hostname or IP address
#   port        - destination port number
#   protocol    - "tcp" or "udp"
#
# Static data (data.json):
#   firewall.default_action          - "deny" or "allow"
#   firewall.blocked_destinations    - always-blocked IPs/hosts
#   firewall.allowed_domains         - explicitly allowed domains
#   firewall.allowed_ports           - allowed port numbers

default action := "deny"

default rule_name := "default-deny"

# Explicit block rules take highest priority.
action := "deny" if {
	_is_blocked_destination
}

rule_name := "block-explicit" if {
	_is_blocked_destination
}

# Allowed if domain + port match.
action := "allow" if {
	not _is_blocked_destination
	_is_allowed_domain
	_is_allowed_port
}

rule_name := "domain-allowlist" if {
	not _is_blocked_destination
	_is_allowed_domain
	_is_allowed_port
}

# Default action from config when no explicit match.
action := data.firewall.default_action if {
	not _is_blocked_destination
	not _is_allowed_domain
}

rule_name := "default-policy" if {
	not _is_blocked_destination
	not _is_allowed_domain
}

# Domain allowed but port not in allowlist (only if ports are configured).
action := "deny" if {
	not _is_blocked_destination
	_is_allowed_domain
	not _is_allowed_port
	count(data.firewall.allowed_ports) > 0
}

rule_name := "port-restricted" if {
	not _is_blocked_destination
	_is_allowed_domain
	not _is_allowed_port
	count(data.firewall.allowed_ports) > 0
}

# --- Helper rules ---

_is_blocked_destination if {
	some blocked in data.firewall.blocked_destinations
	input.destination == blocked
}

_is_allowed_domain if {
	some domain in data.firewall.allowed_domains
	input.destination == domain
}

_is_allowed_port if {
	count(data.firewall.allowed_ports) == 0
}

_is_allowed_port if {
	some port in data.firewall.allowed_ports
	input.port == port
}
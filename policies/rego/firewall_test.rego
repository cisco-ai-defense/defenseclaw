package defenseclaw.firewall_test

import rego.v1

import data.defenseclaw.firewall

_default_fw_data := {
	"default_action": "deny",
	"blocked_destinations": ["169.254.169.254", "fd00:ec2::254"],
	"allowed_domains": ["api.github.com", "registry.npmjs.org"],
	"allowed_ports": [443, 80],
}

test_block_cloud_metadata if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "169.254.169.254",
		"port": 80,
		"protocol": "tcp",
	}
		with data.firewall as _default_fw_data

	result.action == "deny"
}

test_allow_github_https if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "api.github.com",
		"port": 443,
		"protocol": "tcp",
	}
		with data.firewall as _default_fw_data

	result.action == "allow"
	result.rule_name == "domain-allowlist"
}

test_deny_unknown_domain if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "evil.com",
		"port": 443,
		"protocol": "tcp",
	}
		with data.firewall as _default_fw_data

	result.action == "deny"
}

test_deny_allowed_domain_wrong_port if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "api.github.com",
		"port": 8080,
		"protocol": "tcp",
	}
		with data.firewall as _default_fw_data

	result.action == "deny"
	result.rule_name == "port-restricted"
}

test_allow_any_port_when_no_port_restriction if {
	result := firewall with input as {
		"target_type": "mcp",
		"destination": "api.github.com",
		"port": 9999,
		"protocol": "tcp",
	}
		with data.firewall as {
			"default_action": "deny",
			"blocked_destinations": [],
			"allowed_domains": ["api.github.com"],
			"allowed_ports": [],
		}

	result.action == "allow"
}

test_block_ipv6_metadata if {
	result := firewall with input as {
		"target_type": "skill",
		"destination": "fd00:ec2::254",
		"port": 80,
		"protocol": "tcp",
	}
		with data.firewall as _default_fw_data

	result.action == "deny"
}

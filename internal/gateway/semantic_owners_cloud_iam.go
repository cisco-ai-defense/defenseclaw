// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

var semanticCloudIAMOwners = map[string]semanticOwner{
	"defense_evasion.cloud_security_telemetry_disable": {
		prerequisite: cloudAuditOperationPrerequisite(actionfacts.CloudAuditTelemetryDisable),
		alertOnly:    true,
	},
	"exfiltration.cloud_external_snapshot_share": {
		prerequisite: cloudAuditOperationPrerequisite(actionfacts.CloudAuditExternalSnapshotShare),
		alertOnly:    true,
	},
	"exposure.cloud_worldwide_ssh": {
		prerequisite: cloudAuditOperationPrerequisite(actionfacts.CloudAuditWorldwideSSHExposure),
		alertOnly:    true,
	},
	"defense_evasion.endpoint_defender_exclusion": {
		prerequisite: endpointSecurityMutationPrerequisite(actionfacts.EndpointDefenderExclusionAdded),
		alertOnly:    true,
	},
	"defense_evasion.endpoint_defender_logging_disable": {
		prerequisite: endpointSecurityMutationPrerequisite(actionfacts.EndpointDefenderLoggingDisabled),
		alertOnly:    true,
	},
	"impact.cloud_s3_data_delete": {
		prerequisite: func(facts actionfacts.Facts) bool {
			for _, mutation := range actionfacts.ExactCloudResourceMutations(facts) {
				if mutation.Recursive {
					return true
				}
			}
			return false
		},
		suppressFallback: authoritativeSemanticSafeNegative,
		// Only exact recursive prefix/bucket destruction is visible here. Single
		// object cleanup remains a fact for chains but creates no atomic finding.
		alertOnly: true,
	},
	"privilege.cloud_iam_administrator_attachment": {
		prerequisite: func(facts actionfacts.Facts) bool {
			return actionfacts.ExactCloudIAMAdministratorAttachment(facts) ||
				cloudAuditOperationPrerequisite(actionfacts.CloudAuditAdministratorAttach)(facts)
		},
		suppressFallback: authoritativeSemanticSafeNegative,
		// AdministratorAccess can be legitimate provisioning. The standalone
		// terminal fact and the same-principal chain stay visible but cannot
		// block until trusted protected-account policy reaches the matcher.
		detectionOnly: true,
	},
	"privilege.cloud_iam_wildcard_inline_policy": {
		prerequisite:     actionfacts.ExactCloudIAMWildcardInlinePolicy,
		suppressFallback: authoritativeSemanticSafeNegative,
		// A universal inline policy is highly privileged but may be intentional
		// provisioning. Keep it visible without universal blocking.
		alertOnly: true,
	},
}

func endpointSecurityMutationPrerequisite(operation actionfacts.EndpointSecurityControlMutation) semanticOwnerPrerequisite {
	return func(facts actionfacts.Facts) bool {
		for _, fact := range actionfacts.ExactEndpointSecurityControlMutations(facts) {
			if fact.Operation == operation {
				return true
			}
		}
		return false
	}
}

func cloudAuditOperationPrerequisite(operation actionfacts.CloudAuditSecurityOperation) semanticOwnerPrerequisite {
	return func(facts actionfacts.Facts) bool {
		for _, fact := range actionfacts.ExactCloudAuditSecurityOperations(facts) {
			if fact.Operation == operation {
				return true
			}
		}
		return false
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

const semanticKubernetesCronJobPrivilegedPatchExpression = `f.tool == 'kubectl'`

const semanticKubernetesPrivilegedPodRunExpression = `f.tool == 'kubectl'`

const semanticKubernetesCronJobReverseShellExpression = `f.tool == 'kubectl'`

const semanticKubernetesClusterWideSecretEnumerationExpression = `f.tool == 'kubectl'`

const semanticKubernetesWorkloadIdentityTokenReadExpression = `f.tool == 'kubectl'`

const kubernetesBatchSecretCollectionRuleID = "credential.kubernetes_batch_secret_collection"

const semanticKubernetesClusterAdminBindingExpression = `f.commands.exists(c,
c.argv_complete && c.program == 'kubectl' &&
defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_PERMISSION_CHANGE in c.operations &&
defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_PRIVILEGE in c.operations)`

var semanticKubernetesOwners = map[string]semanticOwner{
	"privilege.kubernetes_cluster_admin_binding": {
		prerequisite:     kubernetesClusterAdminBindingPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// Exact cluster-admin grants are high-value privilege signals but can be
		// legitimate administration. Keep the universal policy alert-only;
		// protected-cluster policy may choose stronger enforcement.
		alertOnly: true,
	},
	"privilege.kubernetes_cronjob_privileged_patch": {
		prerequisite: kubernetesCronJobPrivilegedPatchPrerequisite,
		// A literal privileged CronJob mutation is a strong local signal, but
		// legitimate cluster administration has the same observable shape.
		// Preserve a HIGH alert in every built-in profile; only a future trusted
		// protected-cluster policy may authorize a synchronous deny.
		alertOnly: true,
	},
	"privilege.kubernetes_privileged_pod_run": {
		prerequisite: kubernetesPrivilegedPodRunPrerequisite,
		// Privileged pods are a strong escalation primitive but also a valid
		// administrative operation. Universal profiles alert; protected-cluster
		// packs can enforce them using deployment context.
		alertOnly: true,
	},
	"persistence.kubernetes_cronjob_reverse_shell": {
		prerequisite: kubernetesCronJobReverseShellPrerequisite,
		// The exact operation is high-confidence malicious detection evidence,
		// but universal profiles do not know whether this is an authorized
		// security exercise. Keep it visible without granting block authority.
		detectionOnly: true,
	},
	"secrets.kubernetes_cluster_wide_enumeration": {
		prerequisite: kubernetesClusterWideSecretEnumerationPrerequisite,
		// Listing Secrets across every namespace is a high-value credential
		// discovery signal but remains legitimate cluster administration. Built-in
		// profiles alert only; protected-cluster policy may enforce it.
		alertOnly: true,
	},
	"secrets.kubernetes_workload_identity_token_read": {
		prerequisite: kubernetesWorkloadIdentityTokenReadPrerequisite,
		// Reading a pod token is a high-value credential-access signal but can
		// be legitimate administration. Universal profiles alert only; a
		// protected-cluster policy may enforce it with deployment context.
		alertOnly: true,
	},
}

func init() {
	if _, exists := exactFallbackContracts[kubernetesBatchSecretCollectionRuleID]; exists {
		panic("duplicate exact Kubernetes semantic owner " + kubernetesBatchSecretCollectionRuleID)
	}
	// This owner needs the private authenticated tool-resource identity and the
	// original closed structured arguments, neither of which belongs in the CEL
	// projection. The code-owned exact lane is therefore the semantic authority;
	// the inert catalog pattern cannot create a finding by itself.
	exactFallbackContracts[kubernetesBatchSecretCollectionRuleID] = exactFallbackContract{
		proves: func(input actionfacts.Input, _ actionfacts.Facts) bool {
			_, ok := actionfacts.ExactKubernetesBatchSecretCollection(input)
			return ok
		},
		boundedSubgraphProves: func(input actionfacts.Input, _ actionfacts.Facts) bool {
			_, ok := actionfacts.ExactKubernetesBatchSecretCollection(input)
			return ok
		},
		requiresExactDetectionProof: true,
		codeOwnedDetection:          true,
	}
}

func kubernetesWorkloadIdentityTokenReadPrerequisite(facts actionfacts.Facts) bool {
	return actionfacts.ExactKubernetesWorkloadIdentityTokenRead(facts)
}

func kubernetesClusterWideSecretEnumerationPrerequisite(facts actionfacts.Facts) bool {
	_, ok := actionfacts.ExactKubernetesSensitiveAccess(facts)
	return ok
}

func kubernetesPrivilegedPodRunPrerequisite(facts actionfacts.Facts) bool {
	_, ok := actionfacts.ExactKubernetesPodRun(facts)
	return ok
}

func kubernetesCronJobReverseShellPrerequisite(facts actionfacts.Facts) bool {
	_, ok := actionfacts.ExactKubernetesCronJobReverseShell(facts)
	return ok
}

func kubernetesClusterAdminBindingPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.ArgvComplete && command.Program == "kubectl" &&
			hasOperation(command, actionfacts.OperationPermissionChange) &&
			hasOperation(command, actionfacts.OperationPrivilege) {
			return true
		}
	}
	return false
}

func kubernetesCronJobPrivilegedPatchPrerequisite(facts actionfacts.Facts) bool {
	fact, ok := actionfacts.ExactKubernetesCronJobOperation(facts)
	return ok && fact.Operation == actionfacts.KubernetesCronJobPrivilegedPatch
}

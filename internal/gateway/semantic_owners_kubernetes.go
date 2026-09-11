// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

const semanticKubernetesCronJobPrivilegedPatchExpression = `f.tool == 'kubectl'`

var semanticKubernetesOwners = map[string]semanticOwner{
	"privilege.kubernetes_cronjob_privileged_patch": {
		prerequisite: kubernetesCronJobPrivilegedPatchPrerequisite,
		// A literal privileged CronJob mutation is a strong local signal, but
		// legitimate cluster administration has the same observable shape.
		// Preserve a HIGH alert in every built-in profile; only a future trusted
		// protected-cluster policy may authorize a synchronous deny.
		alertOnly: true,
	},
}

func kubernetesCronJobPrivilegedPatchPrerequisite(facts actionfacts.Facts) bool {
	fact, ok := actionfacts.ExactKubernetesCronJobOperation(facts)
	return ok && fact.Operation == actionfacts.KubernetesCronJobPrivilegedPatch
}

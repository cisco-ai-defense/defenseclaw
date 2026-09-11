// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

var semanticCloudIAMOwners = map[string]semanticOwner{
	"privilege.cloud_iam_administrator_attachment": {
		prerequisite:     actionfacts.ExactCloudIAMAdministratorAttachment,
		suppressFallback: authoritativeSemanticSafeNegative,
		// AdministratorAccess can be legitimate provisioning. The standalone
		// terminal fact and the same-principal chain stay visible but cannot
		// block until trusted protected-account policy reaches the matcher.
		detectionOnly: true,
	},
}

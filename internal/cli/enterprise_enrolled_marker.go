// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookcli"
)

// enterpriseHomeConnectorEnrolledBefore is enterpriseConnectorEnrolledBefore
// for an account's profile folder.
func enterpriseHomeConnectorEnrolledBefore(userHome, connector string) bool {
	userHome = strings.TrimSpace(userHome)
	if userHome == "" {
		return false
	}
	return hookcli.EnterpriseConnectorEnrolledBefore(filepath.Join(userHome, ".defenseclaw"), connector)
}

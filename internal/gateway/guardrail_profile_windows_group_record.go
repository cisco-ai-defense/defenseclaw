// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// profileGroupSIDsForAccount takes group identifiers from an identity record.
func profileGroupSIDsForAccount(accountSID string, record enterprisehooks.IdentitySpoolRecord) ([]string, error) {
	accountSID = strings.ToUpper(strings.TrimSpace(accountSID))
	if !strings.HasPrefix(accountSID, "S-1-") || !strings.EqualFold(strings.TrimSpace(record.Key), accountSID) {
		return nil, errors.New("profile groups: identity record belongs to another account")
	}
	if record.Facts.GroupsPartial {
		return nil, errors.New("profile groups: current token groups are unavailable")
	}
	seen := map[string]bool{}
	var ids []string
	for _, value := range record.Facts.Groups {
		sid := strings.ToUpper(strings.TrimSpace(value))
		if strings.HasPrefix(sid, "S-1-") && !seen[sid] {
			ids = append(ids, sid)
			seen[sid] = true
		}
	}
	return ids, nil
}

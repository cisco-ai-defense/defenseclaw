// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/acp"
)

// revokeEnterpriseACPEnrollmentsOfDeletedSIDs revokes the managed ACP
// enrollments of the Windows accounts deleted reports gone. The enumerator
// runs it every cycle: the credential of a deleted local account stayed
// valid, listed as "account deleted", until someone revoked it by hand
// (GAP-0367). The user's copy is not touched: its account is gone.
func revokeEnterpriseACPEnrollmentsOfDeletedSIDs(dataDir string, deleted func(sid string) bool, stderr io.Writer) (revoked []string) {
	if strings.TrimSpace(dataDir) == "" || deleted == nil {
		return nil
	}
	enrollments, _, err := acp.ListEnterpriseEnrollments(dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "[acp-enrollments] warn: could not read the managed ACP enrollments: %v\n", err)
		return nil
	}
	for _, enrollment := range enrollments {
		kind, sid, _ := strings.Cut(enrollment.Principal, ":")
		if kind != "sid" || sid == "" || !deleted(sid) {
			continue
		}
		pair := fmt.Sprintf("%s %s/%s/%s", enrollment.Principal, enrollment.ClientID, enrollment.AgentID, enrollment.Profile)
		if err := acp.RemoveEnterpriseCredential(dataDir, enrollment.Principal, enrollment.ClientID, enrollment.AgentID, enrollment.Profile); err != nil {
			fmt.Fprintf(stderr, "[acp-enrollments] warn: %s: the account no longer exists, but its ACP enrollment could not be revoked: %v\n", pair, err)
			continue
		}
		fmt.Fprintf(stderr, "[acp-enrollments] %s: the account no longer exists; revoked its ACP enrollment\n", pair)
		revoked = append(revoked, pair)
	}
	return revoked
}

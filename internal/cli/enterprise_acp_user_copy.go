// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// removeEnterpriseACPUserTokenCopy removes a user's copy of an ACP
// credential; run it as that user. A missing copy is not an error.
func removeEnterpriseACPUserTokenCopy(tokenPath string) error {
	info, err := os.Lstat(tokenPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to remove unsafe ACP user token path")
	}
	return os.Remove(tokenPath)
}

// enterpriseACPSignedOut reports a target Windows account with no session to
// act under.
func enterpriseACPSignedOut(err error) bool {
	var session *enterprisehooks.WindowsTargetSessionUnavailableError
	return errors.As(err, &session)
}

// enterpriseACPDeferUserCopyCleanup records the user copy of a revoked
// enrollment for removal at the user's next sign-in, and says so. A revoke
// of a signed-out user used to fail and ask for the enrollment to be run
// again, which would issue the credential afresh (GAP-0718).
func enterpriseACPDeferUserCopyCleanup(enrollment enterpriseACPEnrollment, tokenPath string) string {
	who := enterpriseACPWho(enrollment)
	entry := acp.EnterpriseUserCopyCleanup{
		SID: strings.ToUpper(strings.TrimSpace(enrollment.target.sid)), ClientID: enrollment.client, AgentID: enrollment.agent,
		UserHome: enrollment.target.home, TokenFile: tokenPath, RecordedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	err := errors.New("the account has no SID")
	if entry.SID != "" {
		err = withEnterpriseACPServiceOwner(cfg.DataDir, func() error {
			return acp.UpdateEnterpriseUserCopyCleanups(cfg.DataDir, func(entries []acp.EnterpriseUserCopyCleanup) []acp.EnterpriseUserCopyCleanup {
				kept := entries[:0]
				for _, existing := range entries {
					if !strings.EqualFold(existing.SID, entry.SID) || existing.ClientID != entry.ClientID || existing.AgentID != entry.AgentID {
						kept = append(kept, existing)
					}
				}
				return append(kept, entry)
			})
		})
	}
	if err != nil {
		return fmt.Sprintf("%s is signed out, so the user's copy %s stays (it no longer works); run this revoke again while %s is signed in to remove it (recording it for the next sign-in failed: %v)",
			who, tokenPath, who, err)
	}
	return fmt.Sprintf("%s is signed out, so the user's copy %s stays until the next sign-in, when DefenseClaw removes it; it no longer works", who, tokenPath)
}

// cleanEnterpriseACPUserCopies removes the recorded user copies of revoked
// enrollments (GAP-0718). remove runs as the user and reports false while
// the user is still signed out; an account deleted or enrolled again since
// drops its entry.
func cleanEnterpriseACPUserCopies(
	dataDir string,
	remove func(acp.EnterpriseUserCopyCleanup) (bool, error),
	deleted func(sid string) bool,
	stderr io.Writer,
) {
	// Enrollment can publish a new copy after the list is read. Hold its
	// transaction lock through removal and the list update (GAP-0982).
	var unlock func()
	if err := withEnterpriseACPServiceOwner(dataDir, func() error {
		var lockErr error
		unlock, lockErr = acp.AcquireEnterpriseCredentialEnrollmentLock(dataDir)
		return lockErr
	}); err != nil {
		fmt.Fprintf(stderr, "[acp-enrollments] warn: could not lock ACP user copy cleanup: %v\n", err)
		return
	}
	defer unlock()
	pending, err := acp.EnterpriseUserCopyCleanups(dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "[acp-enrollments] warn: could not read the ACP user copies waiting for removal: %v\n", err)
	}
	if len(pending) == 0 {
		return
	}
	enrollments, _, err := acp.ListEnterpriseEnrollments(dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "[acp-enrollments] warn: could not read the managed ACP enrollments: %v\n", err)
		return
	}
	enrolled := map[string]bool{}
	for _, enrollment := range enrollments {
		if sid, ok := strings.CutPrefix(enrollment.Principal, "sid:"); ok {
			enrolled[strings.ToUpper(sid)+"\x00"+enrollment.ClientID+"\x00"+enrollment.AgentID] = true
		}
	}
	done := map[acp.EnterpriseUserCopyCleanup]bool{}
	for _, entry := range pending {
		switch {
		case enrolled[strings.ToUpper(entry.SID)+"\x00"+entry.ClientID+"\x00"+entry.AgentID]:
			// Enrolled again: the copy holds the new credential.
			done[entry] = true
		case deleted != nil && deleted(entry.SID):
			done[entry] = true
		default:
			removed, removeErr := remove(entry)
			if removeErr != nil {
				fmt.Fprintf(stderr, "[acp-enrollments] warn: could not remove the revoked ACP token copy %s of %s: %v (will retry)\n", entry.TokenFile, entry.SID, removeErr)
				continue
			}
			if removed {
				done[entry] = true
				fmt.Fprintf(stderr, "[acp-enrollments] removed the revoked ACP token copy %s of %s\n", entry.TokenFile, entry.SID)
			}
		}
	}
	if len(done) == 0 {
		return
	}
	if err := acp.UpdateEnterpriseUserCopyCleanups(dataDir, func(entries []acp.EnterpriseUserCopyCleanup) []acp.EnterpriseUserCopyCleanup {
		kept := entries[:0]
		for _, entry := range entries {
			if !done[entry] {
				kept = append(kept, entry)
			}
		}
		return kept
	}); err != nil {
		fmt.Fprintf(stderr, "[acp-enrollments] warn: could not update the ACP user copies waiting for removal: %v\n", err)
	}
}

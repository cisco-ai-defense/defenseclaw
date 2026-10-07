// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// enterpriseACPTargetRefusal says why an enrollment could not reach the
// target Windows account and how to enroll. The hook guardian errors it
// wraps named hook mutation and gave no next step (GAP-0261).
type enterpriseACPTargetRefusal struct {
	message string
	err     error
}

func (e *enterpriseACPTargetRefusal) Error() string { return e.message }
func (e *enterpriseACPTargetRefusal) Unwrap() error { return e.err }

const enterpriseACPWindowsEnrollForm = "run it as LocalSystem (an MDM script or a SYSTEM scheduled task) while the user is signed in, " +
	`and name the user with --user DOMAIN\name or --sid S-1-5-21-...`

// enterpriseACPWindowsTargetError turns the Windows refusals of the target
// account into what an administrator can do: only LocalSystem can act as a
// signed-in user (notLocalSystem reports the refusal for any other
// caller), only while that user has a session, and --user-home alone names
// the folder owner, which is SYSTEM for a profile folder Windows created.
func enterpriseACPWindowsTargetError(err error, notLocalSystem bool) error {
	var session *enterprisehooks.WindowsTargetSessionUnavailableError
	switch {
	case err == nil:
		return nil
	case notLocalSystem:
		return &enterpriseACPTargetRefusal{err: err, message: "enterprise acp: on Windows only LocalSystem can write the ACP token " +
			"into a user profile, and this prompt is not LocalSystem; " + enterpriseACPWindowsEnrollForm}
	case errors.As(err, &session):
		return &enterpriseACPTargetRefusal{err: err, message: fmt.Sprintf(
			"enterprise acp: %s has no signed-in session, and the ACP token is written as the signed-in user; "+
				"run the enrollment again while that user is signed in (nothing retries it)", strings.TrimSpace(session.SID))}
	case strings.Contains(err.Error(), "refusing non-interactive target SID"):
		return &enterpriseACPTargetRefusal{err: err, message: "enterprise acp: the target is a system account, not a user (" +
			err.Error() + "); --user-home alone names the owner of the folder; " + enterpriseACPWindowsEnrollForm}
	}
	return err
}

// enterpriseACPRefusal is what enroll, verify and revoke report when the
// target account could not be reached. Secure Client keeps the hook
// guardian wording it has on main.
func enterpriseACPRefusal(err error) error {
	if cfg != nil && cfg.SecureClientIntegration() {
		return err
	}
	return enterpriseACPTargetError(err)
}

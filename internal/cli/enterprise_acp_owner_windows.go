//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"golang.org/x/sys/windows"
)

// configureEnterpriseACPTargetLookup does nothing on Windows: accounts
// resolve through the local security authority.
func configureEnterpriseACPTargetLookup(context.Context) {}

// enterpriseACPUnknownAccount reports an account name the local security
// authority does not know.
func enterpriseACPUnknownAccount(err error) bool { return errors.Is(err, windows.ERROR_NONE_MAPPED) }

// enterpriseACPNoAccountText is the refusal for an unknown account name.
func enterpriseACPNoAccountText(name string) string {
	return "enterprise acp: no account named " + name + " on this computer or its domain; " +
		`check the spelling and the domain prefix (DOMAIN\name)`
}

// enterpriseACPNoHomeText is the refusal for an account whose profile folder
// does not exist: Windows creates it at the first sign-in, and Setup /ensure
// does not (GAP-0715).
func enterpriseACPNoHomeText(who, home, sid string) string {
	if _, err := enterpriseHookSIDProfilePath(sid); err == nil {
		return fmt.Sprintf("enterprise acp: the profile folder of %s (%s) was removed; have the user sign in again, "+
			"which recreates it, then run this enrollment again while they are signed in", who, home)
	}
	return fmt.Sprintf("enterprise acp: %s has not signed in on this computer yet, so it has no profile folder (%s) "+
		"for the ACP token; have the user sign in once, then run this enrollment again while they are signed in", who, home)
}

// enterpriseACPTargetError says how to enroll on Windows when the target
// account cannot be reached (GAP-0261).
func enterpriseACPTargetError(err error) error {
	return enterpriseACPWindowsTargetError(err, errors.Is(err, enterprisehooks.ErrWindowsEnterpriseNotLocalSystem))
}

// withEnterpriseACPServiceOwner runs fn as is: on Windows the elevated
// caller hardens the records with ACLs for the gateway service afterwards
// (alignEnterpriseACPCredentialOwner).
func withEnterpriseACPServiceOwner(_ string, fn func() error) error { return fn() }

func alignEnterpriseACPCredentialOwner(dataDir, principal, client, agent, profile, token string) error {
	path, err := acp.EnterpriseCredentialPath(dataDir, principal, client, agent, profile)
	if err != nil {
		return err
	}
	indexPath, err := acp.EnterpriseCredentialIndexPath(dataDir, token)
	if err != nil {
		return err
	}
	owner, err := enterpriseWindowsPathOwner(dataDir)
	if err != nil {
		return fmt.Errorf("enterprise ACP: inspect managed data_dir owner: %w", err)
	}
	serviceSID, err := enterpriseWindowsGatewayServiceSID()
	if err != nil {
		return err
	}
	for _, directory := range []string{filepath.Join(dataDir, "acp"), filepath.Dir(path), filepath.Dir(indexPath)} {
		if err := setEnterpriseWindowsRuntimeProtection(directory, owner, serviceSID, true); err != nil {
			return fmt.Errorf("enterprise ACP: harden service credential directory: %w", err)
		}
	}
	if err := setEnterpriseWindowsRuntimeProtection(path, owner, serviceSID, false); err != nil {
		return fmt.Errorf("enterprise ACP: harden service credential: %w", err)
	}
	if err := setEnterpriseWindowsRuntimeProtection(indexPath, owner, serviceSID, false); err != nil {
		return fmt.Errorf("enterprise ACP: harden service credential index: %w", err)
	}
	return nil
}

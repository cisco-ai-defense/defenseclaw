//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/acp"
)

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

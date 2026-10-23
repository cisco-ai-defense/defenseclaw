// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ValidateManagedStandaloneRuntimeCandidate runs the managed gateway's
// service-time content and policy-input checks on a staged standalone config.
// The caller checks the staged file's ownership and fixed data_dir layout
// separately. Setup creates or re-stamps that runtime directory's ACL during
// the transaction, before the strict installed-file load. Checking its old
// ACL here would prevent ensure from repairing ordinary drift.
func ValidateManagedStandaloneRuntimeCandidate(cfg *Config) error {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return errors.New("standalone runtime candidate is unavailable")
	}
	return validateManagedEnterpriseRuntime(cfg, true, false, true)
}

// ValidateManagedStandaloneRuntimeContent checks the service-time rules that
// depend only on config values. The Unix lifecycle validates policy inputs
// separately through its rooted filesystem and trust callback.
func ValidateManagedStandaloneRuntimeContent(cfg *Config) error {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return errors.New("standalone runtime candidate is unavailable")
	}
	return validateManagedEnterpriseRuntime(cfg, false, false, true)
}

func validateManagedEnterpriseRuntime(cfg *Config, checkPolicyInputs, checkDataDir, checkListener bool) error {
	if checkDataDir {
		if err := managed.ValidateTrustedServiceRuntimeDir(
			cfg.DataDir, "managed data_dir", os.Getenv(managed.WindowsServiceAccountEnv),
		); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "managed_data_dir_untrusted")
			}
			return fmt.Errorf("config: managed_enterprise data_dir trust check failed: %w", err)
		}
	}
	if checkListener {
		if err := ValidateManagedEnterpriseListenerBindings(cfg); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "managed_listener_non_loopback")
			}
			return err
		}
	}
	if checkPolicyInputs {
		if err := validateManagedStandalonePolicyInputs(cfg); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "managed_policy_input_untrusted")
			}
			return err
		}
	}
	if err := ValidateManagedEnterpriseWindowsPeerAuthKnobs(cfg); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "managed_ipc_peer_auth_unsupported_on_windows")
		}
		return err
	}
	return nil
}

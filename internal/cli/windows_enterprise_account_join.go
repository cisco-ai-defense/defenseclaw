// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
	"github.com/defenseclaw/defenseclaw/internal/accountjoin/devicekeys"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsAccountJoinReport computes the account join keys for an elevated
// caller while the installed config turns enterprise.account_join on; nil
// otherwise. The keys are computed here and never stored: status and
// verify carry only their summary.
func windowsAccountJoinReport(cfg *config.Config, layout managed.StandaloneLayout) *accountjoin.Report {
	if cfg == nil || !cfg.Enterprise.AccountJoin.On() || !windowsEnterpriseIsElevated() {
		return nil
	}
	return devicekeys.Report(devicekeys.Sources{
		Config:       cfg.Enterprise.AccountJoin,
		SecureClient: managed.IsSecureClientProfile(cfg.Enterprise.Profile),
		Tenant: func() (string, error) {
			path, err := enterprisebundle.AnchorsPath("windows")
			if err != nil {
				return "", err
			}
			anchors, err := enterprisebundle.LoadAnchors(path, enterprisebundle.TrustAnchorFile)
			if err != nil {
				return "", err
			}
			return anchors.TenantID, nil
		},
		ReadSecret: func(name string) ([]byte, error) {
			// As the gateway service account the store grants read to.
			value, _, err := managed.ResolveServiceCredentialAs(name, layout.SecretsDir, windowsSecretGatewayAccount)
			return value, err
		},
		SpoolDir:   enterprisehooks.IdentitySpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir)),
		SpoolTrust: managed.ValidateTrustedFilePath,
		// next_not_after is bounded by the time the confirmed bundle that
		// carries it was signed (rel-1-0-6:GAP-0277).
		SignedAt: func(generation int, notAfter time.Time) (time.Time, bool) {
			store, err := bundleStore()
			if err != nil {
				return time.Time{}, false
			}
			return store.ConfirmedAccountJoinSignedAt(generation, notAfter)
		},
		StatePath: filepath.Join(layout.LifecycleDir, devicekeys.StateFileName),
		GOOS:      "windows",
		Now:       time.Now(),
	})
}

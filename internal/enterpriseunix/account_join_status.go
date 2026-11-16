// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

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

// confirmedAccountJoinSignedAt reads the signing time of the confirmed
// bundle that carries next_not_after (tests replace it).
var confirmedAccountJoinSignedAt = func(s *enterprisebundle.Store, generation int, notAfter time.Time) (time.Time, bool) {
	return s.ConfirmedAccountJoinSignedAt(generation, notAfter)
}

// describeAccountJoin adds the account_join summary (counts and reason
// codes, no key) to a status or verify run as root while the installed
// config turns enterprise.account_join on.
func (l *lifecycle) describeAccountJoin() {
	if report := l.env.AccountJoinReport(); report != nil {
		summary := report.Summary()
		l.result.AccountJoin = &summary
	}
}

// AccountJoinReport computes the account join keys for a caller running as
// root while the installed config turns enterprise.account_join on; nil
// otherwise. The keys are computed from the verified bundle tenant, the
// protected tenant secrets and the guardian's identity spool, and never
// stored.
func (env *Env) AccountJoinReport() *accountjoin.Report {
	if env.Geteuid() != 0 {
		return nil
	}
	raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes)
	if err != nil {
		return nil
	}
	cfg, err := env.loadConfigCandidate(raw)
	if err != nil || cfg == nil || !cfg.Enterprise.AccountJoin.On() {
		return nil
	}
	return devicekeys.Report(env.accountJoinSources(cfg))
}

// accountJoinSources are the device inputs of the account join keys for the
// installed config cfg.
func (env *Env) accountJoinSources(cfg *config.Config) devicekeys.Sources {
	return devicekeys.Sources{
		Config:       cfg.Enterprise.AccountJoin,
		SecureClient: managed.IsSecureClientProfile(cfg.Enterprise.Profile),
		Tenant: func() (string, error) {
			path, err := enterprisebundle.AnchorsPath(env.GOOS)
			if err != nil {
				return "", err
			}
			anchors, err := enterprisebundle.LoadAnchors(env.P(path), func(p string) error { return env.Trust(p, TrustAdminFile) })
			if err != nil {
				return "", err
			}
			return anchors.TenantID, nil
		},
		ReadSecret: func(name string) ([]byte, error) {
			value, _, err := managed.ResolveServiceCredential(name, env.P(env.Layout.SecretsDir))
			return value, err
		},
		SpoolDir:   enterprisehooks.IdentitySpoolDir(env.P(env.Layout.GuardianAuthDir)),
		SpoolTrust: func(path, _ string) error { return env.Trust(path, TrustAdminFile) },
		// next_not_after is bounded by the time the confirmed bundle that
		// carries it was signed (rel-1-0-6:GAP-0277).
		SignedAt: func(generation int, notAfter time.Time) (time.Time, bool) {
			return confirmedAccountJoinSignedAt(env.bundleStore(), generation, notAfter)
		},
		StatePath: filepath.Join(env.P(env.Layout.LifecycleDir), devicekeys.StateFileName),
		GOOS:      env.GOOS,
		Now:       env.Now(),
	}
}

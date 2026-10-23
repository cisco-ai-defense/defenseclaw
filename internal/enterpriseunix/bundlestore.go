// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

const (
	codeBundleStateUnreadable = "bundle_state_unreadable"
	codeBundleInterrupted     = "bundle_interrupted"
	codeBundleUnconfirmed     = "bundle_unconfirmed"
)

// bundleStore is the signed policy bundle store of this deployment
// (<etc>/bundles, state and receipts in the lifecycle directory).
func (e *Env) bundleStore() *enterprisebundle.Store {
	s := enterprisebundle.NewStore(e.P(filepath.Join(e.Layout.ConfigDir, enterprisebundle.BundlesDirName)), e.P(e.Layout.LifecycleDir))
	s.Now = e.Now
	s.ReceiptEventReported = func(id string) bool {
		return enterprisestatus.ReceiptEventReported(e.P(e.Layout.DataDir), id)
	}
	s.PublishReceipt = func(path string) error {
		if filepath.Dir(path) == s.PublicReceiptEventsDir() {
			if err := e.ensureDir(s.PublicReceiptEventsDir(), 0o755, rootOwner()); err != nil {
				return err
			}
		}
		return e.fixMetadata(path, 0o644, rootOwner())
	}
	return s
}

// bundleStoreForGroup seals promoted versions for the gateway's service
// group. Read-only status and settlement use bundleStore without this hook.
func (e *Env) bundleStoreForGroup(gid int) *enterprisebundle.Store {
	s := e.bundleStore()
	s.SealVersion = func(root string) error {
		return enterprisebundle.SealVersionForGroup(root, gid, e.Lchown)
	}
	return s
}

// settleBundles runs after recoverInterrupted on every changing run: a
// bundle a previous run received but did not apply ends as
// failed(interrupted) and its staging copy goes; the last good bundle keeps
// enforcing. An applied bundle that was not confirmed is confirmed or failed
// against the deployment and the gateway (settleUnconfirmedBundle).
func (l *lifecycle) settleBundles(ctx context.Context, record *Deployment) (pending bool) {
	store := l.env.bundleStore()
	report, err := store.Settle(l.env.installedBundleDirs()...)
	if err != nil {
		l.result.AddWarning(codeBundleStateUnreadable, "could not settle the policy bundle store: "+err.Error())
		return true
	}
	if n := len(report.Interrupted); n > 0 {
		l.result.AddWarning(codeBundleInterrupted, fmt.Sprintf(
			"%d policy bundle(s) a previous run received were not applied (failed: interrupted); the last good bundle keeps enforcing", n))
	}
	if len(report.Pending) > 0 {
		pending = true
		l.result.AddWarning(enterprisebundle.WarnBundlePending, "an applied policy bundle remains pending because its confirmation prerequisite is unavailable")
	}
	for _, rc := range report.Unconfirmed {
		if l.settleUnconfirmedBundle(ctx, store, record, rc) {
			pending = true
		}
	}
	return pending
}

// describeBundle fills Result.Bundle from the store; nil when this device
// never received a bundle or the store cannot be read (status as a
// standard user).
func (l *lifecycle) describeBundle() { l.describeBundleBlock((*enterprisebundle.Store).Summary) }

// describeCurrentBundle is describeBundle for a repeated delivery of the
// current bundle. It wrote no receipt, so the block is the confirmed current
// bundle and its receipt, not a newer delivery that failed after staging.
func (l *lifecycle) describeCurrentBundle() {
	l.describeBundleBlock((*enterprisebundle.Store).CurrentSummary)
}

func (l *lifecycle) describeBundleBlock(block func(*enterprisebundle.Store) (*enterprisestatus.BundleState, error)) {
	store := l.env.bundleStore()
	summary, err := block(store)
	if err == nil {
		l.result.Bundle = summary
		if summary != nil {
			l.result.SetBundleSessions(l.env.UnprotectedSessions(context.Background()))
			l.result.SetBundleReceiptWarnings()
		}
	}
	_, l.result.LastRefusal, _ = store.Latest()
}

// withBundleFields adds the bundle the lifecycle installed in the recorded
// config generation to a policy-state record.
func (e *Env) withBundleFields(record enterprisestatus.PolicyStateRecord) enterprisestatus.PolicyStateRecord {
	state, err := configwrite.ReadGenerationState(e.P(e.Layout.ConfigPath))
	if err == nil && state.Generation == record.ConfigGeneration && state.BundleID != "" {
		record.BundleID, record.BundleVersion = state.BundleID, state.BundleVersion
	}
	return record
}

// installedBundleDirs are the version directories that the installed
// config.yaml and the committed config name. The store keeps them even when
// no bundle state or open receipt does: after a failed confirm with no last
// good bundle, or a return to the last good bundle that rolled back, the
// config the gateway loads still names that directory.
func (e *Env) installedBundleDirs() []string {
	bundlesDir := filepath.Join(e.Layout.ConfigDir, enterprisebundle.BundlesDirName)
	var names []string
	for _, path := range []string{e.P(e.Layout.ConfigPath), e.committedConfigPath()} {
		raw, err := readBounded(path, maxInputBytes)
		if err != nil {
			continue
		}
		names = append(names, enterprisebundle.VersionDirsNamed(raw, bundlesDir)...)
	}
	return names
}

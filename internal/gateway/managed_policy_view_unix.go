//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/subtle"
	"maps"
	"slices"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Test seams.
var (
	managedPolicyViewOptions = func(goos string) (enterprisepolicy.Options, string, bool) {
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil {
			return enterprisepolicy.Options{}, "", false
		}
		return enterprisepolicy.LayoutOptions(layout, "", ""), layout.DescriptorPath, true
	}
	computeManagedPolicyViewFor = computeManagedPolicyView
	// managedPolicyViewPollInterval paces the change check: a stamp of the
	// sources' metadata (enterprisepolicy.PolicyViewStamp), which reads no
	// policy bytes. The digests are recomputed only when it moves.
	managedPolicyViewPollInterval = 2 * time.Second
)

// computeManagedPolicyView proves each machine-policy connector's view
// against the trusted descriptor's pins: the shared sources as the vendor
// reads them (enterprisepolicy.PolicyViewDigest, which leaves out the
// drop-ins a vendor ignores) and, on macOS, each account's own managed
// preference. It runs with the gateway's permissions: a source it can not
// read is unproven, never proven.
func computeManagedPolicyView(opts enterprisepolicy.Options, descriptor *managed.RuntimeDescriptor) *managedPolicyView {
	if descriptor == nil || len(descriptor.MachinePolicyConnectors) == 0 {
		return nil
	}
	view := &managedPolicyView{connectors: make(map[string]managedPolicyViewConnector, len(descriptor.MachinePolicyConnectors))}
	for _, name := range descriptor.MachinePolicyConnectors {
		pin := descriptor.PolicyViewDigests[name]
		observed, err := enterprisepolicy.PolicyViewDigest(opts, name)
		state := managedPolicyViewConnector{
			shared: pin == "" || err != nil || subtle.ConstantTimeCompare([]byte(observed), []byte(pin)) != 1,
		}
		accounts, err := enterprisepolicy.PolicyViewAccountsUnproven(opts, name, descriptor.PolicyViewUserSources[name])
		state.allAccounts = err != nil
		state.accounts = accounts
		view.connectors[name] = state
	}
	return view
}

func (s managedPolicyViewConnector) anyUnproven() bool {
	return s.shared || s.allAccounts || len(s.accounts) > 0
}

// managedPolicyViewWatch keeps APIServer.managedPolicyView current, off the
// path of every call.
type managedPolicyViewWatch struct {
	api            *APIServer
	goos           string
	opts           enterprisepolicy.Options
	descriptorPath string
	connectors     []string
	stamp          string
	computed       bool
}

// startManagedPolicyView publishes the view once before the hook socket
// serves its first call, then checks for changes until ctx ends.
func (a *APIServer) startManagedPolicyView(ctx context.Context, goos string) {
	opts, descriptorPath, ok := managedPolicyViewOptions(goos)
	if !ok {
		return
	}
	watch := &managedPolicyViewWatch{api: a, goos: goos, opts: opts, descriptorPath: descriptorPath}
	watch.refresh()
	go watch.run(ctx)
}

func (w *managedPolicyViewWatch) run(ctx context.Context) {
	ticker := time.NewTicker(managedPolicyViewPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.refresh()
		}
	}
}

// refresh recomputes and publishes the view when the stamp of its sources
// and of the descriptor moved. The stamp is taken before the sources are
// read, so a change made while they are read moves the next stamp too.
func (w *managedPolicyViewWatch) refresh() {
	stamp := enterprisepolicy.PolicyViewStamp(w.opts, w.connectors, w.descriptorPath)
	if w.computed && stamp == w.stamp {
		return
	}
	descriptor, err := loadStandaloneRuntimeDescriptor(w.goos)
	if err != nil {
		descriptor = nil
	}
	var connectors []string
	if descriptor != nil {
		connectors = append(connectors, descriptor.MachinePolicyConnectors...)
	}
	if !slices.Equal(connectors, w.connectors) {
		// Another connector set: stamp its sources before they are read.
		w.connectors = connectors
		stamp = enterprisepolicy.PolicyViewStamp(w.opts, w.connectors, w.descriptorPath)
	}
	w.stamp, w.computed = stamp, true
	w.api.publishManagedPolicyView(computeManagedPolicyViewFor(w.opts, descriptor))
}

// publishManagedPolicyView stores view for the hook calls and queues one
// host alert for each connector whose view became unproven (or whose
// unproven accounts changed). An administrator then learns of a vendor
// policy change that dropped a managed hook even when no hook call follows
// it (GAP-1061).
func (a *APIServer) publishManagedPolicyView(view *managedPolicyView) {
	previous := a.managedPolicyView.Swap(view)
	if view == nil {
		return
	}
	for name, state := range view.connectors {
		if !state.anyUnproven() {
			continue
		}
		if previous != nil {
			if old, ok := previous.connectors[name]; ok && old.shared == state.shared &&
				old.allAccounts == state.allAccounts && maps.Equal(old.accounts, state.accounts) {
				continue
			}
		}
		a.managedAlerts.enqueue(a, managedPolicyViewAlert{uid: managedPolicyViewHostAlert, connector: name, route: "policy-view"})
	}
}

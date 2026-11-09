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

	"github.com/defenseclaw/defenseclaw/internal/config"
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
	authorizer     *managedHookAuthorizer
	goos           string
	opts           enterprisepolicy.Options
	descriptorPath string
	connectors     []string
	authorized     []string
	stamp          string
	generation     *Generation
	computed       bool
}

// startManagedPolicyView publishes the view once before the hook socket
// serves its first call, then checks for changes until ctx ends.
func (a *APIServer) startManagedPolicyView(ctx context.Context, goos string, authorizer *managedHookAuthorizer) {
	opts, descriptorPath, ok := managedPolicyViewOptions(goos)
	if !ok {
		return
	}
	watch := &managedPolicyViewWatch{api: a, authorizer: authorizer, goos: goos, opts: opts, descriptorPath: descriptorPath}
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
	generation := w.api.generation()
	stamp := enterprisepolicy.PolicyViewStamp(w.opts, w.connectors, w.descriptorPath)
	if w.computed && stamp == w.stamp && generation == w.generation {
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
	if w.authorizer != nil {
		// A changed descriptor can add authorization only when its connector
		// belongs to the recorded config and its published policy is proved.
		w.authorized = admittedMachinePolicyConnectors(w.goos, w.opts, generation, w.authorized, descriptor, !w.computed)
		w.authorizer.setMachinePolicy(w.authorized)
	}
	if !slices.Equal(connectors, w.connectors) {
		// Another connector set: stamp its sources before they are read.
		w.connectors = connectors
		stamp = enterprisepolicy.PolicyViewStamp(w.opts, w.connectors, w.descriptorPath)
	}
	w.stamp, w.generation, w.computed = stamp, generation, true
	view := computeManagedPolicyViewFor(w.opts, descriptor)
	if view != nil && w.authorizer != nil {
		view.admitted = make(map[string]bool, len(w.authorized))
		for _, connector := range w.authorized {
			view.admitted[connector] = true
		}
	}
	w.api.publishManagedPolicyView(view)
}

// machinePolicyPresenceOptions are the options that read the vendor machine
// policy files of the recorded standalone config: the admission of a changed
// descriptor and the own status of an excluded account both ask them whether a
// machine-policy hook is installed.
func machinePolicyPresenceOptions(goos string, viewOpts enterprisepolicy.Options, cfg *config.Config) (enterprisepolicy.Options, error) {
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		return enterprisepolicy.Options{}, err
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, "", "", cfg)
	if err != nil {
		return enterprisepolicy.Options{}, err
	}
	opts.OpenCodePluginPlanned = true
	opts.Root = viewOpts.Root
	opts.SkipTrustChecks = viewOpts.SkipTrustChecks
	return opts, nil
}

// machineHookAbsent proves that no machine-policy hook of connector is
// installed in the vendor files: they were read and name none, neither an exact
// registration nor a drifted one (timeout, arguments). A source that
// cannot be read, parsed or trusted proves nothing. The runtime descriptor and
// the admitted set are not this proof: either can be gone while the vendor
// hook stays, and the hook then refuses its calls.
var machineHookAbsent = func(goos string, cfg *config.Config, connector string) bool {
	viewOpts, _, ok := managedPolicyViewOptions(goos)
	if !ok {
		return false
	}
	opts, err := machinePolicyPresenceOptions(goos, viewOpts, cfg)
	if err != nil {
		return false
	}
	absent, err := enterprisepolicy.MachinePolicyAbsent(opts, connector)
	return err == nil && absent
}

func admittedMachinePolicyConnectors(goos string, viewOpts enterprisepolicy.Options, generation *Generation, previous []string, descriptor *managed.RuntimeDescriptor, initial bool) []string {
	if generation == nil || generation.Config == nil || !generation.Config.StandaloneEnterprise() || !generation.ConfigGenRecorded {
		return nil
	}
	opts, err := machinePolicyPresenceOptions(goos, viewOpts, generation.Config)
	if err != nil {
		return nil
	}
	intended := enterprisepolicy.MachinePolicyConnectors(opts, enterprisepolicy.StandaloneConnectors(generation.Config))
	var admitted []string
	// A descriptor written ahead of the gateway's config reload cannot
	// remove authorization that the still-live generation already admitted.
	// Once that generation changes, its intended set removes retired names.
	for _, name := range previous {
		if slices.Contains(intended, name) && !slices.Contains(admitted, name) {
			admitted = append(admitted, name)
		}
	}
	if descriptor == nil {
		return admitted
	}
	for _, name := range descriptor.MachinePolicyConnectors {
		if !slices.Contains(intended, name) || slices.Contains(admitted, name) {
			continue
		}
		if initial {
			// A gateway starting on an existing deployment keeps the previous
			// descriptor admission behavior. Hot additions require proof.
			admitted = append(admitted, name)
			continue
		}
		pin := descriptor.PolicyViewDigests[name]
		observed, err := enterprisepolicy.PolicyViewDigest(viewOpts, name)
		if pin == "" || err != nil || observed != pin {
			continue
		}
		present, err := enterprisepolicy.MachinePolicyPresent(opts, name)
		if err == nil && present {
			admitted = append(admitted, name)
		}
	}
	return admitted
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

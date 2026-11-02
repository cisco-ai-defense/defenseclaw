//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

// HostCheckOptions configures the per-tick host checks.
type HostCheckOptions struct {
	InstallRoot string
	Ports       []int
	// ExecProbe runs the gateway with --version (installer, before bootstrap).
	ExecProbe bool
}

// HostChecks runs the host prerequisite checks and the advisory code
// integrity comparison. The guardian keeps one for its lifetime and runs it
// every tick, so each finding is logged once per streak; the installer runs a
// fresh one. Nothing here can fail or stop the caller.
type HostChecks struct {
	opts      HostCheckOptions
	probes    HostPrereqProbes
	prereqs   PrereqReporter
	integrity *IntegrityChecker
}

// NewHostChecks returns host checks that act on the real host.
func NewHostChecks(opts HostCheckOptions) *HostChecks {
	return &HostChecks{
		opts:      opts,
		probes:    DefaultHostPrereqProbes(),
		integrity: NewIntegrityChecker(opts.InstallRoot),
	}
}

// Run performs one pass and returns the missing prerequisites and the code
// integrity findings it found (logged or already logged in this streak).
func (h *HostChecks) Run() ([]PrereqFinding, []IntegrityFinding) {
	if h == nil {
		return nil, nil
	}
	prereqs := CheckHostPrerequisites(HostPrereqInput{
		InstallRoot: h.opts.InstallRoot,
		Ports:       h.opts.Ports,
		ExecProbe:   h.opts.ExecProbe,
	}, h.probes)
	h.prereqs.Report(prereqs)
	return prereqs, h.integrity.Check()
}

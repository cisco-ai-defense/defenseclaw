//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import "time"

// hostPrereqInterval bounds how often the guardian's ticks re-run the
// prerequisite probes, which start processes (curl, lsof, xcode-select) that
// an endpoint agent can stall. Findings are advisory, so a few minutes of
// latency is harmless; the first pass always runs.
const hostPrereqInterval = 5 * time.Minute

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

	now         func() time.Time
	lastPrereq  time.Time
	lastFinding []PrereqFinding
}

// NewHostChecks returns host checks that act on the real host.
func NewHostChecks(opts HostCheckOptions) *HostChecks {
	return &HostChecks{
		opts:      opts,
		probes:    DefaultHostPrereqProbes(),
		integrity: NewIntegrityChecker(opts.InstallRoot),
		now:       time.Now,
	}
}

// Run performs one pass and returns the missing prerequisites and the code
// integrity findings it found (logged or already logged in this streak). The
// prerequisite probes re-run at most every hostPrereqInterval; in between the
// last findings are returned.
func (h *HostChecks) Run() ([]PrereqFinding, []IntegrityFinding) {
	if h == nil {
		return nil, nil
	}
	now := time.Now()
	if h.now != nil {
		now = h.now()
	}
	if h.lastPrereq.IsZero() || now.Sub(h.lastPrereq) >= hostPrereqInterval {
		h.lastFinding = CheckHostPrerequisites(HostPrereqInput{
			InstallRoot: h.opts.InstallRoot,
			Ports:       h.opts.Ports,
			ExecProbe:   h.opts.ExecProbe,
		}, h.probes)
		h.lastPrereq = now
		h.prereqs.Report(h.lastFinding)
	}
	return h.lastFinding, h.integrity.Check()
}

//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

// HostCheckOptions configures the per-tick host checks.
type HostCheckOptions struct {
	InstallRoot string
	Ports       []int
	ExecProbe   bool
}

// IntegrityFinding is one code integrity finding.
type IntegrityFinding struct {
	Path     string
	Reason   string
	Expected string
	Actual   string
	Detail   string
}

// HostChecks is a no-op off macOS: the managed macOS prerequisites and the
// install tree manifest do not apply to other hosts.
type HostChecks struct{}

// NewHostChecks returns host checks that do nothing on this host.
func NewHostChecks(HostCheckOptions) *HostChecks { return &HostChecks{} }

// Run does nothing on this host.
func (*HostChecks) Run() ([]PrereqFinding, []IntegrityFinding) { return nil, nil }

// ReportInventoryScanDenial reports nothing on this host: TCC is macOS only.
func ReportInventoryScanDenial(string, error) bool { return false }

// ReportPolicyDenial reports nothing on this host: only macOS overloads EPERM
// with Endpoint Security and TCC denials.
func ReportPolicyDenial(string, string, error) bool { return false }

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

// StandaloneContentDriftError is the refusal of a drifted standalone policy
// or data file (StandaloneRefusesContentDrift). It wraps the strict verdict,
// so errors.As still finds the UntrustedPrincipalError that names the path
// and the account, and adds what to do: DefenseClaw does not repair the file
// in place, because an account that could write it may have changed it and
// may still hold a handle to it (GAP-0561). For config.yaml and the guardian
// manifest, Setup writes a fresh file from the administrator's source and
// replaces the old one; for a file Setup has no administrator source for,
// the administrator removes the entry and checks the file (GAP-0590).
type StandaloneContentDriftError struct {
	Err error
}

// Recovery texts of a StandaloneContentDriftError, by file. Setup is not
// installed on a managed computer, so each names the commands through the
// renderer and says where Setup comes from (cowork-1-0-8 GAP-0095).
func standaloneConfigDriftRecovery() string {
	return "from an elevated PowerShell prompt run `" + WindowsSetupCommand("/ensure", "CONFIG=<the approved administrator-only config>") +
		"` so Setup writes a new config.yaml from it, then `" + WindowsAdminCommand("enterprise", "windows", "verify", "--profile", "standalone") +
		"`. " + WindowsSetupSource
}

func standaloneManifestDriftRecovery() string {
	return "from an elevated PowerShell prompt run `" + WindowsSetupCommand("/ensure", "CONFIG=<the approved config>") +
		"` so Setup writes a new targets.yaml enumerated from it (in manifest enrollment mode add MANIFEST=<the approved targets.yaml>), then `" +
		WindowsAdminCommand("enterprise", "windows", "verify", "--profile", "standalone") + "`. " + WindowsSetupSource
}

func standaloneRecordDriftRecovery() string {
	return "Setup does not write this file from an administrator source and refuses it too, before it stops anything: remove that " +
		"entry, or give the file back to Administrators, and check the file, then from an elevated PowerShell prompt run `" + WindowsSetupCommand("/ensure") + "` and `" +
		WindowsAdminCommand("enterprise", "windows", "verify", "--profile", "standalone") + "`. " + WindowsSetupSource
}

func (e *StandaloneContentDriftError) Error() string {
	return e.Err.Error() + "; a standalone install does not repair this file in place, because an account that could " +
		"write it may have changed it: " + standaloneContentDriftRecovery(e.Err)
}

func (e *StandaloneContentDriftError) Unwrap() error { return e.Err }

// RefuseStandaloneContentDrift returns err as a StandaloneContentDriftError,
// or nil for nil.
func RefuseStandaloneContentDrift(err error) error {
	if err == nil {
		return nil
	}
	return &StandaloneContentDriftError{Err: err}
}

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
	// Recovery replaces the recovery chosen from the refused path when set.
	Recovery string
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

// standaloneMachinePolicyDriftRecovery is the way out of a drifted Claude
// Code, Codex or Cursor machine policy folder or DefenseClaw file in it,
// which the hook guardian does not re-stamp (GAP-0633). A file is deleted,
// not fixed with icacls: an identical rewrite keeps the old object, and a
// handle the account opened while it could write the file keeps working on
// it (g582 review 3 S2).
func standaloneMachinePolicyDriftRecovery() string {
	return "the hook guardian leaves it as it is and every DefenseClaw reader keeps refusing it: " +
		"from an elevated PowerShell prompt delete the file (for the ownership record .defenseclaw-managed-hooks.state delete the " +
		"DefenseClaw policy file beside it too, 90-defenseclaw.json or requirements.toml; for Cursor delete the record, " +
		".defenseclaw-managed-hooks.receipt and defenseclaw-hook.ps1 together), then run `" + WindowsSetupCommand("/ensure") +
		"`, which writes them new from Setup's own state, and `" + WindowsAdminCommand("enterprise", "windows", "verify", "--profile", "standalone") +
		"`; for a folder remove that entry (icacls \"<path>\" /remove:g *<SID>), or give it back to Administrators " +
		"(icacls \"<path>\" /setowner *S-1-5-32-544). " + WindowsSetupSource
}

func (e *StandaloneContentDriftError) Error() string {
	return e.Err.Error() + "; a standalone install does not repair this file in place, because an account that could " +
		"write it may have changed it: " + e.recovery()
}

func (e *StandaloneContentDriftError) recovery() string {
	if e.Recovery != "" {
		return e.Recovery
	}
	return standaloneContentDriftRecovery(e.Err)
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

// RefuseStandaloneMachinePolicyDrift is RefuseStandaloneContentDrift for a
// vendor machine policy folder or a DefenseClaw file in it, which the hook
// guardian refuses to re-stamp on standalone (GAP-0633).
func RefuseStandaloneMachinePolicyDrift(err error) error {
	if err == nil {
		return nil
	}
	return &StandaloneContentDriftError{Err: err, Recovery: standaloneMachinePolicyDriftRecovery()}
}

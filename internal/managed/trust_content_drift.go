// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

// StandaloneContentDriftError is the refusal of a drifted standalone policy
// or data file (StandaloneRefusesContentDrift). It wraps the strict verdict,
// so errors.As still finds the UntrustedPrincipalError that names the path
// and the account, and adds what to do: DefenseClaw does not repair the file
// in place, because an account that could write it may have changed it and
// may still hold a handle to it. Setup writes a fresh file from the
// administrator's source and replaces the old one (GAP-0561).
type StandaloneContentDriftError struct {
	Err error
}

func (e *StandaloneContentDriftError) Error() string {
	return e.Err.Error() + "; a standalone install does not repair this file in place, because an account that could " +
		"write it may have changed it: from an elevated prompt run Setup /ensure with the approved CONFIG= and " +
		"MANIFEST= sources so Setup writes fresh files, then Setup /verify"
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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// ManagedHermesSessionHomeCoverageLimit returns the coverage limit that a
// standalone managed Hermes deployment reports, or "" when none applies.
// Setup proves that it hooked the account's persistent home, and the
// persistent-home check refuses a home it finds set elsewhere. A shell can
// still export HERMES_HOME later without changing its initial process
// environment, so neither the guardian nor Verify can prove that a later
// Hermes launch reads the hooked home.
//
// The limit is a coverage verdict, not a verification failure: ensure,
// status and verify keep coverage and security incomplete and name it, while
// a verified hook stays verified, so an install, upgrade or ensure is never
// refused or rolled back for it. It is a string so that no verifier can
// return it as an error.
func ManagedHermesSessionHomeCoverageLimit(goos, connector string, managed, secureClient bool) string {
	if (goos == "windows" || goos == "linux" || goos == "darwin") && connector == "hermes" && managed && !secureClient {
		return "session-only HERMES_HOME cannot be observed by the managed service: Hermes may use an unhooked home that no installed hook or persistent setting records; managed Hermes coverage cannot be certified"
	}
	return ""
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "errors"

// ManagedHermesSessionHomeAttestation is an attestation limit, not an
// installation check. Setup can prove that it wrote hooks to a persistent
// home, but a shell can export HERMES_HOME later without changing its initial
// process environment. Neither the guardian nor Verify can prove that a
// subsequent Hermes launch will read the hooked home.
func ManagedHermesSessionHomeAttestation(goos, connector string, managed, secureClient bool) error {
	if (goos == "windows" || goos == "linux" || goos == "darwin") && connector == "hermes" && managed && !secureClient {
		return errors.New("session-only HERMES_HOME cannot be observed by the managed service: Hermes may use an unhooked home that no installed hook or persistent setting records; managed Hermes coverage cannot be certified")
	}
	return nil
}

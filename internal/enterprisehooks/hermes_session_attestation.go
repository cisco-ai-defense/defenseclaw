// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "errors"

// managedHermesSessionHomeAttestation is an attestation limit, not an
// installation check. Setup can prove that it wrote hooks to the persistent
// home; Verify must also account for a Windows shell's unobservable
// session-only HERMES_HOME before it claims the agent is guarded.
func managedHermesSessionHomeAttestation(goos, connector string, managed, secureClient bool) error {
	if goos == "windows" && connector == "hermes" && managed && !secureClient {
		return errors.New("session-only HERMES_HOME cannot be observed by the managed service: Hermes may use an unhooked home that no installed hook or persistent setting records; this Windows Hermes registration cannot be certified")
	}
	return nil
}

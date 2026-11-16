// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

// DenialClass is what ClassifyDenial concluded about a failed file operation.
type DenialClass string

const (
	// DenialNone: there was no error.
	DenialNone DenialClass = ""
	// DenialAccess: mode or ACL denial (EACCES). Permission drift a re-stamp
	// fixes.
	DenialAccess DenialClass = "access"
	// DenialFlags: a write-blocking flag (uchg, uappnd, schg, sappnd) on the
	// object or its folder. Cleared by EnsureCanonical while kern.securelevel
	// allows it.
	DenialFlags DenialClass = "flags"
	// DenialSystemIntegrity: the object is protected by System Integrity
	// Protection. Never repaired; reported.
	DenialSystemIntegrity DenialClass = "system_integrity"
	// DenialPolicy: an Endpoint Security client, TCC or another policy
	// denied the operation. Never repaired; reported as a prerequisite.
	DenialPolicy DenialClass = "policy"
	// DenialOther: any other error.
	DenialOther DenialClass = "other"
)

// Drift reports whether a re-stamp of the object can clear the denial.
func (c DenialClass) Drift() bool {
	return c == DenialAccess || c == DenialFlags
}

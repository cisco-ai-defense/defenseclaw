// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

// TamperedDropIns lists the machine-policy drop-ins DefenseClaw owns whole
// and published (an ownership record names them) whose bytes are no longer
// the ones it wrote, or that are gone: the Claude Code managed-settings
// drop-in. The standalone Unix hook guardian checks them between lifecycle
// runs, because an edited or deleted drop-in left the hooks off for every
// user until an administrator ran repair (GAP-1178). Shared vendor files,
// which administrators edit too, are left to verify.
func TamperedDropIns(opts Options) []string {
	expected, err := claudeDropInPath(opts)
	if err != nil {
		return nil
	}
	record, err := loadRecord(opts, claudeConnector)
	if err != nil || record == nil || record.Path != expected || record.PostimageSHA256 == "" {
		return nil
	}
	current, exists, err := readPolicyFile(opts, record.Path)
	if err != nil || !exists || sha256Hex(current) != record.PostimageSHA256 {
		return []string{record.Path}
	}
	return nil
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

// managedHostWindowsStandalone reports a standalone managed deployment. Two
// administrator-written signals count, and nothing a standard user can
// create does (%ProgramData% lets any user create folders, so a planted
// record would otherwise refuse every other user's per-user gateway):
//
//   - the HKLM marker the elevated standalone lifecycle publishes after a
//     successful install and removes after uninstall, honored only when its
//     key is owned by SYSTEM, Administrators or TrustedInstaller and no
//     other principal can write it (managedHostStandaloneMarker);
//   - the ProgramData deployment record, when no one but an administrator
//     could have written it (managedHostRecordTrusted) or the
//     administrator-registered standalone gateway service confirms it
//     (managedStandaloneRecordCounts). An uninstalled deployment (tombstone)
//     does not count.
//
// Secure Client hosts are unaffected: only the standalone profile writes the
// marker, and their record lives under the Secure Client roots, which this
// profile's inspection never reads.
// secureClientHost uses machine roots, a trusted installation, and its
// registered service. An ordinary user may be unable to read the protected
// deployment record; that does not demote an otherwise verified installation.
// A first install writes that record only when its lifecycle transaction
// commits; until then the transaction's own protected record
// (install\pending.json) stands in for it, so the target enumeration and the
// helpers the install runs apply the Secure Client rules, as they already do
// for Repair and Upgrade.

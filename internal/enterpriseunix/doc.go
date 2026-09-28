// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// Package enterpriseunix is the standalone managed-enterprise lifecycle for
// Linux (systemd) and macOS (launchd): install, upgrade, repair, ensure,
// reconcile, status, verify and uninstall of the administrator-owned
// DefenseClaw services.
//
// Every mutating action is one transaction. It takes the lifecycle lock
// under the protected lifecycle directory, records an intent, snapshots
// every file it will touch, stages replacements in the destination
// directory, stops the services, applies, reloads the service manager,
// activates the services in dependency order, verifies the result, and
// either commits the deployment record or restores the snapshot and the
// previously running services. An interrupted transaction is rolled back
// by the next invocation before anything else happens.
//
// The package never trusts the caller's environment for paths: every
// location comes from managed.StandaloneLayoutFor. Tests run the same code
// against a temporary root with fake service, account and command
// runners.
package enterpriseunix

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Package fleet builds the documents `defenseclaw substrate status --json`
// and `verify --json` print on the management contract
// (packaging/mdm/contract/substrate-status.schema.json and
// substrate-verify.schema.json), and the cluster checks `doctor` runs:
// issuer uniqueness (E13), snapshot bucket hygiene (E10), the OpenFGA grants
// (E2, E3), the callout registration (D10), the Substrate version range, the
// router clients (E2) and the actor listener's routes (E1, D15).
//
// The checks are pure functions over what the CLI observed (Observed), so
// they run the same in doctor, verify and the tests.
package fleet

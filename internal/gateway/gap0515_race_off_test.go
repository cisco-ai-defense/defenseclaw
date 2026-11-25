// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package gateway

// gap0515Scale divides the sizes of the GAP-0515 property tests under the
// race detector: there they check the memo's locking, and the plain run
// checks the answers at full size.
const gap0515Scale = 1

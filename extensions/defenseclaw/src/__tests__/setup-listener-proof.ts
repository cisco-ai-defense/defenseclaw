/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0
 */

// The suites run without a DefenseClaw gateway: the listener proof
// (GAP-0594) passes for loopback targets. listener-proof.test.ts restores
// the real proof against its own loopback listeners.
import { _setListenerProofForTest } from "../listener-proof.js";

_setListenerProofForTest(async () => {});

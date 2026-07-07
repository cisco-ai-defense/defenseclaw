// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package cloud sources cloud identity credentials for managed-mode
// defenseclaw from the Cisco Secure Client Cloud Management module.
//
// The Cisco module ships a dynamic library (libcmidapi.dylib on macOS,
// cmidapi.dll on Windows) that exposes an opaque CMID, a bound token,
// a business ID, and per-service URLs. Callers are expected to:
//
//   - load the library afresh before making API calls, and unload as soon
//     as required values have been retrieved (i.e. do not hold the library
//     open indefinitely);
//   - call cmid_refresh_token first during the caller's lifetime;
//   - implement wait-and-retry (Cisco suggests 10s, 20s, 30s incremental
//     back-off with up to three retries) around agent/cloud failures;
//   - allocate and free the buffers passed into the two-step size query
//     pattern; contents are opaque printable ASCII.
//
// This package encapsulates those rules behind a small Provider interface
// so the future defenseclaw cloud client can consume credentials without
// touching the dylib directly. The provider caches values in memory and
// re-fetches on demand (typically after a 401 from the cloud, via
// Invalidate).
package cloud

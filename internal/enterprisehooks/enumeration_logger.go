// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// EnumerationLogger receives one line per user profile the enumerator dropped
// or annotated, so an operator can debug WHY a specific user isn't getting
// hooked. Matches the macOS `_enumerate_users_warn` shape. Nil is safe (drops
// are silent).
//
// Kept in a cross-platform file so non-Windows stubs (e.g. the inventory-DACL
// pass) can reference the type without duplicating a build-tagged declaration.
type EnumerationLogger func(subject, reason string)

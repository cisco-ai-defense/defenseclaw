// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bounded

// This package's tests run with the misuse checks on, as every adopter's
// tests do (see PanicOnMisuse).
func init() { PanicOnMisuse(true) }

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package procimage owns the one macOS call that asks the kernel for the file
// a process runs (proc_info PROC_PIDPATHINFO). It is a leaf package because
// internal/enterpriseunix imports internal/openshell: both share the call
// from here instead of each making their own (GAP-0629, GAP-0687). Other
// platforms read /proc or have no such proof.
package procimage

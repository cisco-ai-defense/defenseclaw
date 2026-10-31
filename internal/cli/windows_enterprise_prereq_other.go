// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

// windowsEnterprisePrerequisiteChecker is the Windows enterprise lifecycle
// preflight. The lifecycle commands exist only on Windows, so elsewhere there
// is nothing to check.
var windowsEnterprisePrerequisiteChecker = func(windowsEnterprisePrereqInput) error { return nil }

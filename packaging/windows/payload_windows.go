// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package windowspayload

import _ "embed"

//go:embed install-enterprise.ps1
var installer []byte

//go:embed DefenseClawEnterprise.psm1
var module []byte

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config_test

// The package tests check v8 documents, so the test program links the check
// as every config program does. An internal test file cannot import it (the
// check imports config); this external one shares the test program.
import _ "github.com/defenseclaw/defenseclaw/internal/config/fullconfig"

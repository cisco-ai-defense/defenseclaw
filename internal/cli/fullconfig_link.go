// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

// The CLI loads, checks and compiles v8 config documents (config validate,
// status, daemon start), so it links the full config (internal/config/fullconfig).
import _ "github.com/defenseclaw/defenseclaw/internal/config/fullconfig"

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

// The gateway compiles v8 config documents (config_manager.go, the
// observability bootstrap), so it links the full config (internal/config/fullconfig).
import _ "github.com/defenseclaw/defenseclaw/internal/config/fullconfig"

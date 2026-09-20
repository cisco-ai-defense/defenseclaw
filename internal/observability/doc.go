// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package observability owns the dependency-neutral semantic taxonomy used by
// the DefenseClaw observability pipeline. It intentionally does not import
// gateway, audit, telemetry, or configuration packages; those producers adapt
// their typed keys into this contract at their integration boundaries.
package observability

//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func copilotRefixOptions(t *testing.T) Options { return windowsTestOptions(t) }

// writeAdministratorPolicy writes a policy file the way an elevated
// administrator does under UAC: owned by Administrators. The policy file
// trust rule refuses one the built-in Administrator account (a GitHub
// runner) owns itself, and such a file is not administrator content.
func writeAdministratorPolicy(t *testing.T, path, content string) {
	t.Helper()
	testenv.AsAdministratorsOwner(t, func() { writeFile(t, path, content) })
}

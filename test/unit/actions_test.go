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

package unit

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestValidateAcceptsValid(t *testing.T) {
	actions := config.DefaultSkillActions()
	if err := actions.Validate(); err != nil {
		t.Fatalf("Validate: unexpected error: %v", err)
	}
}

func TestValidateRejectsInvalidRuntime(t *testing.T) {
	actions := config.DefaultSkillActions()
	actions.Medium.Runtime = "deny"
	if err := actions.Validate(); err == nil {
		t.Fatal("expected Validate to return error for invalid runtime")
	}
}

func TestValidateRejectsInvalidFile(t *testing.T) {
	actions := config.DefaultSkillActions()
	actions.High.File = "delete"
	if err := actions.Validate(); err == nil {
		t.Fatal("expected Validate to return error for invalid file action")
	}
}

func TestValidateRejectsInvalidInstall(t *testing.T) {
	actions := config.DefaultSkillActions()
	actions.Critical.Install = "yeet"
	if err := actions.Validate(); err == nil {
		t.Fatal("expected Validate to return error for invalid install action")
	}
}

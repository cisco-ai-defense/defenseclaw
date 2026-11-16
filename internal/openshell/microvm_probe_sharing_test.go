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

package openshell_test

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestR108OSMINMicroVMDoesNotRequireDockerFileSharing keeps the vm driver
// independent of the container engine's project-folder sharing setting.
func TestR108OSMINMicroVMDoesNotRequireDockerFileSharing(t *testing.T) {
	f := newDoctorFixture(t)
	f.onMicroVMs()
	c := expectCheck(t, f.run(), openshell.CheckIDDockerFileSharing, openshell.StatusSkip, "the MicroVM driver does not mount project folders")
	if c.Fix != nil {
		t.Fatalf("unexpected file-sharing fix: %+v", c.Fix)
	}
}

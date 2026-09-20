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

package connector

import "context"

// Setup authenticates the Windows Amp executable evidence before the managed
// policy plugin is created or repaired. Other platforms retain the established
// plugin setup contract through the platform no-op admission implementation.
func (c *AMPConnector) Setup(ctx context.Context, opts SetupOpts) error {
	if err := validateAmpWindowsSetupAdmission(opts); err != nil {
		return err
	}
	return c.hookOnlyConnector.Setup(ctx, opts)
}

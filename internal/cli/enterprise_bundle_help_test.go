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

package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// The bundle limits are documented in the command help, not on the public
// site, so each verb must name the codes an operator will see.
func TestEnterpriseBundleHelpNamesTheLimits(t *testing.T) {
	cases := []struct {
		verb string
		cmd  *cobra.Command
		want []string
	}{
		{"verify", newEnterpriseBundleVerifyCommand(), []string{
			"floor_unchecked", "already_applied", "On Windows the installed anchors", "not_admin",
			"revoked key is refused (key_revoked)", "retired key verifies only the confirmed bundle", "(key_expired)",
		}},
		{"status", newEnterpriseBundleStatusCommand(), []string{
			"gateway_unchecked", fmt.Sprintf("last %d receipts", enterprisebundle.MaxReceipts),
		}},
		{"apply", newEnterpriseBundleApplyCommand(), []string{
			"superseded", "bundle_state_unreadable", "On Linux and macOS, --inbox", "Windows has no inbox",
			"ensure and repair on Linux and macOS keep the installed config", "On Windows they stop with bundle_restore_failed and repair nothing",
		}},
	}
	for _, c := range cases {
		long := strings.Join(strings.Fields(c.cmd.Long), " ")
		for _, w := range c.want {
			if !strings.Contains(long, w) {
				t.Errorf("bundle %s help does not mention %q", c.verb, w)
			}
		}
	}
}

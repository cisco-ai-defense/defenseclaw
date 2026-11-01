// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"io"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
)

var enterpriseAccountKeysCmd = &cobra.Command{
	Use:   "account-keys",
	Short: "Print the account join keys of this device (root or administrators only)",
	Long: `Print, as JSON on standard output, the account join key of each enrolled
account the hook guardian saw in the last 30 days, for the management agent
that sends them to the fleet service. Requires enterprise.account_join on,
the protected credential account-join-key and root (Linux, macOS) or an
elevated administrator (Windows). The keys are computed now and stored
nowhere; status and verify report only their counts.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error { return runEnterpriseAccountKeys(cmd) },
}

func init() {
	enterpriseCmd.AddCommand(enterpriseAccountKeysCmd)
}

// enterpriseAccountKeysDocument is what `enterprise account-keys` prints.
type enterpriseAccountKeysDocument struct {
	SchemaVersion int                 `json:"schema_version"`
	AccountJoin   *accountjoin.Report `json:"account_join"`
}

// printEnterpriseAccountKeys prints report; nil is the feature off.
func printEnterpriseAccountKeys(w io.Writer, report *accountjoin.Report) error {
	if report == nil {
		report = &accountjoin.Report{State: "off", ReasonCodes: []string{accountjoin.ReasonFeatureOff}}
	}
	return json.NewEncoder(w).Encode(enterpriseAccountKeysDocument{SchemaVersion: 1, AccountJoin: report})
}

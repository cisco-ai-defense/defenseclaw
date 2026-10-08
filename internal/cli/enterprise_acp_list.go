// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/spf13/cobra"
)

var enterpriseACPListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the managed ACP enrollments: user, editor, agent, profile and setup state",
	Long: `List every managed ACP enrollment in the protected machine state: the account
it was issued to, the editor and agent, the profile, when it was enrolled,
whether the user's private copy of the credential is present and whether the
user has run setup: "done" when the editor entry's contract lock exists for
the enrolled profile and its mode and the entry points at this home, "stale"
when it does not (the enrollment was replaced, the profile changed mode, or
an account rename moved the home; the user runs the setup command again). The user's files are read
as that user, in the enrolled data directory (or <home>/.defenseclaw for
older enrollments).`,
	Args: cobra.NoArgs,
	// Secure Client keeps the command tree of main (issue #1092).
	Annotations: map[string]string{secureClientAbsentAnnotation: "true"},
	RunE:        runEnterpriseACPList,
}

func init() {
	enterpriseACPListCmd.Flags().BoolVar(&enterpriseACPJSON, "json", false, "Emit machine-readable JSON")
	enterpriseACPCmd.AddCommand(enterpriseACPListCmd)
}

// enterpriseACPListedEnrollment is one row of enterprise acp list.
type enterpriseACPListedEnrollment struct {
	acp.EnterpriseEnrollment
	User string `json:"user,omitempty"`
	// Account is "present", "deleted" (no account has the uid or SID) or
	// "unknown" (the lookup failed, or the principal names no account).
	Account string `json:"account"`
	// TokenCopy and Setup are "present"/"missing" and "done"/"not run", or
	// "unknown" when the user's files could not be read.
	TokenCopy string `json:"token_copy"`
	Setup     string `json:"setup"`
}

// runEnterpriseACPList answers who is enrolled: an administrator could see
// the enrollments only by reading the protected record directory, so
// orphans and users who never ran setup went unnoticed (GAP-0400).
func runEnterpriseACPList(cmd *cobra.Command, _ []string) error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return enterpriseACPResult(cmd, nil, errors.New("enterprise ACP enrollment requires deployment_mode: managed_enterprise"))
	}
	var enrollments []acp.EnterpriseEnrollment
	var invalid []string
	if err := withEnterpriseACPServiceOwner(cfg.DataDir, func() error {
		var listErr error
		enrollments, invalid, listErr = acp.ListEnterpriseEnrollments(cfg.DataDir)
		return listErr
	}); err != nil {
		return enterpriseACPResult(cmd, nil, fmt.Errorf("enterprise acp: read the managed ACP enrollments: %w", err))
	}
	rows := make([]enterpriseACPListedEnrollment, 0, len(enrollments))
	for _, enrollment := range enrollments {
		rows = append(rows, describeEnterpriseACPEnrollment(enrollment))
	}
	if enterpriseACPJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"ok": true, "enrollments": rows, "invalid": invalid})
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "  %d managed ACP enrollment(s)\n", len(rows))
	if len(rows) > 0 {
		table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "  USER\tCLIENT/AGENT\tPROFILE\tENROLLED\tTOKEN COPY\tSETUP")
		for _, row := range rows {
			user := row.Principal
			switch {
			case row.Account == "deleted":
				user += " (account deleted)"
			case row.User != "":
				user = row.User + " (" + row.Principal + ")"
			}
			fmt.Fprintf(table, "  %s\t%s/%s\t%s\t%s\t%s\t%s\n", user, row.ClientID, row.AgentID, row.Profile,
				row.Created.Format("2006-01-02 15:04Z"), row.TokenCopy, row.Setup)
		}
		_ = table.Flush()
	}
	if len(invalid) > 0 {
		fmt.Fprintf(out, "  %s %d record(s) in the enrollment directory could not be read: %s\n",
			Style("!", "fg=yellow", "bold"), len(invalid), strings.Join(invalid, ", "))
	}
	return nil
}

// describeEnterpriseACPEnrollment names the account of an enrollment and
// reads, as that account, whether its token copy and contract lock exist.
func describeEnterpriseACPEnrollment(enrollment acp.EnterpriseEnrollment) enterpriseACPListedEnrollment {
	row := enterpriseACPListedEnrollment{EnterpriseEnrollment: enrollment, Account: "unknown", TokenCopy: "unknown", Setup: "unknown"}
	row.Created = row.Created.Truncate(time.Second)
	account, err := enterpriseACPDescribePrincipal(enrollment.Principal)
	switch {
	case err != nil:
		return row
	case !account.exists:
		row.Account, row.TokenCopy, row.Setup = "deleted", "-", "-"
		return row
	}
	row.Account, row.User = "present", account.name
	if account.home == "" {
		return row
	}
	dataDir := enrollment.UserDataDir
	if dataDir == "" {
		dataDir = filepath.Join(account.home, ".defenseclaw")
	}
	home, err := filepath.Abs(account.home)
	if err != nil {
		return row
	}
	relative, err := filepath.Rel(home, dataDir)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return row
	}
	tokenPath, err := acp.EnterpriseUserTokenPath(dataDir, enrollment.ClientID, enrollment.AgentID)
	if err != nil {
		return row
	}
	_ = enterprisehooks.RunAsTarget(enterprisehooks.TargetCredentials{
		UserHome: account.home, UID: account.uid, GID: account.gid, SID: account.sid,
	}, func() error {
		row.TokenCopy, row.Setup = "missing", "not run"
		if info, statErr := os.Lstat(tokenPath); statErr == nil && info.Mode().IsRegular() {
			row.TokenCopy = "present"
		}
		if done, mismatch := enterpriseACPSetupState(dataDir, account.home, enrollment.ClientID, enrollment.AgentID,
			enrollment.Profile, enterpriseACPProfileMode(enrollment.Profile)); done {
			row.Setup = "done"
		} else if mismatch != "" {
			// A lock whose entry points elsewhere (an account rename moved
			// the home, GAP-0693) or that has another profile or mode
			// (GAP-0833) is not a done setup.
			row.Setup = "stale"
		}
		return nil
	})
	return row
}

// enterpriseACPAccount is the account an enrollment principal names.
type enterpriseACPAccount struct {
	exists          bool
	name, home, sid string
	uid, gid        int
}

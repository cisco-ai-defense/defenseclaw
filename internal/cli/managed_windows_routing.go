// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

// managedWindowsRoutingRead reads one own-routing path from the managed
// gateway (the own-status pipe on Windows); a seam for tests.
var managedWindowsRoutingRead = readOwnRouting

const managedWindowsRoutingReads = "`defenseclaw routing status`, `defenseclaw routing budgets list` and `defenseclaw routing explain <id>`"

// addManagedWindowsRoutingCommand serves `defenseclaw routing` on a managed
// Windows computer, which has no per-user (Python) CLI: a standard account
// reads its own routing (status, budgets list, explain <id>) from the managed
// gateway, which answers for the caller's own account only and refuses when
// routing.admin.visibility.users_see is none. Every other routing command
// changes the administrator's config and gets the managed answer (exit 3).
// Without it, routing got the generic "not available on this computer"
// answer of the per-user command table.
func addManagedWindowsRoutingCommand(root *cobra.Command, where string) {
	for _, command := range root.Commands() {
		if command.Name() == "routing" {
			return
		}
	}
	root.AddCommand(&cobra.Command{
		Use:                "routing",
		Short:              "Read your own model routing decisions and budgets",
		DisableFlagParsing: true,
		SilenceUsage:       true,
		Annotations:        map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, help := managedAnswerHelpArgs(args); help {
				cmd.Long = fmt.Sprintf("This computer's DefenseClaw is managed by your organization (%s). Read your own routing with %s; "+
					"the gateway shows only your own decisions and budgets.", where, managedWindowsRoutingReads)
				return cmd.Help()
			}
			path, ok := managedWindowsRoutingPath(args)
			if !ok {
				return withExitCode(managedDeviceAnswer(fmt.Sprintf("this computer's DefenseClaw is managed by your organization (%s): "+
					"model routing, its rules and budgets are set by your administrator. You can read your own routing with %s. "+
					"Nothing was changed.", where, managedWindowsRoutingReads)), 3)
			}
			status, body, err := managedWindowsRoutingRead(cmd.Context(), path)
			if err != nil {
				return fmt.Errorf("the managed gateway did not answer (%v); try again, and if it keeps failing contact your IT help desk", err)
			}
			var pretty bytes.Buffer
			if json.Indent(&pretty, bytes.TrimSpace(body), "", "  ") != nil {
				pretty.Reset()
				pretty.Write(bytes.TrimSpace(body))
			}
			if status != http.StatusOK {
				var e struct {
					Error string `json:"error"`
				}
				_ = json.Unmarshal(body, &e)
				return &routingReadError{status: status, message: e.Error}
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), pretty.String())
			return err
		},
	})
}

// managedWindowsRoutingPath maps the own reads to their gateway path. The
// output is JSON either way, so --json is accepted and changes nothing.
func managedWindowsRoutingPath(args []string) (string, bool) {
	words := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--json" {
			words = append(words, arg)
		}
	}
	var path string
	switch {
	case len(words) == 1 && words[0] == "status":
		path = "/api/v1/routing/effective?recent=5"
	case len(words) == 2 && words[0] == "budgets" && words[1] == "list":
		path = "/api/v1/routing/budgets"
	case len(words) == 2 && words[0] == "explain" && words[1] != "":
		path = "/api/v1/routing/explain/" + url.PathEscape(words[1])
	default:
		return "", false
	}
	return path, refusalpipe.ValidRoutingReadPath(path)
}

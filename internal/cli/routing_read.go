// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

// routingReadCmd is how `defenseclaw routing status | budgets list |
// explain` reaches the managed gateway for a standard account, which cannot
// read config.yaml or the API token: the hook socket on Linux and macOS, the
// own-status pipe on Windows. The gateway answers for the caller's own
// account only.
var routingReadCmd = &cobra.Command{
	Use:    "routing-read PATH",
	Short:  "Read your own routing decisions and budgets from the managed gateway",
	Hidden: true, // the Python CLI calls it; users run defenseclaw routing
	Args:   cobra.ExactArgs(1),
	// A standard account cannot read config.yaml: no daemon bootstrap.
	Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	RunE: func(cmd *cobra.Command, args []string) error {
		path := strings.TrimSpace(args[0])
		if !refusalpipe.ValidRoutingReadPath(path) {
			return errors.New("routing-read: PATH must be /api/v1/routing/effective[?recent=N], /api/v1/routing/budgets or /api/v1/routing/explain/<id>")
		}
		status, body, err := readOwnRouting(cmd.Context(), path)
		if err != nil {
			return fmt.Errorf("the managed gateway did not answer (%v); try again, and if it keeps failing contact your IT help desk", err)
		}
		if status != http.StatusOK {
			var e struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(body, &e)
			fmt.Fprintln(cmd.OutOrStdout(), string(body))
			return &routingReadError{status: status, message: e.Error}
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(body))
		return err
	},
}

// routingReadError is a refusal of the gateway; the JSON body is on stdout.
type routingReadError struct {
	status  int
	message string
}

func (e *routingReadError) Error() string {
	if e.message != "" {
		return fmt.Sprintf("the managed gateway refused the routing read (HTTP %d): %s", e.status, e.message)
	}
	return fmt.Sprintf("the managed gateway refused the routing read (HTTP %d)", e.status)
}

func init() {
	routingReadCmd.SilenceUsage = true
	rootCmd.AddCommand(routingReadCmd)
}

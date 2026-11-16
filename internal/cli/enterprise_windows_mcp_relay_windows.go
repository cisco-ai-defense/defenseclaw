// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
)

// enterpriseWindowsMCPRelayDialTimeout bounds the wait for the hook
// enumerator's pipe.
const enterpriseWindowsMCPRelayDialTimeout = 15 * time.Second

// newEnterpriseWindowsMCPRelayCommand is the stdio server the managed
// Windows scanner runtime starts in place of an enrolled user's local MCP
// server (#1164). It asks the hook enumerator to start that server as the
// user and relays its stdio; it never starts a command itself. Internal:
// only the gateway's scanner runtime runs it.
func newEnterpriseWindowsMCPRelayCommand() *cobra.Command {
	var request string
	cmd := &cobra.Command{
		Use:          "mcp-relay",
		Short:        "Relay an MCP admission scan to a server the hook enumerator starts as its user (internal)",
		Hidden:       true,
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			code := runEnterpriseWindowsMCPRelay(cmd.Context(), request, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
			if code != 0 {
				// The server's own exit code, for the scanner's message.
				return withExitCode(fmt.Errorf("MCP server exited with code %d", code), code)
			}
			return nil
		},
	}
	cmd.SilenceErrors = true
	cmd.Flags().StringVar(&request, "request", "", "the encoded server request the gateway wrote")
	return cmd
}

// Seams for tests.
var (
	enterpriseWindowsMCPRelayDial = mcpasuser.Dial
	enterpriseWindowsMCPRelayRun  = mcpasuser.RunRelay
)

func runEnterpriseWindowsMCPRelay(ctx context.Context, arg string, stdin io.Reader, stdout, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := mcpasuser.DecodeRequestArg(arg)
	if err != nil {
		fmt.Fprintf(stderr, "mcp as-user scan: %v\n", err)
		return 2
	}
	dialCtx, cancel := context.WithTimeout(ctx, enterpriseWindowsMCPRelayDialTimeout)
	conn, err := enterpriseWindowsMCPRelayDial(dialCtx, request.GatewayService)
	cancel()
	if err != nil {
		fmt.Fprintf(stderr, "mcp as-user scan: %v\n", err)
		return 3
	}
	defer conn.Close()
	code, err := enterpriseWindowsMCPRelayRun(conn, request, stdin, stdout, stderr)
	if err != nil {
		var refused *mcpasuser.RefusedError
		if errors.As(err, &refused) {
			fmt.Fprintf(stderr, "mcp as-user scan: the hook enumerator did not start the server: %s\n", refused.Reason)
		} else {
			fmt.Fprintf(stderr, "mcp as-user scan: %v\n", err)
		}
		if code == 0 {
			code = 3
		}
	}
	return code
}

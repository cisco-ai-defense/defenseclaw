// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/spf13/cobra"
)

func postPerUserPluginHook(ctx context.Context, apiAddr string, source io.Reader, output io.Writer, curlOutput bool) error {
	request, err := hookexec.ReadPerUserPluginRequest(source)
	if err != nil {
		return err
	}
	response, err := hookexec.PostPerUserHook(ctx, apiAddr, request.Path, request.Headers, []byte(request.Body))
	if err != nil {
		return err
	}
	return writePluginHookReply(output, response, curlOutput)
}

// postSecureClientPluginHook uses the protected gateway service identity,
// never the account-wide bearer, to decide whether it may send that bearer.
func postSecureClientPluginHook(ctx context.Context, apiAddr string, source io.Reader, output io.Writer) error {
	if !secureClientHost() {
		return fmt.Errorf("secure client gateway service peer cannot be verified on this host")
	}
	request, err := hookexec.ReadPerUserPluginRequest(source)
	if err != nil {
		return err
	}
	response, err := hookexec.PostManagedEnterprisePluginHook(ctx, apiAddr, managedServiceName(true),
		request.Path, request.Headers, []byte(request.Body))
	if err != nil {
		return err
	}
	return writePluginHookReply(output, response, false)
}

func writePluginHookReply(output io.Writer, response hookexec.PerUserHookReply, curlOutput bool) error {
	if curlOutput {
		_, err := fmt.Fprintf(output, "%s\n%d", response.Body, response.Status)
		return err
	}
	return json.NewEncoder(output).Encode(response)
}

func init() {
	var apiAddr string
	var maxTime int
	var curlOutput bool
	var secureClientService bool
	cmd := &cobra.Command{
		Use:         "hook-post",
		Hidden:      true,
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if maxTime < 1 || maxTime > 30 {
				return fmt.Errorf("per-user hook timeout must be 1 to 30 seconds")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(maxTime)*time.Second)
			if secureClientService {
				defer cancel()
				if curlOutput {
					return fmt.Errorf("secure client plugin post does not support curl output")
				}
				return postSecureClientPluginHook(ctx, apiAddr, os.Stdin, cmd.OutOrStdout())
			}
			err := postPerUserPluginHook(ctx, apiAddr, os.Stdin, cmd.OutOrStdout(), curlOutput)
			cancel()
			if hookexec.PerUserPostOutage(err) {
				// This account's gateway is not running: the status the shell
				// hooks and plugins read as an outage, not as a refusal.
				fmt.Fprintf(cmd.ErrOrStderr(), "defenseclaw-gateway hook-post: %v\n", err)
				hookProcessExit(hookexec.PerUserPostOutageExit)
			}
			if hookexec.PerUserPostPeerUnverified(err) {
				// Nothing of the call was sent: the one failure the plugins
				// may send again (GAP-2083).
				fmt.Fprintf(cmd.ErrOrStderr(), "defenseclaw-gateway hook-post: %v\n", err)
				hookProcessExit(hookexec.PerUserPostPeerUnverifiedExit)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&apiAddr, "api-addr", "", "gateway loopback host:port")
	cmd.Flags().IntVar(&maxTime, "max-time", 10, "maximum request time in seconds")
	cmd.Flags().BoolVar(&curlOutput, "curl-output", false, "print response body and trailing HTTP code")
	cmd.Flags().BoolVar(&secureClientService, "secure-client-service", false, "verify the Secure Client gateway service peer")
	_ = cmd.MarkFlagRequired("api-addr")
	rootCmd.AddCommand(cmd)

	var local, remote, managedService string
	verify := &cobra.Command{
		Use:         "hook-verify-connected",
		Hidden:      true,
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if managedService != "" {
				return hookexec.VerifyManagedConnectedTuple(local, remote, managedService)
			}
			return hookexec.VerifyPerUserConnectedTuple(local, remote)
		},
	}
	verify.Flags().StringVar(&local, "local", "", "connected client endpoint")
	verify.Flags().StringVar(&remote, "remote", "", "connected gateway endpoint")
	verify.Flags().StringVar(&managedService, "managed-service", "", "protected gateway service identity")
	_ = verify.MarkFlagRequired("local")
	_ = verify.MarkFlagRequired("remote")
	rootCmd.AddCommand(verify)
}

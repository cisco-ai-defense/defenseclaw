// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookcli

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

func PostPerUserPluginHook(ctx context.Context, apiAddr string, source io.Reader, output io.Writer, curlOutput bool) error {
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

// PostSecureClientPluginHook uses the protected gateway service identity,
// never the account-wide bearer, to decide whether it may send that bearer.
func PostSecureClientPluginHook(ctx context.Context, apiAddr string, source io.Reader, output io.Writer) error {
	if !SecureClientHost() {
		return fmt.Errorf("secure client gateway service peer cannot be verified on this host")
	}
	request, err := hookexec.ReadPerUserPluginRequest(source)
	if err != nil {
		return err
	}
	response, err := hookexec.PostManagedEnterprisePluginHook(ctx, apiAddr, ManagedServiceName(true),
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

// NewHookPostCmd builds the hidden hook-post command: the per-user shell hooks
// and plugins send one gateway request through it.
func NewHookPostCmd() *cobra.Command {
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
				return PostSecureClientPluginHook(ctx, apiAddr, os.Stdin, cmd.OutOrStdout())
			}
			err := PostPerUserPluginHook(ctx, apiAddr, os.Stdin, cmd.OutOrStdout(), curlOutput)
			cancel()
			if hookexec.PerUserPostOutage(err) {
				// This account's gateway is not running: the status the shell
				// hooks and plugins read as an outage, not as a refusal.
				fmt.Fprintf(cmd.ErrOrStderr(), "defenseclaw-gateway hook-post: %v\n", err)
				HookProcessExit(hookexec.PerUserPostOutageExit)
			}
			if hookexec.PerUserPostPeerUnverified(err) {
				// Nothing of the call was sent: the one failure the plugins
				// may send again (GAP-2083).
				if curlOutput {
					fmt.Fprint(cmd.OutOrStdout(), hookexec.PerUserPeerRefusalOutput(err, apiAddr, os.Getenv("_DC_HOOK_POST_DATA_DIR")))
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "defenseclaw-gateway hook-post: %v\n", err)
				HookProcessExit(hookexec.PerUserPostPeerUnverifiedExit)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&apiAddr, "api-addr", "", "gateway loopback host:port")
	cmd.Flags().IntVar(&maxTime, "max-time", 10, "maximum request time in seconds")
	cmd.Flags().BoolVar(&curlOutput, "curl-output", false, "print response body and trailing HTTP code")
	cmd.Flags().BoolVar(&secureClientService, "secure-client-service", false, "verify the Secure Client gateway service peer")
	_ = cmd.MarkFlagRequired("api-addr")
	return cmd
}

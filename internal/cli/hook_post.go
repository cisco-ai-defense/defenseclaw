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

type perUserHookInput struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

const maxPerUserHookInput = 6 << 20

func postPerUserPluginHook(ctx context.Context, apiAddr string, source io.Reader, output io.Writer, curlOutput bool) error {
	input, err := io.ReadAll(io.LimitReader(source, maxPerUserHookInput+1))
	if err != nil {
		return err
	}
	if len(input) > maxPerUserHookInput {
		return fmt.Errorf("per-user plugin hook input is too large")
	}
	var request perUserHookInput
	if err := json.Unmarshal(input, &request); err != nil {
		return fmt.Errorf("decode per-user plugin hook input: %w", err)
	}
	response, err := hookexec.PostPerUserHook(ctx, apiAddr, request.Path, request.Headers, []byte(request.Body))
	if err != nil {
		return err
	}
	if curlOutput {
		_, err = fmt.Fprintf(output, "%s\n%d", response.Body, response.Status)
		return err
	}
	return json.NewEncoder(output).Encode(response)
}

func init() {
	var apiAddr string
	var maxTime int
	var curlOutput bool
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
			defer cancel()
			return postPerUserPluginHook(ctx, apiAddr, os.Stdin, cmd.OutOrStdout(), curlOutput)
		},
	}
	cmd.Flags().StringVar(&apiAddr, "api-addr", "", "gateway loopback host:port")
	cmd.Flags().IntVar(&maxTime, "max-time", 10, "maximum request time in seconds")
	cmd.Flags().BoolVar(&curlOutput, "curl-output", false, "print response body and trailing HTTP code")
	_ = cmd.MarkFlagRequired("api-addr")
	rootCmd.AddCommand(cmd)

	var local, remote string
	verify := &cobra.Command{
		Use:         "hook-verify-connected",
		Hidden:      true,
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return hookexec.VerifyPerUserConnectedTuple(local, remote)
		},
	}
	verify.Flags().StringVar(&local, "local", "", "connected client endpoint")
	verify.Flags().StringVar(&remote, "remote", "", "connected gateway endpoint")
	_ = verify.MarkFlagRequired("local")
	_ = verify.MarkFlagRequired("remote")
	rootCmd.AddCommand(verify)
}

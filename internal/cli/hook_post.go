// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
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
const maxFramedHookHeaders = 64

func postPerUserHookInput(ctx context.Context, apiAddr string, source io.Reader, output io.Writer, curlOutput, framed bool) error {
	var request perUserHookInput
	var err error
	if framed {
		request, err = readFramedHookInput(source)
	} else {
		request, err = readPluginHookInput(source)
	}
	if err != nil {
		return err
	}
	response, err := hookexec.PostPerUserHook(ctx, apiAddr, request.Path, request.Headers, []byte(request.Body))
	if err != nil {
		return err
	}
	return writePluginHookReply(output, response, curlOutput)
}

// Shell hooks can send fields directly as NUL-separated bytes without a
// tr/sed process pair for every header and payload field. The final field is
// the body. Shell variables cannot contain NUL; the frame has an exact field
// count and the same total size bound as the plugin JSON request.
func readFramedHookInput(source io.Reader) (perUserHookInput, error) {
	input, err := io.ReadAll(io.LimitReader(source, maxPerUserHookInput+1))
	if err != nil {
		return perUserHookInput{}, err
	}
	if len(input) > maxPerUserHookInput {
		return perUserHookInput{}, fmt.Errorf("shell hook input is too large")
	}
	// Limit split allocation even when an untrusted caller supplies millions
	// of separators. One extra field is enough to reject an overlong frame.
	fields := bytes.SplitN(input, []byte{0}, 3+2*maxFramedHookHeaders+1)
	if len(fields) < 3 {
		return perUserHookInput{}, fmt.Errorf("shell hook input frame is incomplete")
	}
	count, err := strconv.Atoi(string(fields[1]))
	if err != nil || count < 0 || count > maxFramedHookHeaders || len(fields) != 3+2*count {
		return perUserHookInput{}, fmt.Errorf("shell hook input frame has invalid headers")
	}
	request := perUserHookInput{Path: string(fields[0]), Headers: make(map[string]string, count), Body: string(fields[len(fields)-1])}
	for i := 0; i < count; i++ {
		name, value := string(fields[2+2*i]), string(fields[3+2*i])
		if name == "" || strings.ContainsAny(value, "\r\n") {
			return perUserHookInput{}, fmt.Errorf("shell hook input frame has invalid header")
		}
		for _, c := range name {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-", c) {
				return perUserHookInput{}, fmt.Errorf("shell hook input frame has invalid header")
			}
		}
		request.Headers[name] = value
	}
	return request, nil
}

// postSecureClientPluginHook uses the protected gateway service identity,
// never the account-wide bearer, to decide whether it may send that bearer.
func postSecureClientPluginHook(ctx context.Context, apiAddr string, source io.Reader, output io.Writer) error {
	if !secureClientHost() {
		return fmt.Errorf("secure client gateway service peer cannot be verified on this host")
	}
	request, err := readPluginHookInput(source)
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

func readPluginHookInput(source io.Reader) (perUserHookInput, error) {
	input, err := io.ReadAll(io.LimitReader(source, maxPerUserHookInput+1))
	if err != nil {
		return perUserHookInput{}, err
	}
	if len(input) > maxPerUserHookInput {
		return perUserHookInput{}, fmt.Errorf("plugin hook input is too large")
	}
	var request perUserHookInput
	if err := json.Unmarshal(input, &request); err != nil {
		return perUserHookInput{}, fmt.Errorf("decode plugin hook input: %w", err)
	}
	return request, nil
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
	var framedInput bool
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
			err := postPerUserHookInput(ctx, apiAddr, os.Stdin, cmd.OutOrStdout(), curlOutput, framedInput)
			cancel()
			if hookexec.PerUserPostOutage(err) {
				// This account's gateway is not running: the status the shell
				// hooks and plugins read as an outage, not as a refusal.
				fmt.Fprintf(cmd.ErrOrStderr(), "defenseclaw-gateway hook-post: %v\n", err)
				hookProcessExit(hookexec.PerUserPostOutageExit)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&apiAddr, "api-addr", "", "gateway loopback host:port")
	cmd.Flags().IntVar(&maxTime, "max-time", 10, "maximum request time in seconds")
	cmd.Flags().BoolVar(&curlOutput, "curl-output", false, "print response body and trailing HTTP code")
	cmd.Flags().BoolVar(&framedInput, "framed-input", false, "read the shell hook field frame")
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

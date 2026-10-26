// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// defenseclaw-hook-post is the small POSIX per-user hook transport. Shell
// hooks select its verified installed path and send a framed request on stdin
// with --curl-output. The OpenCode and Amp per-user plugins send the gateway
// CLI's JSON request without it and read the JSON reply, so a hook event does
// not start the full gateway CLI.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

const maxInput = hookexec.MaxPerUserPluginRequest

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func run(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 1 && args[0] == "--version" {
		_, err := fmt.Fprintf(output, "defenseclaw-hook-post version %s (commit=%s, built=%s)\n", version, commit, date)
		return err
	}
	if len(args) > 0 && args[0] == "prefix-review" {
		flags := flag.NewFlagSet("prefix-review", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		event := flags.String("event", "", "registered hook event")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return fmt.Errorf("invalid bounded review arguments")
		}
		prefix, err := io.ReadAll(io.LimitReader(input, (1<<20)+2))
		if err != nil || len(prefix) > (1<<20)+1 {
			return fmt.Errorf("bounded review input is invalid or too large")
		}
		review := hookexec.OversizedReviewPayload(prefix, *event)
		if review == nil {
			return fmt.Errorf("bounded review input cannot be reviewed")
		}
		_, err = output.Write(review)
		return err
	}
	if len(args) == 0 || args[0] != "hook-post" {
		return fmt.Errorf("expected hook-post subcommand")
	}
	flags := flag.NewFlagSet("hook-post", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	apiAddr := flags.String("api-addr", "", "gateway loopback host:port")
	maxTime := flags.Int("max-time", 10, "maximum request time in seconds")
	curlOutput := flags.Bool("curl-output", false, "print response body and trailing HTTP code")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *apiAddr == "" || *maxTime < 1 || *maxTime > 30 {
		return fmt.Errorf("invalid per-user hook transport arguments")
	}
	data, err := io.ReadAll(io.LimitReader(input, maxInput+1))
	if err != nil {
		return err
	}
	if len(data) > maxInput {
		return fmt.Errorf("native hook input is invalid or too large")
	}
	var request hookexec.PerUserPluginRequest
	if *curlOutput {
		if !bytes.HasPrefix(data, []byte("DCPOST1\x00")) {
			return fmt.Errorf("native hook input is invalid or too large")
		}
		frame, err := hookexec.ReadNativeHookFrame(data)
		if err != nil {
			return err
		}
		request = hookexec.PerUserPluginRequest{Path: frame.Path, Headers: frame.Headers, Body: frame.Body}
	} else if request, err = hookexec.DecodePerUserPluginRequest(data); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*maxTime)*time.Second)
	defer cancel()
	response, err := hookexec.PostPerUserHook(ctx, *apiAddr, request.Path, request.Headers, []byte(request.Body))
	if err != nil {
		return err
	}
	if !*curlOutput {
		return json.NewEncoder(output).Encode(response)
	}
	_, err = fmt.Fprintf(output, "%s\n%d", response.Body, response.Status)
	return err
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw-hook-post: %v\n", err)
		if hookexec.PerUserPostOutage(err) {
			os.Exit(hookexec.PerUserPostOutageExit)
		}
		os.Exit(1)
	}
}

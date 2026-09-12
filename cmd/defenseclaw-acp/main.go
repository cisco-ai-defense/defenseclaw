// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw-acp: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "-version") {
		fmt.Fprintf(os.Stdout, "defenseclaw-acp version %s (commit=%s, built=%s)\n", version, commit, date)
		return nil
	}
	if len(args) == 1 && args[0] == "--version-json" {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema_version": 1, "name": "defenseclaw-acp", "version": version,
			"commit": commit, "built": date,
		})
	}
	flags := flag.NewFlagSet("defenseclaw-acp", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	agentID := flags.String("agent", "", "ACP catalog agent ID")
	clientID := flags.String("client", "custom", "ACP client ID")
	profile := flags.String("profile", "default", "DefenseClaw ACP policy profile")
	mode := flags.String("mode", "observe", "observe or action")
	gateway := flags.String("gateway", "http://127.0.0.1:18970/api/v1/acp/evaluate", "loopback evaluation endpoint")
	tokenFile := flags.String("token-file", "", "file containing the gateway bearer token")
	contractLock := flags.String("contract-lock", "", "setup-generated runtime contract lock")
	catalog := flags.Bool("catalog", false, "print the built-in ACP catalog as JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *catalog {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(acp.BuiltinCatalog())
	}

	commandArgs := flags.Args()
	command := ""
	if len(commandArgs) > 0 {
		command = commandArgs[0]
		commandArgs = commandArgs[1:]
	} else {
		if *agentID == "" {
			return errors.New("set --agent or provide a command after --")
		}
		agent, err := acp.LookupAgent(*agentID)
		if err != nil {
			return err
		}
		command = agent.Command
		commandArgs = append([]string(nil), agent.Args...)
	}
	if strings.TrimSpace(command) == "" {
		return errors.New("ACP agent command is empty")
	}
	if *contractLock == "" {
		return errors.New("--contract-lock is required for guarded ACP execution")
	}
	if err := acp.ValidateRuntimeContract(*contractLock, *clientID, *agentID, *profile, acp.Mode(*mode), command); err != nil {
		return err
	}

	token := ""
	if *tokenFile == "" {
		return errors.New("--token-file is required for guarded ACP execution")
	}
	if *tokenFile != "" {
		clean := filepath.Clean(*tokenFile)
		info, err := os.Lstat(clean)
		if err != nil {
			return fmt.Errorf("stat token file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return errors.New("token file is not a regular file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return errors.New("token file permissions are too broad")
		}
		if err := safefile.ValidatePrivateFile(clean); err != nil {
			return errors.New("token file protection is unsafe")
		}
		if info.Size() > 16<<10 {
			return errors.New("token file is unexpectedly large")
		}
		body, err := safefile.ReadRegularFileBounded(clean, 16<<10)
		if err != nil {
			return fmt.Errorf("read token file: %w", err)
		}
		token = strings.TrimSpace(string(body))
		if token == "" {
			return errors.New("token file is empty")
		}
	}
	evaluator, err := acp.NewHTTPEvaluator(*gateway, token)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return acp.Run(ctx, acp.ProxyOptions{
		AgentID: *agentID, ClientID: *clientID, Profile: *profile,
		Mode: acp.Mode(*mode), Command: command, Args: commandArgs,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Evaluator: evaluator,
	})
}

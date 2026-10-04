// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// firstRequestWait bounds how long a guard that cannot start waits for the
// editor's first request so it can answer it with a readable error.
const firstRequestWait = 10 * time.Second

// startupErrorCode is the JSON-RPC "internal error" code.
const startupErrorCode = -32603

func main() {
	if err := run(os.Args[1:]); err != nil {
		var startup *startupError
		if errors.As(err, &startup) {
			fmt.Fprintf(os.Stderr, "defenseclaw-acp: %s\n", startup.message)
			if stdinIsPipe() {
				answerFirstRequest(os.Stdin, os.Stdout, startup.message, firstRequestWait)
			}
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "defenseclaw-acp: %v\n", err)
		os.Exit(1)
	}
}

// startupError is a failure after the editor launched the guard but before
// the proxy started. Editors only show JSON-RPC errors, not stderr, so the
// guard answers the first request with message, which says in plain words
// what is wrong and what to run.
type startupError struct {
	message string
	err     error
}

func (e *startupError) Error() string { return e.message }
func (e *startupError) Unwrap() error { return e.err }

func newStartupError(err error, clientID, agentID, profile, mode string) error {
	setup := fmt.Sprintf("defenseclaw acp setup --client %s --agent %s", clientID, agentID)
	if profile != "" && profile != "default" {
		setup += " --profile " + profile
	}
	if mode == string(acp.ModeAction) {
		setup += " --activate"
	}
	pair := clientID + "/" + agentID
	if errors.Is(err, acp.ErrRuntimeContractMissing) {
		return &startupError{err: err, message: fmt.Sprintf(
			"DefenseClaw ACP guard is not set up for %s (the binding was removed). Run '%s', or delete this editor entry.",
			pair, setup)}
	}
	return &startupError{err: err, message: fmt.Sprintf(
		"DefenseClaw ACP guard could not start for %s: %v. Run 'defenseclaw acp verify', then '%s', or delete this editor entry.",
		pair, err, setup)}
}

func stdinIsPipe() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice == 0
}

// answerFirstRequest waits up to wait for the first JSON-RPC request on in
// (normally initialize) and answers it with a JSON-RPC error carrying
// message. It reports whether a response was written.
func answerFirstRequest(in io.Reader, out io.Writer, message string, wait time.Duration) bool {
	ids := make(chan json.RawMessage, 1)
	go func() {
		defer close(ids)
		scanner := bufio.NewScanner(in)
		scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for scanner.Scan() {
			msg, err := acp.ParseMessage(scanner.Bytes())
			if err == nil && msg.IsRequest() {
				ids <- append(json.RawMessage(nil), msg.ID...)
				return
			}
		}
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case id, ok := <-ids:
		if !ok {
			return false
		}
		_, err := out.Write(append(acp.ErrorResponse(id, startupErrorCode, message), '\n'))
		return err == nil
	case <-timer.C:
		return false
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

	fail := func(err error) error { return newStartupError(err, *clientID, *agentID, *profile, *mode) }
	commandArgs := flags.Args()
	command := ""
	if len(commandArgs) > 0 {
		command = commandArgs[0]
		commandArgs = commandArgs[1:]
	} else {
		if *agentID == "" {
			return fail(errors.New("set --agent or provide a command after --"))
		}
		agent, err := acp.LookupAgent(*agentID)
		if err != nil {
			return fail(err)
		}
		command = agent.Command
		commandArgs = append([]string(nil), agent.Args...)
	}
	if strings.TrimSpace(command) == "" {
		return fail(errors.New("ACP agent command is empty"))
	}
	if *contractLock == "" {
		return fail(errors.New("--contract-lock is required for guarded ACP execution"))
	}
	if err := acp.ValidateRuntimeContract(*contractLock, *clientID, *agentID, *profile, acp.Mode(*mode), command); err != nil {
		return fail(err)
	}

	token := ""
	if *tokenFile == "" {
		return fail(errors.New("--token-file is required for guarded ACP execution"))
	}
	if *tokenFile != "" {
		clean := filepath.Clean(*tokenFile)
		info, err := os.Lstat(clean)
		if err != nil {
			return fail(fmt.Errorf("stat token file: %w", err))
		}
		if !info.Mode().IsRegular() {
			return fail(errors.New("token file is not a regular file"))
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return fail(errors.New("token file permissions are too broad"))
		}
		if err := safefile.ValidatePrivateFile(clean); err != nil {
			return fail(errors.New("token file protection is unsafe"))
		}
		if info.Size() > 16<<10 {
			return fail(errors.New("token file is unexpectedly large"))
		}
		body, err := safefile.ReadRegularFileBounded(clean, 16<<10)
		if err != nil {
			return fail(fmt.Errorf("read token file: %w", err))
		}
		token = strings.TrimSpace(string(body))
		if token == "" {
			return fail(errors.New("token file is empty"))
		}
	}
	evaluator, err := acp.NewHTTPEvaluator(*gateway, token)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return acp.Run(ctx, acp.ProxyOptions{
		AgentID: *agentID, ClientID: *clientID, Profile: *profile,
		Mode: acp.Mode(*mode), Command: command, Args: commandArgs,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Evaluator: evaluator,
	})
}

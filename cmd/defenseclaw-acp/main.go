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
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

func newStartupError(err error, clientID, agentID, profile, mode, contractLock string) error {
	pair := clientID + "/" + agentID
	activate := ""
	if mode == string(acp.ModeAction) {
		activate = " --activate"
	}
	if gateway := managedGatewayCommand(contractLock); gateway != "" {
		// A managed host has only the gateway binary, not the Python CLI
		// the per-user text names (GAP-0270).
		next := fmt.Sprintf("If your administrator revoked or has not enrolled %s for you, ask them to run "+
			"enterprise acp enroll; then run %s enterprise acp setup --client %s --agent %s --profile %s%s "+
			"(the command the enrollment reports), or delete this editor entry.",
			pair, gateway, clientID, agentID, profile, activate)
		if errors.Is(err, acp.ErrRuntimeContractMissing) {
			return &startupError{err: err, message: fmt.Sprintf(
				"DefenseClaw ACP guard is not set up for %s (the binding was removed). %s", pair, next)}
		}
		return &startupError{err: err, message: fmt.Sprintf(
			"DefenseClaw ACP guard could not start for %s: %v. %s", pair, err, next)}
	}
	setup := fmt.Sprintf("defenseclaw acp setup --client %s --agent %s", clientID, agentID)
	if profile != "" && profile != "default" {
		setup += " --profile " + profile
	}
	setup += activate
	if errors.Is(err, acp.ErrRuntimeContractMissing) {
		return &startupError{err: err, message: fmt.Sprintf(
			"DefenseClaw ACP guard is not set up for %s (the binding was removed). Run '%s', or delete this editor entry.",
			pair, setup)}
	}
	return &startupError{err: err, message: fmt.Sprintf(
		"DefenseClaw ACP guard could not start for %s: %v. Run 'defenseclaw acp verify', then '%s', or delete this editor entry.",
		pair, err, setup)}
}

// guardExecutable is the path of this guard; a variable for tests.
var guardExecutable = os.Executable

// managedGatewayCommand returns the gateway command of a managed host, or
// "" on a per-user install. A guard is managed when its contract lock
// records managed custody or, with the lock gone, when it runs from an
// administrator-owned path; either way the gateway binary must sit next to
// it.
func managedGatewayCommand(contractLock string) string {
	guard, err := guardExecutable()
	if err != nil {
		return ""
	}
	if !contractLockManagedCustody(contractLock) && managed.ValidateTrustedFilePath(guard, "managed ACP guard") != nil {
		return ""
	}
	names := []string{"defenseclaw-gateway"}
	if runtime.GOOS == "windows" {
		names = []string{"defenseclaw.exe", "defenseclaw-gateway.exe"}
	}
	for _, name := range names {
		path := filepath.Join(filepath.Dir(guard), name)
		if info, statErr := os.Stat(path); statErr == nil && info.Mode().IsRegular() {
			if runtime.GOOS == "windows" {
				return "& \"" + path + "\""
			}
			return path
		}
	}
	return ""
}

// contractLockManagedCustody reports whether the contract lock at path was
// written by a managed enrollment. It only chooses the remediation text.
func contractLockManagedCustody(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	body, err := safefile.ReadRegularFileBounded(filepath.Clean(path), acp.MaxContractLockBytes)
	if err != nil {
		return false
	}
	var lock struct {
		Guard struct {
			ManagedCustody bool `json:"managed_custody"`
		} `json:"guard"`
	}
	return json.Unmarshal(body, &lock) == nil && lock.Guard.ManagedCustody
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

	fail := func(err error) error {
		return newStartupError(err, *clientID, *agentID, *profile, *mode, *contractLock)
	}
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

	if *tokenFile == "" {
		return fail(errors.New("--token-file is required for guarded ACP execution"))
	}
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
	token := strings.TrimSpace(string(body))
	if token == "" {
		return fail(errors.New("token file is empty"))
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

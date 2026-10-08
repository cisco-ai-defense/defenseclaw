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
	"net/url"
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

// setupCommand is the command that writes this editor entry again: the
// gateway's enterprise acp setup for a managed enrollment, whose host has no
// other DefenseClaw command, or defenseclaw acp setup. managedEntry reports
// which.
func setupCommand(clientID, agentID, profile, mode, contractLock string, managedFlags ...string) (command string, managedEntry bool) {
	activate := ""
	if mode == string(acp.ModeAction) {
		activate = " --activate"
	}
	if gateway := standaloneManagedGatewayCommand(contractLock); gateway != "" {
		return fmt.Sprintf("%s enterprise acp setup --client %s --agent %s --profile %s%s%s",
			gateway, clientID, agentID, profile, activate, strings.Join(managedFlags, "")), true
	}
	setup := fmt.Sprintf("defenseclaw acp setup --client %s --agent %s", clientID, agentID)
	if profile != "" && profile != "default" {
		setup += " --profile " + profile
	}
	return setup + activate, false
}

// managedSetupFlags are the enterprise acp setup flags this guard knows from
// its own argv. The setup refuses to run without --api-port, and a data dir
// other than <home>/.defenseclaw must be named, so the command the guard
// printed did not run (GAP-0723).
func managedSetupFlags(gatewayURL, tokenFile string) string {
	flags := ""
	if parsed, err := url.Parse(gatewayURL); err == nil && parsed.Port() != "" {
		flags += " --api-port " + parsed.Port()
	}
	if tokenFile = strings.TrimSpace(tokenFile); tokenFile != "" {
		dataDir := filepath.Dir(filepath.Dir(filepath.Clean(tokenFile)))
		home, err := os.UserHomeDir()
		if err != nil || !sameGuardPath(dataDir, filepath.Join(home, ".defenseclaw")) {
			if runtime.GOOS == "windows" {
				flags += " --data-dir '" + strings.ReplaceAll(dataDir, "'", "''") + "'"
			} else {
				flags += fmt.Sprintf(" --data-dir %q", dataDir)
			}
		}
	}
	return flags
}

func sameGuardPath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func newStartupError(err error, clientID, agentID, profile, mode, contractLock string, managedFlags ...string) error {
	pair := clientID + "/" + agentID
	setup, managedEntry := setupCommand(clientID, agentID, profile, mode, contractLock, managedFlags...)
	if managedEntry {
		// A managed host has only the gateway binary, not the Python CLI
		// the per-user text names (GAP-0270).
		next := fmt.Sprintf("If your administrator revoked or has not enrolled %s for you, ask them to run "+
			"enterprise acp enroll; then run %s (the command the enrollment reports), or delete this editor entry.",
			pair, setup)
		if errors.Is(err, acp.ErrRuntimeContractMissing) {
			return &startupError{err: err, message: fmt.Sprintf(
				"DefenseClaw ACP guard is not set up for %s (the binding was removed). %s", pair, next)}
		}
		return &startupError{err: err, message: fmt.Sprintf(
			"DefenseClaw ACP guard could not start for %s: %v. %s", pair, err, next)}
	}
	if errors.Is(err, acp.ErrRuntimeContractMissing) {
		return &startupError{err: err, message: fmt.Sprintf(
			"DefenseClaw ACP guard is not set up for %s (the binding was removed). Run '%s', or delete this editor entry.",
			pair, setup)}
	}
	return &startupError{err: err, message: fmt.Sprintf(
		"DefenseClaw ACP guard could not start for %s: %v. Run 'defenseclaw acp verify', then '%s', or delete this editor entry.",
		pair, err, setup)}
}

// standaloneManagedGatewayCommand uses the administrator-owned standalone
// descriptor as the profile gate. Secure Client has no such descriptor and
// keeps the startup error bytes from main, including for old managed locks.
func standaloneManagedGatewayCommand(contractLock string) string {
	if managed.IsSecureClientProfile(os.Getenv(managed.EnterpriseProfileEnv)) {
		return ""
	}
	layout, err := managedACPStandaloneLayout()
	if err != nil {
		return ""
	}
	if _, err := loadACPStandaloneDescriptor(layout.DescriptorPath); err != nil {
		return ""
	}
	return managedGatewayCommand(contractLock)
}

var loadACPStandaloneDescriptor = managed.LoadRuntimeDescriptor

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
	dirs := []string{filepath.Dir(guard)}
	if !acp.SecureClientHost() && contractLockManagedCustody(contractLock) {
		// A managed lock whose guard is not the installed one still belongs
		// to a managed host: name its gateway, not the per-user commands it
		// lacks (GAP-0391).
		if layout, layoutErr := managed.StandaloneLayoutFor(runtime.GOOS); layoutErr == nil {
			dirs = append(dirs, layout.BinDir)
		}
	}
	for _, dir := range dirs {
		for _, name := range names {
			path := filepath.Join(dir, name)
			if info, statErr := os.Stat(path); statErr == nil && info.Mode().IsRegular() {
				if runtime.GOOS == "windows" {
					return "& \"" + path + "\""
				}
				return path
			}
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

	flagsForSetup := managedSetupFlags(*gateway, *tokenFile)
	fail := func(err error) error {
		return newStartupError(err, *clientID, *agentID, *profile, *mode, *contractLock, flagsForSetup)
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
	setup, managedEntry := setupCommand(*clientID, *agentID, *profile, *mode, *contractLock, flagsForSetup)
	return acp.Run(ctx, acp.ProxyOptions{
		AgentID: *agentID, ClientID: *clientID, Profile: *profile,
		Mode: acp.Mode(*mode), Command: command, Args: commandArgs,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Evaluator: evaluator,
		Managed: managedEntry, SetupCommand: setup,
		SetupCommandFor: func(profile string, mode acp.Mode) string {
			command, _ := setupCommand(*clientID, *agentID, profile, string(mode), *contractLock, flagsForSetup)
			return command
		},
	})
}

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
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

const maxInput = hookexec.MaxPerUserPluginRequest

// peerRefusalOutput is the root-gateway diagnosis printed after a refused
// listener (a seam for tests: the listener a real refusal needs belongs to
// another account).
var peerRefusalOutput = hookexec.PerUserPeerRefusalOutput

const userGuardCapability = "defenseclaw-hook-post guard-user-hook v1\n"

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func run(args []string, input io.Reader, output io.Writer) error {
	return runWithPeer(args, input, output, nil)
}

// runWithPeer is run; peer, when set, receives the process behind the
// request's connection (hookexec.WithPerUserPeerRecord).
func runWithPeer(args []string, input io.Reader, output io.Writer, peer *hookexec.PerUserPeerRecord) error {
	return runCall(args, input, output, peer, nil)
}

// postedCall is the path and body of the request a run sent (runCall).
type postedCall struct{ path, body string }

// runCall is runWithPeer; call, when set, receives the request that was sent.
func runCall(args []string, input io.Reader, output io.Writer, peer *hookexec.PerUserPeerRecord, call *postedCall) error {
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
	opts, err := parseHookPostFlags(args)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(input, maxInput+1))
	if err != nil {
		return err
	}
	if len(data) > maxInput {
		return fmt.Errorf("native hook input is invalid or too large")
	}
	var request hookexec.PerUserPluginRequest
	if opts.curlOutput {
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
	timeout := requestTimeout(opts.maxTime)
	if call != nil {
		*call = postedCall{path: request.Path, body: request.Body}
	}
	if request.Headers == nil {
		request.Headers = map[string]string{}
	}
	// Tell the gateway how long this request waits for its answer, so a
	// tool-call judge answers inside it (#1395).
	request.Headers[hookexec.HookAnswerWithinHeader] = strconv.FormatInt(timeout.Milliseconds(), 10)
	ctx, cancel := context.WithTimeout(hookexec.WithPerUserPeerRecord(
		hookexec.WithPerUserGatewayDataDir(context.Background(), os.Getenv(hookPostDataDirEnv)), peer), timeout)
	defer cancel()
	response, err := hookexec.PostPerUserHook(ctx, opts.apiAddr, request.Path, request.Headers, []byte(request.Body))
	if err != nil {
		return err
	}
	hookexec.PerUserGatewayRecordObservedAnswer(os.Getenv(hookPostDataDirEnv), peer)
	if !opts.curlOutput {
		return json.NewEncoder(output).Encode(response)
	}
	_, err = fmt.Fprintf(output, "%s\n%d", response.Body, response.Status)
	return err
}

// hookPostFlags are the parsed arguments of the hook-post subcommand.
type hookPostFlags struct {
	apiAddr    string
	maxTime    int
	curlOutput bool
}

// parseHookPostFlags is the one reading of the hook-post arguments: the
// request, and the diagnosis printed after a refused listener, take the
// address and output mode from it, so every spelling the flag package
// accepts (name value, name=value, a repeated flag, --curl-output=true)
// reaches both the same way (rel-1-0-6 GAP-0712).
func parseHookPostFlags(args []string) (hookPostFlags, error) {
	if len(args) == 0 || args[0] != "hook-post" {
		return hookPostFlags{}, fmt.Errorf("expected hook-post subcommand")
	}
	flags := flag.NewFlagSet("hook-post", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var opts hookPostFlags
	flags.StringVar(&opts.apiAddr, "api-addr", "", "gateway loopback host:port")
	flags.IntVar(&opts.maxTime, "max-time", 10, "maximum request time in seconds")
	flags.BoolVar(&opts.curlOutput, "curl-output", false, "print response body and trailing HTTP code")
	if err := flags.Parse(args[1:]); err != nil {
		return hookPostFlags{}, err
	}
	if flags.NArg() != 0 || opts.apiAddr == "" || opts.maxTime < 1 || opts.maxTime > 30 {
		return hookPostFlags{}, fmt.Errorf("invalid per-user hook transport arguments")
	}
	return opts, nil
}

// hookPostDeadlineEnv is the shell hook's time left for this request in
// milliseconds (_hardening.sh defenseclaw_gateway_post). --max-time is whole
// seconds, which rounds the shell's own time up and cost a large tool call
// up to most of a second of its answer budget (GAP-2279). The value counts
// only below --max-time plus one second, so it never stretches the request
// by a whole second; without it, --max-time alone bounds the request.
const hookPostDeadlineEnv = "_DC_HOOK_POST_DEADLINE_MS"

// hookPostDataDirEnv is the data directory of the shell hook that runs this
// helper (the parent of its own hooks folder), where a gateway start or
// restart holds its start lock.
const hookPostDataDirEnv = "_DC_HOOK_POST_DATA_DIR"

// hookPostAccountHomeEnv is the account home the shell hook saved before it
// replaced HOME with a scratch folder for its own run (_hardening.sh). The
// late-call scan tells the protected folders and files against it
// (GAP-0850).
const hookPostAccountHomeEnv = "_DC_HOOK_POST_ACCOUNT_HOME"

// accountHome is the home of the account the hook runs for, not the scratch
// HOME the shell hook gives this process: the home the shell saved, exactly
// as it got it, else the account database entry of the user. The saved value
// is not rewritten here. The scan resolves it by file system rules (a parent
// step through a link, a trailing slash). A value that is no folder holds no
// protected file; the scan then tells the account database home and indexes
// the other homes the call can mean (hookpaths.LateOrdinaryCallAt). Empty
// (the home of the process) only when neither is known.
func accountHome() string {
	if home := os.Getenv(hookPostAccountHomeEnv); home != "" {
		return home
	}
	if current, err := user.Current(); err == nil && filepath.IsAbs(current.HomeDir) {
		return current.HomeDir
	}
	return ""
}

func requestTimeout(maxTime int) time.Duration {
	limit := time.Duration(maxTime) * time.Second
	ms, err := strconv.Atoi(os.Getenv(hookPostDeadlineEnv))
	if err != nil || ms < 1 || ms >= (maxTime+1)*1000 {
		return limit
	}
	return time.Duration(ms) * time.Millisecond
}

type gatewayStartObservation struct {
	start   bool
	changed bool
}

// observeGatewayStartDuringCall samples the account-owned start lock after
// the request reaches a verified gateway socket. Once that lock is released,
// it checks whether the connected peer gave up the port. Both signals may be
// gone by the time an unanswered call reaches its deadline.
func observeGatewayStartDuringCall(dataDir string, peer *hookexec.PerUserPeerRecord) func() gatewayStartObservation {
	if dataDir == "" || peer == nil {
		return func() gatewayStartObservation { return gatewayStartObservation{} }
	}
	stop := make(chan struct{})
	var start, changed atomic.Bool
	go func() {
		select {
		case <-peer.Connected():
		case <-stop:
			return
		}
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			if hookexec.PerUserGatewayStartInProgress(dataDir) {
				start.Store(true)
				break
			}
			select {
			case <-ticker.C:
			case <-stop:
				return
			}
		}
		for hookexec.PerUserGatewayStartInProgress(dataDir) {
			select {
			case <-ticker.C:
			case <-stop:
				return
			}
		}
		proofTicker := time.NewTicker(100 * time.Millisecond)
		defer proofTicker.Stop()
		for {
			if hookexec.PerUserGatewayRestartProvenDuringCall(dataDir, peer, true) {
				changed.Store(true)
				return
			}
			select {
			case <-proofTicker.C:
			case <-stop:
				return
			}
		}
	}()
	return func() gatewayStartObservation {
		close(stop)
		return gatewayStartObservation{start: start.Load(), changed: changed.Load()}
	}
}

func main() {
	code := runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	// No outage-mode look of the native hook outlives the call (GAP-0268).
	stopNativeHookLooks()
	os.Exit(code)
}

// runMain is main with its streams: the exit status of the request.
func runMain(args []string, input io.Reader, output, errOutput io.Writer) int {
	if len(args) == 1 && args[0] == "--guard-user-hook-capability" {
		if _, err := io.WriteString(output, userGuardCapability); err != nil {
			return 2
		}
		return 0
	}
	if len(args) == 0 {
		// Cursor imports the Claude Code command without its arguments.
		var event struct {
			CursorVersion string `json:"cursor_version"`
		}
		if json.NewDecoder(io.LimitReader(input, hookexec.DefaultMaxBody+1)).Decode(&event) == nil &&
			event.CursorVersion != "" {
			return 0
		}
		fmt.Fprintln(errOutput, "DefenseClaw hook registration is invalid")
		return 2
	}
	if args[0] == "guard-user-hook" {
		self, err := os.Executable()
		if err != nil {
			fmt.Fprintln(errOutput, "DefenseClaw hook could not start")
			return 2
		}
		return runUserHookGuardAt(self, args, input, output, errOutput)
	}
	// The process behind the socket the call is sent on, as the kernel names
	// it when the call connects: a no-answer is the restart outage only when
	// that process changed during the call (lead ruling on rel-1-0-6
	// GAP-0295). The shell names the data directory from the hook's own
	// folder.
	dataDir := os.Getenv(hookPostDataDirEnv)
	peer := hookexec.NewPerUserPeerRecord()
	stopObservingStart := observeGatewayStartDuringCall(dataDir, peer)
	var call postedCall
	err := runCall(args, input, output, peer, &call)
	startObservation := stopObservingStart()
	if err == nil {
		return 0
	}
	fmt.Fprintf(errOutput, "defenseclaw-hook-post: %v\n", err)
	switch {
	case hookexec.PerUserPostOutage(err):
		// A refusal or a connection closed before any HTTP status while the
		// start lock is held is a restart outage. Decide it before the new
		// listener appears or gateway.pid is published (GAP-0497).
		if hookexec.PerUserGatewayStartInProgress(dataDir) {
			return hookexec.PerUserPostRestartOutageExit
		}
		return hookexec.PerUserPostOutageExit
	case hookexec.PerUserPostListenerUnanswered(err):
		// This account's recorded gateway holds the listener and took no
		// accept for the whole wait (a stopped or frozen gateway): nothing was
		// sent, and it is no process of another account. The shell reads it
		// as the outage, as the native hook does, for every event but a tool
		// call that does not plainly name nothing protected.
		if lateOrdinary(call) || nonToolGateEvent(call) {
			return hookexec.PerUserPostLateOrdinaryExit
		}
		return hookexec.PerUserPostNoAnswerExit
	case hookexec.PerUserPostPeerUnverified(err):
		// Nothing of the call was sent: the one failure the OpenCode and
		// Amp plugins send again (GAP-2083). The shell hook reads the
		// root-gateway diagnosis from stdout, as it does from the gateway
		// CLI hook-post (rel-1-0-6 GAP-0712).
		if opts, perr := parseHookPostFlags(args); perr == nil && opts.curlOutput {
			_, _ = io.WriteString(output, peerRefusalOutput(err, opts.apiAddr, dataDir))
		}
		return hookexec.PerUserPostPeerUnverifiedExit
	case hookexec.PerUserPostNoAnswer(err):
		// A local deadline before the verified connection is not an
		// unanswered gateway call. Keep it distinct from exit 9, which
		// records verified contact without a decision.
		select {
		case <-peer.Connected():
		default:
			return 1
		}
		// No status after verified contact: the shell hook reads it as a
		// no-answer, or as the restart outage when this account's start lock
		// was held after the call reached its gateway and that gateway gave
		// up the port during the call (rel-1-0-6 GAP-0498).
		if startObservation.changed || hookexec.PerUserGatewayRestartProvenDuringCall(dataDir, peer, startObservation.start) {
			return hookexec.PerUserPostRestartNoAnswerExit
		}
		if fresh, reason := hookexec.PerUserGatewayFreshStartNoAnswer(dataDir, peer); fresh {
			return hookexec.PerUserPostRestartNoAnswerExit
		} else {
			// The shell consumes this fixed token only for exit 9. It never
			// reaches the agent or changes the no-answer decision.
			if opts, perr := parseHookPostFlags(args); perr == nil && opts.curlOutput {
				_, _ = fmt.Fprint(output, "DCPOSTPROOF1:"+reason)
			}
		}
		if lateOrdinary(call) {
			// A gateway that is up and late with a call that names nothing
			// protected is no reason to deny it (GAP-0518): the shell reads
			// this status as the outage and follows the outage mode.
			return hookexec.PerUserPostLateOrdinaryExit
		}
		return hookexec.PerUserPostNoAnswerExit
	}
	return 1
}

// lateOrdinary reports a sent Claude Code or Codex tool call that the scan
// finds ordinary (hookpaths.LateOrdinaryCall). The connector is named by the
// request path; any other path is not scanned.
func lateOrdinary(call postedCall) bool {
	var connector string
	switch {
	case strings.Contains(call.path, "claude-code") || strings.Contains(call.path, "claudecode"):
		connector = "claudecode"
	case strings.Contains(call.path, "codex"):
		connector = "codex"
	default:
		return false
	}
	return hookpaths.LateOrdinaryCallAt(accountHome(), connector, []byte(call.body))
}

// nonToolGateEvent reports a Claude Code or Codex call that names an event
// which is not a tool gate (a post-tool batch, a prompt, a session event).
// Any other connector, or an event it cannot read, is not one.
func nonToolGateEvent(call postedCall) bool {
	var connector string
	switch {
	case strings.Contains(call.path, "claude-code") || strings.Contains(call.path, "claudecode"):
		connector = "claudecode"
	case strings.Contains(call.path, "codex"):
		connector = "codex"
	default:
		return false
	}
	var event struct {
		Name string `json:"hook_event_name"`
	}
	if json.Unmarshal([]byte(call.body), &event) != nil || strings.TrimSpace(event.Name) == "" {
		return false
	}
	return !hookexec.ToolGateEvent(connector, event.Name)
}

func runUserHookGuardAt(self string, args []string, input io.Reader, output, errOutput io.Writer) int {
	valid := len(args) == 7 || len(args) == 9
	if valid {
		native, home := args[1], args[6]
		account := filepath.Dir(home)
		valid = args[0] == "guard-user-hook" && args[2] == "hook" &&
			args[3] == "--connector" && args[4] == "claudecode" &&
			args[5] == "--hook-home" && filepath.IsAbs(home) &&
			filepath.Clean(home) == home && filepath.Base(home) == ".defenseclaw" &&
			native == filepath.Join(account, ".local", "bin", "defenseclaw-hook-user") &&
			userGuardExecutableMatches(self, filepath.Join(account, ".local", "bin", "defenseclaw-hook-post"))
		if len(args) == 9 {
			valid = valid && args[7] == "--api-addr"
		}
	}
	if !valid {
		fmt.Fprintln(errOutput, "DefenseClaw hook registration is invalid")
		return 2
	}
	// The native hook runs in this process (S8 B2): the same hook body as
	// defenseclaw-hook-user (internal/hookuser), with the registered home and
	// address, so the guard leg is one process and decides even when the
	// hook-user binary is missing or broken.
	return runNativeUserHook(self, args[6], registeredAPIAddr(args), input, output, errOutput)
}

// registeredAPIAddr is the --api-addr value of a checked guard command line,
// "" when it names none.
func registeredAPIAddr(args []string) string {
	if len(args) == 9 {
		return args[8]
	}
	return ""
}

func userGuardExecutableMatches(self, registered string) bool {
	if self == registered {
		return true
	}
	actual, err := os.Stat(self)
	if err != nil || !actual.Mode().IsRegular() {
		return false
	}
	expected, err := os.Stat(registered)
	return err == nil && expected.Mode().IsRegular() && os.SameFile(actual, expected)
}

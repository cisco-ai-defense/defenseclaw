// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// maxPayloadBytes is the agent event cap, the host hooks' 1 MiB
// (hookexec.DefaultMaxBody): a larger event is refused closed.
const maxPayloadBytes = hookexec.DefaultMaxBody

// HookOptions is one hook invocation.
type HookOptions struct {
	Connector    string
	Event        string
	HookContract string
	// Notify is a Codex notify call: the event JSON is NotifyJSON, not stdin.
	Notify     bool
	NotifyJSON string
	Config     Config
	// ConfigErr is why the configuration could not be loaded; the call is
	// then refused closed in the connector's format.
	ConfigErr error
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	Getenv    func(string) string
	// Send overrides the helper-then-direct transport (tests).
	Send func(ctx context.Context, r Request) (Response, string, error)
}

// RunHook runs one hook call and returns the exit code.
func RunHook(ctx context.Context, o HookOptions) int {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	mode := Mode(o.Getenv)
	call := hookexec.RemoteCall{
		Connector: o.Connector, Event: o.Event, HookContractID: o.HookContract,
		FailMode: o.Config.FailModeFor(mode), Stdout: o.Stdout, Stderr: o.Stderr,
	}
	if o.Config.LogDir != "" {
		call.LogHome = o.Config.LogDir
	}
	if call.HookContractID == "" && o.Config.HookContracts != nil {
		call.HookContractID = o.Config.HookContracts[o.Connector]
	}
	refuse := func(reason string) int {
		code, err := hookexec.RemoteRefused(call, reason)
		if err != nil {
			fmt.Fprintf(o.Stderr, "defenseclaw: %s; %v\n", reason, err)
		}
		return code
	}
	if o.ConfigErr != nil {
		call.FailMode = "closed"
		return refuse("DefenseClaw actor kit is not installed correctly: " + o.ConfigErr.Error())
	}

	if o.Notify {
		return runNotify(ctx, o, mode)
	}

	var payload []byte
	if o.Stdin != nil {
		b, err := io.ReadAll(io.LimitReader(o.Stdin, maxPayloadBytes+1))
		if err != nil {
			return refuse("DefenseClaw could not read the hook event: " + err.Error())
		}
		payload = b
	}
	if int64(len(payload)) > maxPayloadBytes {
		return refuse("DefenseClaw hook payload too large")
	}
	call.Payload = payload
	if call.Event == "" {
		var v struct {
			Event string `json:"hook_event_name"`
		}
		_ = json.Unmarshal(payload, &v)
		call.Event = v.Event
	}
	if !json.Valid(payload) {
		return refuse("DefenseClaw could not read the hook event: it is not JSON")
	}
	env := HookEnvelope{
		V: EnvelopeVersion, Connector: o.Connector, Event: call.Event, HookContract: call.HookContractID,
		Mode: mode, KitVersion: o.Config.KitVersion, Payload: json.RawMessage(payload),
		Facts: CollectFacts(o.Connector, call.Event, payload, o.Config.attachCap()),
	}
	body, err := json.Marshal(env)
	if err != nil {
		return refuse("DefenseClaw could not encode the hook event: " + err.Error())
	}
	header := map[string]string{"X-DefenseClaw-Actor-Mode": mode}
	if o.Event != "" {
		header["X-DefenseClaw-Hook-Event"] = o.Event
	}
	if call.HookContractID != "" {
		header["X-DefenseClaw-Hook-Contract"] = call.HookContractID
	}
	send := o.Send
	if send == nil {
		send = defaultSend(o.Config)
	}
	resp, helperMode, err := send(ctx, Request{Path: HookPathPrefix + o.Connector, Header: header, Body: body})
	call.FailMode = outageMode(call.FailMode, resp, helperMode, mode)
	if err != nil {
		if errors.Is(err, ErrUnreachable) {
			cause := strings.TrimPrefix(strings.TrimPrefix(err.Error(), ErrUnreachable.Error()), ": ")
			reason := "the DefenseClaw gateway in the cluster did not answer"
			if cause != "" {
				reason += " (" + cause + ")"
			}
			code, rerr := hookexec.RemoteUnreachable(call, reason)
			if rerr != nil {
				fmt.Fprintln(o.Stderr, "defenseclaw:", rerr)
			}
			return code
		}
		return refuse("DefenseClaw actor hook failed: " + err.Error())
	}
	code, rerr := hookexec.RemoteAnswer(call, resp.Status, resp.Body)
	if rerr != nil {
		fmt.Fprintln(o.Stderr, "defenseclaw:", rerr)
	}
	return code
}

// outageMode is the fail mode of a call: the gateway's word for this actor
// when it has given one (the registration decides, D8), else the
// configuration's; an unattended run is closed whoever says otherwise.
func outageMode(configured string, resp Response, helperMode, envMode string) string {
	if helperMode == ModeUnattend || resp.Mode == ModeUnattend || envMode == ModeUnattend {
		return "closed"
	}
	switch resp.FailMode {
	case "open", "closed":
		return resp.FailMode
	}
	return configured
}

// runNotify forwards a Codex notify event. It is best-effort and never
// blocks or prints, like the host notify bridge.
func runNotify(ctx context.Context, o HookOptions, mode string) int {
	if o.NotifyJSON == "" || !json.Valid([]byte(o.NotifyJSON)) || len(o.NotifyJSON) > int(maxPayloadBytes) {
		return 0
	}
	send := o.Send
	if send == nil {
		send = defaultSend(o.Config)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, err := json.Marshal(HookEnvelope{V: EnvelopeVersion, Connector: o.Connector, Event: "agent-turn-complete",
		Mode: mode, KitVersion: o.Config.KitVersion, Payload: json.RawMessage(o.NotifyJSON)})
	if err != nil {
		return 0
	}
	_, _, _ = send(ctx, Request{
		Path:   NotifyPathPrefix + o.Connector,
		Header: map[string]string{"X-DefenseClaw-Actor-Mode": mode, "x-defenseclaw-source": o.Connector + "-notify"},
		Body:   body,
	})
	return 0
}

// defaultSend posts through the resident helper, starting one for the next
// call when none answers, and posts directly meanwhile.
func defaultSend(cfg Config) func(ctx context.Context, r Request) (Response, string, error) {
	return func(ctx context.Context, r Request) (Response, string, error) {
		budget := cfg.maxTime() + cfg.retryMaxTime() + time.Second
		resp, err := callHelper(ctx, helperRequest{Op: "post", Request: r}, budget)
		if err == nil {
			if resp.Response.FailMode == "" {
				resp.Response.FailMode = resp.FailMode
			}
			if resp.Unreachable {
				return resp.Response, resp.Mode, fmt.Errorf("%w: %s", ErrUnreachable, resp.Error)
			}
			if resp.Error != "" {
				return resp.Response, resp.Mode, errors.New(resp.Error)
			}
			return resp.Response, resp.Mode, nil
		}
		_ = StartHelper()
		t, terr := NewTransport(cfg)
		if terr != nil {
			return Response{}, "", terr
		}
		out, perr := t.Post(ctx, r)
		return out, "", perr
	}
}

// Main is the defenseclaw-actor-hook entrypoint.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "hook-post" {
		cfg, err := LoadConfig(ConfigPath)
		if err != nil {
			fmt.Fprintln(stderr, "defenseclaw-actor-hook:", err)
			return 1
		}
		return RunHookPost(context.Background(), cfg, stdin, stdout, stderr, nil)
	}
	fs := flag.NewFlagSet("defenseclaw-actor-hook", flag.ContinueOnError)
	fs.SetOutput(stderr)
	connectorName := fs.String("connector", "", "connector name (claudecode, codex)")
	event := fs.String("event", "", "hook event, when the agent binds it on the command line")
	contract := fs.String("hook-contract", "", "hook contract id")
	notify := fs.Bool("notify", false, "forward a Codex notify event (the JSON is the last argument)")
	serve := fs.Bool("serve", false, "run the resident transport helper")
	warm := fs.Bool("warm", false, "start the helper if needed and connect it to the gateway")
	unattended := fs.Bool("unattended", false, "with --warm: mark this actor's run unattended (fail closed)")
	configPath := fs.String("config", ConfigPath, "kit configuration")
	version := fs.Bool("version", false, "print the kit version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Fprintf(stdout, "defenseclaw-actor-hook %s\n", Version)
		return 0
	}
	if *configPath != ConfigPath && os.Getenv("DEFENSECLAW_ACTOR_KIT_TEST") != "1" {
		// The agent can run this binary itself: only the root-owned
		// configuration counts, a test build aside.
		*configPath = ConfigPath
	}
	cfg, cfgErr := LoadConfig(*configPath)
	ctx := context.Background()
	switch {
	case *serve:
		if cfgErr != nil {
			fmt.Fprintln(stderr, "defenseclaw-actor-hook:", cfgErr)
			return 1
		}
		h, err := NewHelper(cfg, nil)
		if err != nil {
			fmt.Fprintln(stderr, "defenseclaw-actor-hook:", err)
			return 1
		}
		if err := h.Serve(ctx); err != nil && !errors.Is(err, errHelperRunning) {
			fmt.Fprintln(stderr, "defenseclaw-actor-hook:", err)
			return 1
		}
		return 0
	case *warm:
		if cfgErr != nil {
			fmt.Fprintln(stderr, "defenseclaw-actor-hook:", cfgErr)
			return 1
		}
		budget := cfg.maxTime()
		if *unattended {
			if err := SetUnattended(ctx, budget); err != nil {
				fmt.Fprintln(stderr, "defenseclaw-actor-hook:", err)
				return 1
			}
		}
		if *connectorName == "" {
			return 0
		}
		if err := Warm(ctx, *connectorName, budget); err != nil {
			fmt.Fprintln(stderr, "defenseclaw-actor-hook: warm:", err)
			return 1
		}
		return 0
	}
	name := strings.TrimSpace(*connectorName)
	if name == "" {
		// The command name can carry the connector (a symlink per agent).
		name = strings.TrimPrefix(filepath.Base(os.Args[0]), "defenseclaw-actor-hook-")
	}
	o := HookOptions{
		Connector: name, Event: *event, HookContract: *contract, Notify: *notify,
		Config: cfg, ConfigErr: cfgErr, Stdin: stdin, Stdout: stdout, Stderr: stderr,
	}
	if *notify && fs.NArg() > 0 {
		o.NotifyJSON = fs.Arg(fs.NArg() - 1)
	}
	return RunHook(ctx, o)
}

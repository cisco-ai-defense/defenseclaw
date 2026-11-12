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
	// Home is the agent's HOME for the skill roots and the kit's state
	// (default $HOME).
	Home string
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
	var skillsSent map[string]string
	if skillScanEvents[call.Event] {
		skillsSent = o.attachSkills(&env, payload)
	}
	body, err := json.Marshal(env)
	if err != nil {
		return refuse("DefenseClaw could not encode the hook event: " + err.Error())
	}
	header := map[string]string{"X-DefenseClaw-Actor-Mode": mode}
	if o.Event != "" {
		header["X-DefenseClaw-Hook-Event"] = o.Event
		// Copilot and Antigravity bodies carry no event name: the gateway
		// reads the registration's event from a private header, as it does
		// for the host hooks' shell bridges.
		if h := eventRegistrationHeader[o.Connector]; h != "" {
			header[h] = o.Event
		}
	}
	if call.HookContractID != "" {
		header["X-DefenseClaw-Hook-Contract"] = call.HookContractID
	}
	send := o.Send
	if send == nil {
		send = defaultSend(o.Config)
	}
	resp, _, err := send(ctx, Request{Path: HookPathPrefix + o.Connector, Header: header, Body: body})
	if err == nil && resp.Status >= 200 && resp.Status < 300 && skillsSent != nil {
		o.rememberSkills(skillsSent)
		if moved := quarantineSkills(resp.Body, skillsSent, time.Now()); len(moved) > 0 {
			fmt.Fprintf(o.Stderr, "defenseclaw: blocked skill folders moved out of the skill root: %s\n", strings.Join(moved, ", "))
		}
	}
	call.FailMode = outageMode(call.FailMode, resp, mode)
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

// attachSkills lists every skill folder's fingerprint in env's facts and
// attaches the files of the folders not in the kit's seen-cache. It returns
// the fingerprints it sent. The cache only saves bytes: the gateway decides
// on the fingerprints, and a folder it has not scanned whose files are not
// attached is not scanned, so it is quarantined (a cache the agent edited
// hides nothing).
func (o HookOptions) attachSkills(env *HookEnvelope, payload []byte) map[string]string {
	var v struct {
		CWD string `json:"cwd"`
	}
	_ = json.Unmarshal(payload, &v)
	f := env.Facts
	if f == nil {
		f = &Facts{}
	}
	var used int64
	for _, a := range f.Files {
		used += int64(len(a.Content))
	}
	sent, _ := collectSkills(f, skillRoots(o.home(), filepath.Clean(v.CWD)), loadSkillCache(o.home()), o.Config.attachCap()-used)
	if len(f.Paths) > 0 || len(f.Files) > 0 || len(f.Skills) > 0 || f.Truncated {
		env.Facts = f
	}
	return sent
}

func (o HookOptions) home() string {
	if o.Home != "" {
		return o.Home
	}
	h, _ := os.UserHomeDir()
	return h
}

// rememberSkills adds the fingerprints the gateway answered for to the cache.
func (o HookOptions) rememberSkills(sent map[string]string) { saveSkillCache(o.home(), sent) }

// outageMode is the fail mode of a call: the gateway's word for this actor
// when it answered (the registration decides, D8), else the configuration's;
// an unattended run is closed whoever says otherwise.
func outageMode(configured string, resp Response, envMode string) string {
	if resp.Mode == ModeUnattend || envMode == ModeUnattend {
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

// defaultSend posts on a connection of this call's own (GAP-0047).
func defaultSend(cfg Config) func(ctx context.Context, r Request) (Response, string, error) {
	return func(ctx context.Context, r Request) (Response, string, error) {
		t, err := NewTransport(cfg)
		if err != nil {
			return Response{}, "", err
		}
		out, err := t.Post(ctx, r)
		return out, "", err
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
	version := fs.Bool("version", false, "print the kit version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *version {
		fmt.Fprintf(stdout, "defenseclaw-actor-hook %s\n", Version)
		return 0
	}
	// Only the root-owned configuration counts: the agent can run this
	// binary itself.
	cfg, cfgErr := LoadConfig(ConfigPath)
	ctx := context.Background()
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

// eventRegistrationHeader names, per connector, the header the gateway reads
// the command-line event from (agent_hook.go): the host shell hooks send the
// same one.
var eventRegistrationHeader = map[string]string{
	"copilot":     "X-DefenseClaw-Copilot-Event",
	"antigravity": "X-DefenseClaw-Antigravity-Event",
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Command defenseclaw-sensor-helper holds the privilege the gateway does
// not, and answers a fixed set of questions about what the kernel sees.
//
// It exists because the two halves of AI runtime detection want opposite
// things. Reading the process table, the connection table and kernel events
// needs privilege. The component that reasons about them is network-facing
// and, in a managed deployment, is deliberately de-privileged for exactly
// that reason -- an unprivileged account inside a systemd sandbox on Linux,
// a virtual service account on Windows.
//
// So the privilege lives here, in a process that does nothing else: no
// network listener, no policy, no scoring, no writes to anything a user
// owns. It answers three questions -- the process table, the connection
// table, the kernel event stream -- and takes no instruction about any of
// them. What it watches comes from its own root-owned configuration.
//
// The security argument is the smallness. Anything added here that lets the
// caller say *what* to read turns a root process into a confused deputy for
// whoever holds the socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/ipc"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tetragon"
)

// Set by the release build's -ldflags -X, so a service log and --version name
// the exact helper build.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "defenseclaw-sensor-helper:", err)
		os.Exit(exitCode(err))
	}
}

// exitError carries a one-shot's own exit status. --tetragon-cleanup exits 3
// when Tetragon did not answer, which the lifecycle reports differently from
// a cleanup that failed (1).
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// exitCode is the exit status for err: an exitError's own, otherwise 1.
func exitCode(err error) int {
	var coded *exitError
	if errors.As(err, &coded) && coded.code > 0 {
		return coded.code
	}
	return 1
}

func run() error {
	var (
		socketPath = flag.String("socket", "",
			"path to listen on (default: the deployment's standard location)")
		homeDirs = flag.String("home-dirs", "",
			"comma-separated user homes whose credential paths Plane C watches")
		allowUIDs = flag.String("allow-uid", "",
			"comma-separated peer uids permitted to connect (default: this process's own)")
		socketGID = flag.Int("socket-gid", -1,
			"group to own the socket, so the gateway's account can reach it")
		dataDir = flag.String("data-dir", "",
			"data directory, used to place the socket outside managed deployments")
		managedEnterprise = flag.Bool("managed-enterprise", false,
			"use the managed deployment's socket location")
		serviceAccount = flag.String("service-account", "",
			"gateway account: permit its uid and give the socket its group (unless --allow-uid/--socket-gid are set)")
		homesFromManifest = flag.String("home-dirs-from-manifest", "",
			"protected guardian manifest whose enabled users' homes Plane C watches; restarts when it changes")
		showVersion     = flag.Bool("version", false, "print the helper's version and commit, then exit")
		tetragonCleanup = flag.Bool("tetragon-cleanup", false,
			"remove the Tetragon policies this helper recorded loading, then exit (uninstall, purge, rollback, downgrade)")
		cleanupCheck = flag.Bool("check", false,
			"with --tetragon-cleanup: only report that this helper supports it (exit 0) and change nothing")
	)
	flag.Parse()
	if *showVersion {
		_, err := fmt.Fprintln(os.Stdout, versionString())
		return err
	}
	if *cleanupCheck && !*tetragonCleanup {
		return errors.New("--check needs --tetragon-cleanup")
	}
	if *tetragonCleanup {
		// A one-shot for the lifecycle and the package scripts: no socket,
		// no service log, output on stdout.
		return runTetragonCleanup(*cleanupCheck, os.Stdout,
			slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	}

	// The log destination comes from the protected service environment, not
	// the command line, so the ImagePath of an installed helper never changes
	// shape and a rollback to an older helper binary still starts.
	logger, closeLog := newHelperLogger(serviceLogPath(), os.Stderr)
	defer closeLog()
	logger.Info("sensor helper starting", "version", version, "commit", commit)

	err := runHelper(logger, *socketPath, *homeDirs, *allowUIDs, *socketGID, *dataDir, *managedEnterprise,
		*serviceAccount, *homesFromManifest)
	if err != nil {
		// Under the Service Control Manager this line is the only record of
		// why the helper, and therefore the gateway that depends on it,
		// did not come up.
		logger.Error("sensor helper exited", "error", err)
	}
	return err
}

// versionString names the build in the same form as defenseclaw-gateway
// --version, so an administrator can match the privileged helper to the
// package and the gateway it shipped with.
func versionString() string {
	return fmt.Sprintf("defenseclaw-sensor-helper version %s (commit=%s)", version, commit)
}

func runHelper(
	logger *slog.Logger,
	socketPath, homeDirs, allowUIDs string,
	socketGID int,
	dataDir string,
	managedEnterprise bool,
	serviceAccount, homesFromManifest string,
) error {
	path := socketPath
	if path == "" {
		path = acquire.DefaultSocketPath(dataDir, managedEnterprise)
	}

	uids, err := parseUIDs(allowUIDs)
	if err != nil {
		return err
	}
	if serviceAccount != "" {
		uid, gid, err := resolveServiceAccount(serviceAccount)
		if err != nil {
			return err
		}
		if len(uids) == 0 {
			uids = []int{uid}
		}
		if socketGID < 0 {
			socketGID = gid
		}
	}
	homes := splitList(homeDirs)
	manifestDigest := ""
	if homesFromManifest != "" {
		fromManifest, digest, err := manifestHomes(homesFromManifest)
		if err != nil {
			return err
		}
		homes, manifestDigest = append(homes, fromManifest...), digest
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if homesFromManifest != "" {
		ctx = watchManifest(ctx, homesFromManifest, manifestDigest, 30*time.Second, logger)
	}

	// Tetragon (managed Linux only): the lifecycle's drop-in names the
	// intent; the reconciler starts once and resumes from its persisted
	// state when the manifest watcher restarts the helper.
	var tetragonConfig *acquire.TetragonConfig
	if managedEnterprise && runtime.GOOS == "linux" {
		config := tetragonIntent(envvars.Lookup, logger)
		if config.Mode != "off" {
			config.Dial = tetragon.NewDialer(tetragon.DialerConfig{Homes: homes, BinDir: helperBinDir()})
		}
		if kernelPolicy.start != nil {
			targets, _, err := manifestTargets(homesFromManifest)
			if err != nil {
				logger.Warn("guardian manifest unreadable; the kernel-policy reconciler starts with no enrolled users", "error", err)
			}
			hooks := kernelPolicy.start(ctx, kernelPolicyInput{
				Config: config, Lookup: envvars.Lookup, Manifest: homesFromManifest, Targets: targets,
				Homes: homes, Logger: logger,
			})
			config.OwnObservePolicy, config.KernelStatus = hooks.OwnObservePolicy, hooks.Status
			config.Tap, config.Stream = hooks.Tap, hooks.Stream
		}
		logger.Info("sensor helper Tetragon intent", "mode", config.Mode, "burn_in", config.BurnIn.String(),
			"enforce_ack_set", config.EnforceAck != "", "enforce_connectors", config.EnforceConnectors,
			"reconciler", kernelPolicy.start != nil)
		tetragonConfig = &config
	}

	// Under the Windows SCM there is no console and no signal: the service
	// control manager expects the process to report Running within seconds
	// and to stop when told. runUnderServiceManager takes over the
	// lifecycle when that is where we are, and is a passthrough everywhere
	// else. Without it the service registers, fails to answer SCM, and is
	// killed with error 1053 -- a helper that can never start, on the one
	// platform whose gateway most needs it.
	return runUnderServiceManager(ctx, func(ctx context.Context) error {
		return serve(ctx, path, uids, socketGID, homes, tetragonConfig, logger)
	})
}

// newHelperLogger writes to the service log when one is configured and it
// can be opened safely, and to fallback otherwise. A log that cannot be
// opened is a diagnostics gap, not a reason to refuse to start: the gateway
// depends on this service, so failing here would take managed hooks down
// with it.
func newHelperLogger(path string, fallback io.Writer) (*slog.Logger, func()) {
	options := &slog.HandlerOptions{Level: slog.LevelInfo}
	if strings.TrimSpace(path) == "" {
		return slog.New(slog.NewTextHandler(fallback, options)), func() {}
	}
	file, err := openHelperLog(path)
	if err != nil {
		logger := slog.New(slog.NewTextHandler(fallback, options))
		logger.Warn("sensor helper log is unavailable; logging to stderr",
			"log", path, "error", err)
		return logger, func() {}
	}
	return slog.New(slog.NewTextHandler(file, options)), func() { _ = file.Close() }
}

func serve(
	ctx context.Context,
	path string,
	uids []int,
	socketGID int,
	homeDirs []string,
	tetragonConfig *acquire.TetragonConfig,
	logger *slog.Logger,
) error {

	// 0o660 with a group the gateway belongs to: the socket is reachable by
	// exactly one other account and by nobody else. The peer uid is checked
	// again at accept, because a mode is a filter that can be widened by an
	// unrelated packaging change without anyone noticing.
	listener, err := ipc.ListenSecured(ctx, ipc.ListenSpec{
		Path: path,
		// Named, not borrowed. Windows anchors a bind to the trusted
		// managed IPC directory and to a declared filename; this service
		// has its own access boundary, so it must not share the UI IPC
		// socket's identity.
		BaseName:    acquire.SocketFileName,
		SocketMode:  0o660,
		DirMode:     0o750,
		OwnerUID:    os.Getuid(),
		OwnerGID:    socketGID,
		GatewayOnly: true,
	})
	if err != nil {
		return err
	}

	server := acquire.NewServer(acquire.ServerConfig{
		HomeDirs:    homeDirs,
		AllowedUIDs: uids,
		Logger:      logger,
		Tetragon:    tetragonConfig,
	})

	logger.Info("sensor helper listening",
		"socket", path, "uid", os.Getuid(),
		"allowed_uids", uids, "home_dirs", homeDirs)

	if err := server.Serve(ctx, listener); err != nil {
		return err
	}
	logger.Info("sensor helper stopped")
	return nil
}

func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseUIDs(value string) ([]int, error) {
	var out []int
	for _, part := range splitList(value) {
		uid, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("--allow-uid %q: not a uid", part)
		}
		if uid < 0 {
			return nil, fmt.Errorf("--allow-uid %d: negative", uid)
		}
		out = append(out, uid)
	}
	return out, nil
}

// The Tetragon drop-in the enterprise lifecycle renders
// (30-defenseclaw-tetragon.conf) from enterprise.tetragon. Read only here,
// only with --managed-enterprise on Linux, and only through envvars.Lookup.
const (
	envTetragonMode              = "DEFENSECLAW_SENSOR_TETRAGON_MODE"
	envTetragonBurnIn            = "DEFENSECLAW_SENSOR_TETRAGON_BURN_IN"
	envTetragonEnforceAck        = "DEFENSECLAW_SENSOR_TETRAGON_ENFORCE_ACK"
	envTetragonEnforceConnectors = "DEFENSECLAW_SENSOR_TETRAGON_ENFORCE_CONNECTORS"
)

// Burn-in bounds (enterprise.tetragon.burn_in): 0 (skipped, with a warning)
// or 24h to 2160h; 168h when absent.
const (
	defaultBurnIn = 168 * time.Hour
	minBurnIn     = 24 * time.Hour
	maxBurnIn     = 2160 * time.Hour
)

var (
	enforceAckPattern = regexp.MustCompile(`^sha256:[0-9a-f]{12}$`)
	connectorPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// tetragonIntent reads the drop-in. An absent drop-in is the default
// (consume, 168h, no approval). It never fails and never widens: a
// malformed mode is consume (read only), a malformed burn-in the default,
// a malformed approval none, a malformed connector dropped; each is logged.
// The reconciler applies the same rules to the same variables.
func tetragonIntent(lookup func(string) (string, bool), logger *slog.Logger) acquire.TetragonConfig {
	config := acquire.TetragonConfig{Mode: "consume", BurnIn: defaultBurnIn}
	if value, ok := lookup(envTetragonMode); ok {
		switch mode := strings.ToLower(strings.TrimSpace(value)); mode {
		case "off", "consume", "observe", "enforce":
			config.Mode = mode
		default:
			logger.Warn("malformed Tetragon mode in the helper drop-in; using consume", "variable", envTetragonMode)
		}
	}
	if value, ok := lookup(envTetragonBurnIn); ok && strings.TrimSpace(value) != "" {
		duration, err := time.ParseDuration(strings.TrimSpace(value))
		if err != nil || duration < 0 || (duration != 0 && (duration < minBurnIn || duration > maxBurnIn)) {
			logger.Warn("malformed Tetragon burn-in in the helper drop-in; using 168h", "variable", envTetragonBurnIn)
		} else {
			config.BurnIn = duration
		}
	}
	if value, ok := lookup(envTetragonEnforceAck); ok {
		if value = strings.TrimSpace(value); enforceAckPattern.MatchString(value) {
			config.EnforceAck = value
		} else if value != "" {
			logger.Warn("malformed Tetragon enforce_ack in the helper drop-in; no approval", "variable", envTetragonEnforceAck)
		}
	}
	if value, ok := lookup(envTetragonEnforceConnectors); ok {
		seen := map[string]bool{}
		for _, part := range strings.Split(value, ",") {
			connector := strings.ToLower(strings.TrimSpace(part))
			switch {
			case connector == "" || seen[connector]:
			case !connectorPattern.MatchString(connector):
				logger.Warn("malformed connector in the helper drop-in; ignored", "variable", envTetragonEnforceConnectors)
			default:
				seen[connector] = true
				config.EnforceConnectors = append(config.EnforceConnectors, connector)
			}
		}
	}
	return config
}

// helperBinDir is the managed install's binary directory, where the native
// hook and DefenseClaw's own executables live.
func helperBinDir() string {
	layout, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		return "/opt/defenseclaw/bin"
	}
	return layout.BinDir
}

// kernelPolicy connects the helper to its kernel-policy reconciler. The
// reconciler's half of this command (tetragon_linux.go) fills it in an init;
// a build without it has no reconciler and no cleanup, and the Tetragon
// event stream still runs in consume.
var kernelPolicy kernelPolicyHooks

type kernelPolicyHooks struct {
	// start runs the reconciler for the helper's lifetime, once. In off and
	// consume that is the startup retire step of the names it recorded. It
	// returns what the event stream and the broker need from it.
	start func(ctx context.Context, input kernelPolicyInput) kernelPolicyRuntime
	// cleanup is --tetragon-cleanup: retire every recorded name, write what
	// it removed to out, and empty the record. An *exitError sets the
	// command's exit status (3: Tetragon did not answer).
	cleanup func(ctx context.Context, out io.Writer, logger *slog.Logger) error
}

// kernelPolicyInput is everything the reconciler is started with, all of it
// from root-owned inputs.
type kernelPolicyInput struct {
	// Config is the drop-in intent as this command parsed it.
	Config acquire.TetragonConfig
	// Lookup is envvars.Lookup, for the reconciler's own reading of the
	// same drop-in.
	Lookup func(string) (string, bool)
	// Manifest is the guardian manifest path; Targets its enabled rows.
	Manifest string
	Targets  []helperTarget
	// Homes are the watched homes.
	Homes  []string
	Logger *slog.Logger
}

// kernelPolicyRuntime is what the reconciler hands back.
type kernelPolicyRuntime struct {
	// OwnObservePolicy reports DefenseClaw's recorded observe policy (the
	// fanotify hand-off).
	OwnObservePolicy func(name string) bool
	// Status answers the broker's kernel_status op.
	Status func(ctx context.Context) (acquire.KernelStatus, error)
	// Tap and Stream receive the event stream's batches and its up/down.
	Tap    func(plane.KernelBatch)
	Stream func(connected bool)
}

// runTetragonCleanup is --tetragon-cleanup [--check]. Outside Linux there is
// no Tetragon and nothing to remove. --check exits 0 only on a build that
// can clean up, which is how an rpm %preun tells a Tetragon-aware helper
// from an older one.
func runTetragonCleanup(check bool, out io.Writer, logger *slog.Logger) error {
	if runtime.GOOS != "linux" {
		_, err := fmt.Fprintln(out, "tetragon cleanup: not applicable on "+runtime.GOOS)
		return err
	}
	if kernelPolicy.cleanup == nil {
		return errors.New("this helper build has no Tetragon cleanup")
	}
	if check {
		_, err := fmt.Fprintln(out, "tetragon cleanup: supported")
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return kernelPolicy.cleanup(ctx, out, logger)
}

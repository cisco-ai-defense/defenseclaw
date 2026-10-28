// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

var (
	version = "dev"
	commit  = "unknown"
)

const serviceStopTimeout = 30 * time.Second

func main() {
	options, err := parseBrokerOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "defenseclaw-cmid-broker: invalid service configuration")
		os.Exit(64)
	}
	if err := cmidbroker.ValidateIdentityBinding(
		options.serviceName,
		options.gatewayServiceName,
		options.pipeName,
	); err != nil {
		fmt.Fprintln(os.Stderr, "defenseclaw-cmid-broker: service identity mismatch")
		os.Exit(64)
	}
	hosted, err := svc.IsWindowsService()
	if err != nil || !hosted {
		fmt.Fprintln(os.Stderr, "defenseclaw-cmid-broker: SCM service hosting is required")
		os.Exit(1)
	}
	handler := &brokerWindowsService{options: options}
	if err := svc.Run(options.serviceName, handler); err != nil {
		fmt.Fprintln(os.Stderr, "defenseclaw-cmid-broker: SCM service failed")
		os.Exit(1)
	}
}

type brokerWindowsService struct {
	options brokerOptions
}

func (service *brokerWindowsService) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown
	changes <- svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 30_000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- runBroker(ctx, service.options, ready) }()

	checkpoint := uint32(1)
	startupTicker := time.NewTicker(time.Second)
	defer startupTicker.Stop()
	for {
		select {
		case err := <-result:
			if err != nil {
				return true, 1
			}
			return false, 0
		case <-ready:
			changes <- svc.Status{State: svc.Running, Accepts: accepted}
			return service.waitForStop(cancel, requests, changes, result)
		case <-startupTicker.C:
			checkpoint++
			changes <- svc.Status{State: svc.StartPending, CheckPoint: checkpoint, WaitHint: 30_000}
		case request := <-requests:
			if request.Cmd == svc.Stop || request.Cmd == svc.Shutdown || request.Cmd == svc.PreShutdown {
				cancel()
				return false, 0
			}
		}
	}
}

func (service *brokerWindowsService) waitForStop(
	cancel context.CancelFunc,
	requests <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
	result <-chan error,
) (bool, uint32) {
	current := svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown,
	}
	var stopOnce sync.Once
	for {
		select {
		case err := <-result:
			if err != nil {
				return true, 1
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				stopOnce.Do(cancel)
				return false, 0
			}
			switch request.Cmd {
			case svc.Interrogate:
				changes <- current
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				stopOnce.Do(cancel)
				changes <- svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: uint32(serviceStopTimeout / time.Millisecond)}
				timer := time.NewTimer(serviceStopTimeout)
				select {
				case <-result:
					timer.Stop()
					return false, 0
				case <-timer.C:
					return true, 1
				}
			}
		}
	}
}

// runBroker opens the broker log before it loads the auth key, so every
// startup check that follows leaves a trace. Permission drift on the broker's
// own objects is repaired (the key) or accepted (everything else) and logged
// as stage=acl-drift; it never stops the broker. A failure before the log is
// open goes to the Application event log instead.
func runBroker(ctx context.Context, options brokerOptions, ready chan<- struct{}) error {
	drift := newDriftSink()
	// Both hooks are process-global; set them once, before any trust check.
	managed.ReportTrustDrift = drift.trust
	managed.ReportTrustAdvisory = drift.trust

	serverConfig := cmidbroker.ServerConfig{
		PipeName:           options.pipeName,
		BrokerServiceName:  options.serviceName,
		GatewayServiceName: options.gatewayServiceName,
	}
	if err := cmidbroker.ValidateBrokerServiceIdentity(serverConfig); err != nil {
		return reportStartupFailureEvent(options.serviceName, err, drift.pendingSummary())
	}
	if err := validateBrokerPath(options.logPath, "broker log", true); err != nil {
		return reportStartupFailureEvent(options.serviceName, err, drift.pendingSummary())
	}
	logFile, err := openBrokerLog(options.logPath)
	if err != nil {
		return reportStartupFailureEvent(options.serviceName, err, drift.pendingSummary())
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags|log.LUTC)
	logger.Printf("stage=startup version=%s commit=%s protocol=%d", version, commit, cmidbroker.ProtocolVersion)
	defer logger.Print("stage=shutdown")
	drift.attach(logger)

	stage, err := serveBroker(ctx, options, serverConfig, logger, drift, ready)
	if err != nil {
		logger.Printf("stage=%s error=%q", stage, err.Error())
	}
	return err
}

// serveBroker runs everything after the log is open. It returns the stage to
// log a failure under: startup-failed until the pipe server is ready, then
// serve-failed.
func serveBroker(
	ctx context.Context,
	options brokerOptions,
	serverConfig cmidbroker.ServerConfig,
	logger *log.Logger,
	drift *driftSink,
	ready chan<- struct{},
) (string, error) {
	const startupFailed = "startup-failed"
	key, err := cmidbroker.LoadAuthKey(options.authKeyPath, options.gatewayServiceName, cmidbroker.KeyDriftPolicy{
		Repair: true,
		Report: drift.key,
	})
	if err != nil {
		return startupFailed, err
	}
	defer zeroBytes(key[:])

	if !cloudreg.Registered() {
		logger.Print("stage=provider-registration success=false")
		return startupFailed, errors.New("managed CMID provider is not registered")
	}
	// A full XDR deployment installs Cloud Management last, so cmidapi.dll
	// is frequently absent when this service first starts. Resolve the
	// library lazily instead of at startup: the broker serves the pipe
	// either way, answers token requests with a provider error while the
	// library is missing (managed inspection stays fail-closed), and
	// adopts the library on the first request after Cloud Management
	// lands — no reinstall, repair, or service restart.
	provider, err := cmidbroker.NewDeferredProvider(cmidbroker.DeferredProviderConfig{
		PinnedLibraryPath: options.cmidLibraryPath,
		Discover:          managed.DiscoverCMIDLibrary,
		// A discovered library is dlopened into this service's account, so
		// it faces the same path trust an installer-pinned one does.
		// Permission drift on the library is accepted and logged: Cloud
		// Management owns its ACL.
		Validate: func(path string) error {
			return validateBrokerPath(path, "CMID library", false)
		},
		Construct: func(path string) (cmidbroker.Provider, error) {
			built, buildErr := cloudreg.New(cloudreg.Config{LibPath: path})
			if buildErr != nil {
				return nil, buildErr
			}
			if built == nil {
				return nil, errors.New("managed CMID provider construction failed")
			}
			return built, nil
		},
		OnResolved: func(path string) {
			logger.Printf("stage=provider-resolved success=true library=%s", path)
		},
	})
	if err != nil {
		logger.Print("stage=provider-construction success=false")
		return startupFailed, errors.New("managed CMID provider construction failed")
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = provider.Refresh(refreshCtx)
	cancel()
	if err != nil {
		// Not fatal. Failing here would leave SCM restarting a service
		// that cannot succeed until an unrelated installer finishes.
		if errors.Is(err, cmidbroker.ErrLibraryUnavailable) {
			logger.Print("stage=provider-refresh success=false category=cmid_library_pending")
		} else {
			logger.Print("stage=provider-refresh success=false category=cmid_refresh_failed")
		}
	}

	server, err := cmidbroker.NewServer(serverConfig, provider, key[:], func(event cmidbroker.Event) {
		logger.Printf(
			"stage=%s operation=%s success=%t client_pid=%d duration_ms=%d",
			event.Stage,
			event.Operation,
			event.Success,
			event.ClientPID,
			event.Duration.Milliseconds(),
		)
	})
	if err != nil {
		return startupFailed, err
	}
	// Forward readiness to SCM through a channel this function owns, so a
	// serve error can be told apart from a failure before the pipe was ready.
	serverReady := make(chan struct{})
	go func() {
		select {
		case <-serverReady:
			close(ready)
		case <-ctx.Done():
		}
	}()
	if err := server.ServeWithReady(ctx, serverReady); err != nil {
		select {
		case <-serverReady:
			return "serve-failed", err
		default:
			return startupFailed, err
		}
	}
	return "", nil
}

// validateBrokerPath checks the broker's own paths. Path shape and reparse
// points stay fatal; permission verdicts are accepted and reported as drift,
// because the installer and Cloud Management own those ACLs.
func validateBrokerPath(path, label string, parentOnly bool) error {
	if err := validateLocalWindowsPath(path, label); err != nil {
		return err
	}
	if parentOnly {
		return managed.ValidateTrustedRuntimeDirTolerant(filepath.Dir(path), label+" directory")
	}
	return managed.ValidateTrustedFilePathTolerant(path, label)
}

// driftSink collects stage=acl-drift lines. Lines raised before the log is
// open are buffered and flushed, in order, right after the stage=startup line;
// after that they go straight to the log. Each distinct line is written once
// per process.
type driftSink struct {
	mu      sync.Mutex
	out     *log.Logger
	pending []string
	seen    map[string]struct{}
}

func newDriftSink() *driftSink {
	return &driftSink{seen: make(map[string]struct{})}
}

// trust receives managed trust-walk advisories, which are always accepted.
func (sink *driftSink) trust(path, label, reason string) {
	sink.record(fmt.Sprintf("stage=acl-drift action=%s object=%q path=%q reason=%q",
		cmidbroker.KeyDriftAccepted, label, path, reason))
}

// key receives auth key drift reports.
func (sink *driftSink) key(report cmidbroker.KeyDriftReport) {
	line := fmt.Sprintf("stage=acl-drift action=%s object=%q path=%q reason=%q",
		report.Action, report.Object, report.Path, report.Reason)
	if report.RepairError != "" {
		line += fmt.Sprintf(" repair_error=%q", report.RepairError)
	}
	sink.record(line)
}

func (sink *driftSink) record(line string) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if _, ok := sink.seen[line]; ok {
		return
	}
	sink.seen[line] = struct{}{}
	if sink.out == nil {
		sink.pending = append(sink.pending, line)
		return
	}
	sink.out.Print(line)
}

// pendingSummary returns the drift lines still buffered because the log never
// opened, capped so the event-log entry stays readable. They often explain the
// failure, for example drift on the log folder itself.
func (sink *driftSink) pendingSummary() string {
	const limit = 4096
	sink.mu.Lock()
	defer sink.mu.Unlock()
	summary := strings.Join(sink.pending, "\n")
	if len(summary) > limit {
		summary = summary[:limit] + "\n..."
	}
	return summary
}

func (sink *driftSink) attach(out *log.Logger) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, line := range sink.pending {
		out.Print(line)
	}
	sink.pending = nil
	sink.out = out
}

// reportStartupFailureEvent records a failure that happened before the broker
// log could be opened in the Application event log, under the broker's service
// name as the source, with any drift lines buffered so far, and returns err
// unchanged. RegisterEventSource accepts an
// unregistered source name, so no installer change is needed. A failure to
// write the event is ignored: there is nowhere left to report it.
var reportStartupFailureEvent = func(serviceName string, err error, drift string) error {
	message := "CMID broker startup failed: " + err.Error()
	if drift != "" {
		message += "\n" + drift
	}
	if events, openErr := eventlog.Open(serviceName); openErr == nil {
		_ = events.Error(1, message)
		_ = events.Close()
	}
	return err
}

func validateLocalWindowsPath(path, label string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s path must be clean and absolute", label)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(path); err != nil {
		return fmt.Errorf("%s path is not on a trusted local NTFS volume", label)
	}
	return winpath.RejectReparseChain(filepath.Dir(path))
}

func openBrokerLog(path string) (*os.File, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, errors.New("broker log path is invalid")
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_APPEND_DATA|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, errors.New("broker log is unavailable")
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil ||
		information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("broker log has an unsafe file type")
	}
	file := os.NewFile(uintptr(handle), "cmid-broker.log")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("broker log is unavailable")
	}
	return file, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

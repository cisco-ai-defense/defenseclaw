package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// Sidecar is the long-running process that connects to the OpenClaw gateway,
// watches for skill installs, and exposes a local REST API.
type Sidecar struct {
	cfg    *config.Config
	client *Client
	router *EventRouter
	store  *audit.Store
	logger *audit.Logger
	health *SidecarHealth
	shell  *sandbox.OpenShell
}

// NewSidecar creates a sidecar instance ready to connect.
func NewSidecar(cfg *config.Config, store *audit.Store, logger *audit.Logger, shell *sandbox.OpenShell) (*Sidecar, error) {
	fmt.Fprintf(os.Stderr, "[sidecar] initializing client (host=%s port=%d device_key=%s)\n",
		cfg.Gateway.Host, cfg.Gateway.Port, cfg.Gateway.DeviceKeyFile)

	client, err := NewClient(&cfg.Gateway)
	if err != nil {
		return nil, fmt.Errorf("sidecar: create client: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[sidecar] device identity loaded (id=%s)\n", client.device.DeviceID)

	router := NewEventRouter(client, store, logger, cfg.Gateway.AutoApprove)
	client.OnEvent = router.Route

	return &Sidecar{
		cfg:    cfg,
		client: client,
		router: router,
		store:  store,
		logger: logger,
		health: NewSidecarHealth(),
		shell:  shell,
	}, nil
}

// Run starts all subsystems as independent goroutines. Each subsystem runs
// in its own goroutine so that a gateway disconnect does not stop the watcher
// or API server. Run blocks until ctx is cancelled, then shuts everything down.
func (s *Sidecar) Run(ctx context.Context) error {
	fmt.Fprintf(os.Stderr, "[sidecar] starting subsystems (auto_approve=%v watcher=%v api_port=%d)\n",
		s.cfg.Gateway.AutoApprove, s.cfg.Gateway.Watcher.Enabled, s.cfg.Gateway.APIPort)
	_ = s.logger.LogAction("sidecar-start", "", "starting all subsystems")

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	// Goroutine 1: Gateway connection loop (always runs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runGatewayLoop(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] gateway loop exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 2: Skill/MCP watcher (opt-in via config)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runWatcher(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] watcher exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 3: REST API server (always runs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runAPI(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] api server exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Wait for context cancellation (signal handler in CLI layer)
	<-ctx.Done()
	fmt.Fprintf(os.Stderr, "[sidecar] context cancelled, waiting for subsystems to stop ...\n")
	wg.Wait()

	_ = s.logger.LogAction("sidecar-stop", "", "all subsystems stopped")
	_ = s.client.Close()

	// Return the first non-nil error if any subsystem failed before shutdown
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// runGatewayLoop connects to the gateway and reconnects on disconnect,
// running indefinitely until ctx is cancelled.
func (s *Sidecar) runGatewayLoop(ctx context.Context) error {
	for {
		s.health.SetGateway(StateReconnecting, "", nil)
		fmt.Fprintf(os.Stderr, "[sidecar] connecting to %s:%d ...\n", s.cfg.Gateway.Host, s.cfg.Gateway.Port)

		err := s.client.ConnectWithRetry(ctx)
		if err != nil {
			if ctx.Err() != nil {
				s.health.SetGateway(StateStopped, "", nil)
				return nil
			}
			s.health.SetGateway(StateError, err.Error(), nil)
			fmt.Fprintf(os.Stderr, "[sidecar] connect failed: %v (will keep retrying)\n", err)
			continue
		}

		hello := s.client.Hello()
		s.logHello(hello)
		_ = s.logger.LogAction("sidecar-connected", "",
			fmt.Sprintf("protocol=%d", hello.Protocol))
		s.health.SetGateway(StateRunning, "", map[string]interface{}{
			"protocol": hello.Protocol,
		})

		fmt.Fprintf(os.Stderr, "[sidecar] event loop running, waiting for events ...\n")

		select {
		case <-ctx.Done():
			s.health.SetGateway(StateStopped, "", nil)
			return nil
		case <-s.client.Disconnected():
			fmt.Fprintf(os.Stderr, "[sidecar] gateway connection lost, reconnecting ...\n")
			_ = s.logger.LogAction("sidecar-disconnected", "", "connection lost, reconnecting")
			s.health.SetGateway(StateReconnecting, "connection lost", nil)
		}
	}
}

// runWatcher starts the skill/MCP install watcher if enabled in config.
func (s *Sidecar) runWatcher(ctx context.Context) error {
	wcfg := s.cfg.Gateway.Watcher

	if !wcfg.Enabled {
		s.health.SetWatcher(StateDisabled, "", nil)
		fmt.Fprintf(os.Stderr, "[sidecar] watcher disabled (set gateway.watcher.enabled=true to enable)\n")
		<-ctx.Done()
		return nil
	}

	// Resolve skill dirs: explicit config overrides autodiscovery
	var skillDirs []string
	if wcfg.Skill.Enabled {
		if len(wcfg.Skill.Dirs) > 0 {
			skillDirs = wcfg.Skill.Dirs
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: using configured skill dirs: %v\n", skillDirs)
		} else {
			skillDirs = s.cfg.SkillDirs()
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: autodiscovered skill dirs: %v\n", skillDirs)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: skill watching disabled\n")
	}

	// MCP dirs only when a gateway.watcher.mcp section is added in the future.
	// Until then, no MCP watching from the sidecar.
	var mcpDirs []string

	if len(skillDirs) == 0 && len(mcpDirs) == 0 {
		s.health.SetWatcher(StateError, "no directories configured", nil)
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: no directories to watch\n")
		<-ctx.Done()
		return nil
	}

	s.health.SetWatcher(StateStarting, "", map[string]interface{}{
		"skill_dirs":       len(skillDirs),
		"mcp_dirs":         len(mcpDirs),
		"skill_take_action": wcfg.Skill.TakeAction,
	})

	var opa *policy.Engine
	if s.cfg.PolicyDir != "" {
		regoDir := s.cfg.PolicyDir
		if engine, err := policy.New(regoDir); err == nil {
			if compileErr := engine.Compile(); compileErr == nil {
				opa = engine
				fmt.Fprintf(os.Stderr, "[sidecar] OPA policy engine loaded from %s\n", regoDir)
			} else {
				fmt.Fprintf(os.Stderr, "[sidecar] OPA compile error (falling back to built-in): %v\n", compileErr)
			}
		} else {
			fmt.Fprintf(os.Stderr, "[sidecar] OPA init skipped (falling back to built-in): %v\n", err)
		}
	}

	w := watcher.New(s.cfg, skillDirs, mcpDirs, s.store, s.logger, s.shell, opa, func(r watcher.AdmissionResult) {
		s.handleAdmissionResult(r)
	})

	fmt.Fprintf(os.Stderr, "[sidecar] watcher starting (%d skill dirs, %d mcp dirs, skill_take_action=%v)\n",
		len(skillDirs), len(mcpDirs), wcfg.Skill.TakeAction)

	s.health.SetWatcher(StateRunning, "", map[string]interface{}{
		"skill_dirs":       len(skillDirs),
		"mcp_dirs":         len(mcpDirs),
		"skill_take_action": wcfg.Skill.TakeAction,
	})

	err := w.Run(ctx)
	s.health.SetWatcher(StateStopped, "", nil)
	return err
}

// handleAdmissionResult processes watcher verdicts. For blocked/rejected skills,
// it also disables them at the gateway level when take_action is enabled.
func (s *Sidecar) handleAdmissionResult(r watcher.AdmissionResult) {
	fmt.Fprintf(os.Stderr, "[sidecar] watcher verdict: %s %s — %s (%s)\n",
		r.Event.Type, r.Event.Name, r.Verdict, r.Reason)

	if r.Verdict != watcher.VerdictBlocked && r.Verdict != watcher.VerdictRejected {
		return
	}

	if r.Event.Type != watcher.InstallSkill {
		return
	}

	if !s.cfg.Gateway.Watcher.Skill.TakeAction {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: skill %s verdict=%s (take_action=false, logging only)\n",
			r.Event.Name, r.Verdict)
		_ = s.logger.LogAction("sidecar-watcher-verdict", r.Event.Name,
			fmt.Sprintf("verdict=%s (take_action disabled, no gateway action)", r.Verdict))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*1e9)
	defer cancel()

	if err := s.client.DisableSkill(ctx, r.Event.Name); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway disable %s failed: %v\n",
			r.Event.Name, err)
	} else {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway disabled skill %s\n", r.Event.Name)
		_ = s.logger.LogAction("sidecar-watcher-disable", r.Event.Name,
			fmt.Sprintf("auto-disabled via gateway after verdict=%s", r.Verdict))
	}
}

// runAPI starts the REST API server.
func (s *Sidecar) runAPI(ctx context.Context) error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.cfg.Gateway.APIPort)
	api := NewAPIServer(addr, s.health, s.client, s.store, s.logger)
	return api.Run(ctx)
}

func (s *Sidecar) logHello(h *HelloOK) {
	fmt.Fprintf(os.Stderr, "[sidecar] connected to gateway (protocol v%d)\n", h.Protocol)
	if h.Features != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] methods: %s\n", strings.Join(h.Features.Methods, ", "))
		fmt.Fprintf(os.Stderr, "[sidecar] events:  %s\n", strings.Join(h.Features.Events, ", "))
	}
}

// Client returns the underlying gateway client for direct RPC calls.
func (s *Sidecar) Client() *Client {
	return s.client
}

// Health returns the shared health tracker.
func (s *Sidecar) Health() *SidecarHealth {
	return s.health
}

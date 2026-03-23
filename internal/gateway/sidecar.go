package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Sidecar is the long-running process that connects to the OpenClaw gateway,
// subscribes to events, and enforces security policy in real time.
type Sidecar struct {
	cfg    *config.Config
	client *Client
	router *EventRouter
	store  *audit.Store
	logger *audit.Logger
}

// NewSidecar creates a sidecar instance ready to connect.
func NewSidecar(cfg *config.Config, store *audit.Store, logger *audit.Logger) (*Sidecar, error) {
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
	}, nil
}

// Run connects to the gateway and runs the event loop until ctx is cancelled.
// On disconnect, it reconnects with exponential backoff.
func (s *Sidecar) Run(ctx context.Context) error {
	fmt.Fprintf(os.Stderr, "[sidecar] starting event loop (auto_approve=%v)\n", s.cfg.Gateway.AutoApprove)
	_ = s.logger.LogAction("sidecar-start", "", "connecting to gateway")

	for {
		fmt.Fprintf(os.Stderr, "[sidecar] connecting to %s:%d ...\n", s.cfg.Gateway.Host, s.cfg.Gateway.Port)
		err := s.client.ConnectWithRetry(ctx)
		if err != nil {
			if ctx.Err() != nil {
				fmt.Fprintf(os.Stderr, "[sidecar] context cancelled during connect\n")
				return ctx.Err()
			}
			fmt.Fprintf(os.Stderr, "[sidecar] connect failed permanently: %v\n", err)
			return fmt.Errorf("sidecar: connect: %w", err)
		}

		hello := s.client.Hello()
		s.logHello(hello)
		_ = s.logger.LogAction("sidecar-connected", "",
			fmt.Sprintf("protocol=%d", hello.Protocol))

		fmt.Fprintf(os.Stderr, "[sidecar] event loop running, waiting for events ...\n")
		<-ctx.Done()
		fmt.Fprintf(os.Stderr, "[sidecar] context cancelled, shutting down\n")
		_ = s.logger.LogAction("sidecar-stop", "", "context cancelled")
		return s.client.Close()
	}
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

package shield

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/shield/audit"
	shieldca "github.com/defenseclaw/defenseclaw/internal/shield/ca"
	"github.com/defenseclaw/defenseclaw/internal/shield/inspect"
	"github.com/defenseclaw/defenseclaw/internal/shield/policy"
	"github.com/defenseclaw/defenseclaw/internal/shield/providers"
	"github.com/defenseclaw/defenseclaw/internal/shield/proxy"
)

type Daemon struct {
	proxy   *proxy.TransparentProxy
	ipc     *proxy.IPCServer
	logger  *audit.Logger
	ca      *shieldca.Authority
	dataDir string
}

func DataDir() string {
	dir := os.Getenv("DEFENSECLAW_SHIELD_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".defenseclaw-shield")
	}
	return dir
}

const DefaultProxyAddr = "127.0.0.1:9443"

func NewDaemon(proxyAddr string) (*Daemon, error) {
	dataDir := DataDir()
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	authority, err := shieldca.LoadOrCreate(dataDir)
	if err != nil {
		return nil, fmt.Errorf("CA: %w", err)
	}

	logPath := filepath.Join(dataDir, "audit.jsonl")
	logger, err := audit.NewLogger(logPath)
	if err != nil {
		return nil, err
	}

	registry := providers.NewRegistry()
	inspector := inspect.NewInspector()
	engine := policy.NewEngine(policy.DefaultConfig())

	if proxyAddr == "" {
		proxyAddr = DefaultProxyAddr
	}

	tp := proxy.NewTransparentProxy(proxyAddr, authority, registry, inspector, engine, logger)
	ipc := proxy.NewIPCServer(registry, inspector, engine, logger)

	return &Daemon{
		proxy:   tp,
		ipc:     ipc,
		logger:  logger,
		ca:      authority,
		dataDir: dataDir,
	}, nil
}

func (d *Daemon) Start() error {
	if err := d.proxy.Start(); err != nil {
		return err
	}
	if err := d.ipc.Start(); err != nil {
		return fmt.Errorf("IPC server: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[shield] DefenseClaw Shield started\n")
	fmt.Fprintf(os.Stderr, "[shield] Proxy:     %s\n", d.proxy.Addr())
	fmt.Fprintf(os.Stderr, "[shield] CA cert:   %s/ca.crt\n", d.dataDir)
	fmt.Fprintf(os.Stderr, "[shield] Audit log: %s/audit.jsonl\n", d.dataDir)
	fmt.Fprintf(os.Stderr, "[shield] Policy:    block on HIGH+ severity\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "[shield] IPC:       %s\n", d.ipc.SocketAddr())
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "[shield] To protect any agent (no TLS termination):\n")
	fmt.Fprintf(os.Stderr, "  python3 internal/shield/interpose/frida/shield_inject.py -- claude \"your prompt\"\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "[shield] Intercepting LLM traffic. Non-LLM traffic ignored.\n")

	return nil
}

func (d *Daemon) CACertPEM() []byte {
	return d.ca.CertPEM()
}

func (d *Daemon) Wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintf(os.Stderr, "\n[shield] shutting down...\n")
}

func (d *Daemon) Stop() {
	d.ipc.Stop()
	d.proxy.Stop()
	d.logger.Close()
}

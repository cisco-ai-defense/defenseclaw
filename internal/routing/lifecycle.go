// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultAPIPort is the loopback classifier API port. Keep it distinct
	// from 8888, which the bundled local observability stack already owns.
	DefaultAPIPort      = 8080
	TestedVersion       = "0.3.0"
	srRouterImagePrefix = "ghcr.io/vllm-project/semantic-router/vllm-sr:v"
	// Multi-platform OCI index digest for v0.3.0 (linux/amd64 + linux/arm64).
	// Keep the tag for operator readability and the digest for immutability.
	testedImageDigest    = "sha256:667c4d45e03fcee84d33792e6901fa3ac0e6a1f53e6a2674ecb1174e1decea64"
	srContainerNameLabel = "com.defenseclaw.component=semantic-router"
)

var semanticRouterVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

// Lifecycle manages the semantic router container.
// We start ONLY the router container (not Envoy/dashboard/observability)
// since DefenseClaw only needs the /api/v1/classify/intent endpoint.
type Lifecycle struct {
	configPath    string
	port          int
	dataDir       string
	containerName string
	version       string
}

type LifecycleConfig struct {
	ConfigPath string
	Port       int
	DataDir    string
	Version    string
}

func NewLifecycle(cfg LifecycleConfig) *Lifecycle {
	port := cfg.Port
	if port == 0 {
		port = DefaultAPIPort
	}
	version := strings.TrimSpace(cfg.Version)
	if version == "" {
		version = TestedVersion
	}
	version = strings.TrimPrefix(version, "v")

	// Generate an instance-specific container name without exposing the data
	// directory in Docker metadata.
	containerName := fmt.Sprintf("defenseclaw-sr-%d", port)
	if cfg.DataDir != "" {
		sum := sha256.Sum256([]byte(filepath.Clean(cfg.DataDir)))
		containerName = fmt.Sprintf("defenseclaw-sr-%x", sum[:8])
	}
	return &Lifecycle{
		configPath:    cfg.ConfigPath,
		port:          port,
		dataDir:       cfg.DataDir,
		containerName: containerName,
		version:       version,
	}
}

func (l *Lifecycle) image() (string, error) {
	if !semanticRouterVersionPattern.MatchString(l.version) {
		return "", fmt.Errorf("routing: invalid semantic-router version %q", l.version)
	}
	if l.version != TestedVersion {
		return "", fmt.Errorf("routing: semantic-router version %q is not supported by this DefenseClaw release (supported: %s)", l.version, TestedVersion)
	}
	return srRouterImagePrefix + l.version + "@" + testedImageDigest, nil
}

func (l *Lifecycle) dockerRunArgs() ([]string, error) {
	image, err := l.image()
	if err != nil {
		return nil, err
	}
	configDir := filepath.Dir(l.configPath)
	configFile := filepath.Base(l.configPath)
	return []string{
		"run", "-d", "--pull=missing",
		"--name", l.containerName,
		"--label", srContainerNameLabel,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"-v", fmt.Sprintf("%s:/app/config:ro", configDir),
		// The stock v0.3.0 entrypoint binds the classification API to
		// container port 8080. Port is the operator-selected host port.
		"-p", fmt.Sprintf("127.0.0.1:%d:%d", l.port, DefaultAPIPort),
		image,
		fmt.Sprintf("/app/config/%s", configFile),
	}, nil
}

// Start launches only the router container via Docker.
// This gives us the /api/v1/classify/intent API without Envoy or extras.
func (l *Lifecycle) Start(ctx context.Context) error {
	args, err := l.dockerRunArgs()
	if err != nil {
		return err
	}
	// Stop any existing container with this instance name.
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", l.containerName).Run()

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("routing: docker run router failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[routing] router container started (port=%d, container=%s)\n", l.port, l.containerName)
	return nil
}

// WaitForHealth polls the SR API endpoint until it responds or timeout.
func (l *Lifecycle) WaitForHealth(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/health", l.port)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				fmt.Fprintf(os.Stderr, "[routing] router healthy (port=%d)\n", l.port)
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("routing: router health check timed out after %v", timeout)
}

// Stop removes the router container belonging to this lifecycle instance.
func (l *Lifecycle) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", l.containerName).Run()
	fmt.Fprintf(os.Stderr, "[routing] router container %s stopped\n", l.containerName)
	return nil
}

// IsRunning checks if the router container is healthy.
func (l *Lifecycle) IsRunning() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", l.port))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Port returns the configured API port.
func (l *Lifecycle) Port() int {
	return l.port
}

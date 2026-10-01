package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shield"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "start":
		cmdStart()
	case "run":
		cmdRun()
	case "status":
		cmdStatus()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func cmdStart() {
	addr := shield.DefaultProxyAddr
	for i, a := range os.Args[2:] {
		if a == "--addr" && i+1 < len(os.Args[2:]) {
			addr = os.Args[i+3]
		}
	}

	daemon, err := shield.NewDaemon(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[shield] error: %v\n", err)
		os.Exit(1)
	}

	if err := daemon.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[shield] start error: %v\n", err)
		os.Exit(1)
	}

	daemon.Wait()
	daemon.Stop()
}

func cmdRun() {
	// Find "--" separator or treat everything after "run" as the command.
	var args []string
	for i, a := range os.Args[2:] {
		if a == "--" {
			args = os.Args[i+3:]
			break
		}
	}
	if len(args) == 0 {
		args = os.Args[2:]
	}
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: defenseclaw-shield run -- <command> [args...]\n")
		os.Exit(1)
	}

	dataDir := shield.DataDir()
	caPath := dataDir + "/ca.crt"
	proxyAddr := shield.DefaultProxyAddr

	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[shield] CA cert not found. Start the daemon first: defenseclaw-shield start\n")
		os.Exit(1)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	env := os.Environ()
	env = append(env,
		"https_proxy=http://"+proxyAddr,
		"HTTPS_PROXY=http://"+proxyAddr,
		"NODE_EXTRA_CA_CERTS="+caPath,
		"SSL_CERT_FILE="+caPath,
		"REQUESTS_CA_BUNDLE="+caPath,
		"NODE_TLS_REJECT_UNAUTHORIZED=0",
	)
	cmd.Env = env

	fmt.Fprintf(os.Stderr, "[shield] Running: %s\n", strings.Join(args, " "))
	fmt.Fprintf(os.Stderr, "[shield] Proxy:   http://%s\n", proxyAddr)
	fmt.Fprintf(os.Stderr, "[shield] CA cert: %s\n", caPath)
	fmt.Fprintf(os.Stderr, "\n")

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "[shield] error: %v\n", err)
		os.Exit(1)
	}
}

func cmdStatus() {
	dataDir := shield.DataDir()
	caPath := dataDir + "/ca.crt"

	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		fmt.Println("Shield: NOT INITIALIZED (no CA cert)")
		return
	}
	fmt.Println("Shield: READY")
	fmt.Printf("  CA cert:   %s\n", caPath)
	fmt.Printf("  Proxy:     %s\n", shield.DefaultProxyAddr)
	fmt.Printf("  Audit log: %s/audit.jsonl\n", dataDir)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `defenseclaw-shield — network-level agent security

Commands:
  start                  Start the shield proxy (intercepts LLM traffic)
  run -- <cmd> [args]    Launch a process with shield protection via https_proxy
  status                 Check shield status

Examples:
  # Terminal 1: start shield
  defenseclaw-shield start

  # Terminal 2: run Claude Code through shield
  defenseclaw-shield run -- claude "fix the bug in main.go"

  # Or set env vars manually for any process
  export https_proxy=http://127.0.0.1:9443
  export NODE_EXTRA_CA_CERTS=~/.defenseclaw-shield/ca.crt
  claude "fix the bug"

How it works:
  Shield runs as an HTTPS proxy on 127.0.0.1:9443. When a process connects:

  LLM domain (api.anthropic.com, api.openai.com, etc.):
    → TLS intercepted → plaintext inspected → ALLOW or BLOCK

  Non-LLM domain (github.com, npm, etc.):
    → Tunneled directly (zero interception, zero overhead)
`)
}

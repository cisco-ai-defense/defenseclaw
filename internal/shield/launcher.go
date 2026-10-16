package shield

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/shield/proxy"
)

func RunWithShield(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: defenseclaw-shield run -- <command> [args...]")
	}

	socketPath := proxy.SocketPath()

	// Check daemon is running.
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return fmt.Errorf("shield daemon not running (no socket at %s). Run 'defenseclaw-shield start' first", socketPath)
	}

	dataDir := DataDir()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "SHIELD_SOCKET="+socketPath)

	switch runtime.GOOS {
	case "darwin":
		dylibPath := filepath.Join(dataDir, "libshield_interpose.dylib")
		if _, err := os.Stat(dylibPath); err != nil {
			return fmt.Errorf("interposition library not found at %s — run 'make shield-interpose-darwin' first", dylibPath)
		}
		cmd.Env = append(cmd.Env,
			"DYLD_INSERT_LIBRARIES="+dylibPath,
			"SHIELD_CALLER_EXE="+args[0],
		)

	case "windows":
		dllPath := filepath.Join(dataDir, "shield_hook.dll")
		if _, err := os.Stat(dllPath); err != nil {
			return fmt.Errorf("hook DLL not found at %s — run 'make shield-interpose-windows' first", dllPath)
		}
		// On Windows, use withdll.exe from Detours or inject via the launcher.
		// For POC, set env var and let the DLL self-load via AppInit_DLLs or
		// use a wrapper (withdll ships with Detours samples).
		cmd.Env = append(cmd.Env,
			"SHIELD_HOOK_DLL="+dllPath,
			"SHIELD_CALLER_EXE="+args[0],
		)

	case "linux":
		soPath := filepath.Join(dataDir, "libshield_interpose.so")
		if _, err := os.Stat(soPath); err != nil {
			return fmt.Errorf("interposition library not found at %s — run 'make shield-interpose-linux' first", soPath)
		}
		cmd.Env = append(cmd.Env,
			"LD_PRELOAD="+soPath,
			"SHIELD_CALLER_EXE="+args[0],
		)

	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	fmt.Fprintf(os.Stderr, "[shield] launching: %s\n", args[0])
	fmt.Fprintf(os.Stderr, "[shield] protection: active (OS-level SSL interception)\n")
	fmt.Fprintf(os.Stderr, "[shield] audit log: %s/audit.jsonl\n", dataDir)
	fmt.Fprintf(os.Stderr, "\n")

	return cmd.Run()
}

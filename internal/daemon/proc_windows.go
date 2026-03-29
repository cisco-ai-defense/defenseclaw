//go:build windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
)

func setSysProcAttr(_ *exec.Cmd) {}

func sendTermSignal(proc *os.Process) error {
	return proc.Kill()
}

func sendKillSignal(proc *os.Process) error {
	return proc.Kill()
}

func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Windows, FindProcess always succeeds. Use Signal(nil) as a
	// best-effort liveness check — it may not behave identically to Unix
	// but is sufficient for daemon bookkeeping.
	return proc.Signal(nil) == nil
}

func (d *Daemon) killStaleProcesses() {
	trackedPID := 0
	if info, err := d.readPIDInfo(); err == nil {
		trackedPID = info.PID
	}

	if trackedPID > 0 && processExists(trackedPID) {
		proc, err := os.FindProcess(trackedPID)
		if err == nil {
			fmt.Fprintf(os.Stderr, "[daemon] killing stale gateway process (PID %d)\n", trackedPID)
			_ = proc.Kill()
		}
	}
}

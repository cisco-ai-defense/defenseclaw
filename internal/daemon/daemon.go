package daemon

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	PIDFileName = "gateway.pid"
	LogFileName = "gateway.log"
	EnvDaemon   = "DEFENSECLAW_DAEMON"
)

var (
	ErrAlreadyRunning = errors.New("daemon is already running")
	ErrNotRunning     = errors.New("daemon is not running")
	ErrStopTimeout    = errors.New("daemon did not stop within timeout")
)

type Daemon struct {
	dataDir string
	pidFile string
	logFile string
}

func New(dataDir string) *Daemon {
	return &Daemon{
		dataDir: dataDir,
		pidFile: filepath.Join(dataDir, PIDFileName),
		logFile: filepath.Join(dataDir, LogFileName),
	}
}

func (d *Daemon) PIDFile() string { return d.pidFile }
func (d *Daemon) LogFile() string { return d.logFile }

func (d *Daemon) IsRunning() (bool, int) {
	pid, err := d.readPID()
	if err != nil {
		return false, 0
	}
	if !processExists(pid) {
		_ = os.Remove(d.pidFile)
		return false, 0
	}
	return true, pid
}

func (d *Daemon) Start(args []string) (int, error) {
	if running, pid := d.IsRunning(); running {
		return pid, ErrAlreadyRunning
	}

	if err := os.MkdirAll(d.dataDir, 0755); err != nil {
		return 0, fmt.Errorf("daemon: create data dir: %w", err)
	}

	logFile, err := os.OpenFile(d.logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return 0, fmt.Errorf("daemon: open log file: %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		logFile.Close()
		return 0, fmt.Errorf("daemon: get executable: %w", err)
	}

	// Open /dev/null for stdin
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		logFile.Close()
		return 0, fmt.Errorf("daemon: open /dev/null: %w", err)
	}

	cmd := exec.Command(executable, args...)
	cmd.Env = append(os.Environ(), EnvDaemon+"=1")
	cmd.Stdin = devNull
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = d.dataDir

	// Detach from parent process group
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		devNull.Close()
		logFile.Close()
		return 0, fmt.Errorf("daemon: start process: %w", err)
	}

	pid := cmd.Process.Pid

	if err := d.writePID(pid); err != nil {
		_ = cmd.Process.Kill()
		devNull.Close()
		logFile.Close()
		return 0, fmt.Errorf("daemon: write pid: %w", err)
	}

	// Don't wait for the child — we detached it
	go func() {
		_ = cmd.Wait()
		devNull.Close()
		logFile.Close()
	}()

	// Give the child a moment to start and verify it's running
	time.Sleep(100 * time.Millisecond)
	if !processExists(pid) {
		_ = os.Remove(d.pidFile)
		return 0, fmt.Errorf("daemon: process exited immediately (check %s for errors)", d.logFile)
	}

	return pid, nil
}

func (d *Daemon) Stop(timeout time.Duration) error {
	running, pid := d.IsRunning()
	if !running {
		return ErrNotRunning
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("daemon: find process %d: %w", pid, err)
	}

	// Send SIGTERM for graceful shutdown
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			_ = os.Remove(d.pidFile)
			return nil
		}
		return fmt.Errorf("daemon: send SIGTERM: %w", err)
	}

	// Wait for process to exit
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processExists(pid) {
			_ = os.Remove(d.pidFile)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill if still running
	_ = proc.Signal(syscall.SIGKILL)
	time.Sleep(100 * time.Millisecond)

	if processExists(pid) {
		return ErrStopTimeout
	}

	_ = os.Remove(d.pidFile)
	return nil
}

func (d *Daemon) Restart(args []string, timeout time.Duration) (int, error) {
	if running, _ := d.IsRunning(); running {
		if err := d.Stop(timeout); err != nil && !errors.Is(err, ErrNotRunning) {
			return 0, fmt.Errorf("daemon: stop for restart: %w", err)
		}
	}
	return d.Start(args)
}

func (d *Daemon) readPID() (int, error) {
	data, err := os.ReadFile(d.pidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func (d *Daemon) writePID(pid int) error {
	return os.WriteFile(d.pidFile, []byte(strconv.Itoa(pid)), 0644)
}

func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Send signal 0 to check if alive.
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

func IsDaemonChild() bool {
	return os.Getenv(EnvDaemon) == "1"
}

// internal/training/dashboard_cmd.go
// Standalone dashboard runner — can be started independently of training.
package training

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// RunDashboard starts the web dashboard and blocks until interrupted.
func RunDashboard() {
	StartDashboard()
	fmt.Fprintf(os.Stderr, "[dashboard] Open http://localhost:8077 in your browser\n")
	fmt.Fprintf(os.Stderr, "[dashboard] Monitoring: /tmp/grpo-metrics.log\n")
	fmt.Fprintf(os.Stderr, "[dashboard] Press Ctrl+C to stop\n")

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	fmt.Fprintf(os.Stderr, "\n[dashboard] Stopped\n")
}

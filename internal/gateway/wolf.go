// SPDX-License-Identifier: Apache-2.0
package gateway

import (
	"context"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/localcontent"
	"runtime"
	"time"
)

func startWolf(ctx context.Context, c config.WolfConfig) (*localcontent.Worker, error) {
	if !c.Enabled {
		return nil, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, fmt.Errorf("wolf defender currently requires macOS or Linux CPU ONNX Runtime")
	}
	startup, cancel := context.WithTimeout(ctx, time.Duration(c.StartupTimeoutMs)*time.Millisecond)
	defer cancel()
	w, err := localcontent.StartConfigured(startup, c.PythonExecutable, []string{"-I", "-m", "defenseclaw.wolf"}, time.Duration(c.TimeoutMs)*time.Millisecond, c)
	if err != nil {
		return nil, fmt.Errorf("wolf defender unavailable: provision the optional Python runtime and pinned model assets; run defenseclaw doctor: %w", err)
	}
	return w, nil
}

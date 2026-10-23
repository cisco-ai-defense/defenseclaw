// SPDX-License-Identifier: Apache-2.0
package config

import (
	"fmt"
	"math"
	"path/filepath"
)

// WolfConfig selects a pinned local model and a trusted Python environment.
// Model assets and optional dependencies are never downloaded by the gateway.
type WolfConfig struct {
	Enabled          bool    `mapstructure:"enabled" yaml:"enabled,omitempty" json:"enabled"`
	Variant          string  `mapstructure:"variant" yaml:"variant,omitempty" json:"variant"`
	ModelDir         string  `mapstructure:"model_dir" yaml:"model_dir,omitempty" json:"model_dir"`
	PythonExecutable string  `mapstructure:"python_executable" yaml:"python_executable,omitempty" json:"python_executable"`
	Threshold        float64 `mapstructure:"threshold" yaml:"threshold,omitempty" json:"threshold"`
	Threads          int     `mapstructure:"threads" yaml:"threads,omitempty" json:"threads"`
	WindowTokens     int     `mapstructure:"window_tokens" yaml:"window_tokens,omitempty" json:"window_tokens"`
	OverlapTokens    int     `mapstructure:"overlap_tokens" yaml:"overlap_tokens,omitempty" json:"overlap_tokens"`
	MaxTokens        int     `mapstructure:"max_tokens" yaml:"max_tokens,omitempty" json:"max_tokens"`
	MaxWindows       int     `mapstructure:"max_windows" yaml:"max_windows,omitempty" json:"max_windows"`
	TimeoutMs        int     `mapstructure:"timeout_ms" yaml:"timeout_ms,omitempty" json:"timeout_ms"`
	StartupTimeoutMs int     `mapstructure:"startup_timeout_ms" yaml:"startup_timeout_ms,omitempty" json:"startup_timeout_ms"`
}

func DefaultWolfConfig() WolfConfig {
	return WolfConfig{Variant: "small", Threshold: .5, Threads: 2, WindowTokens: 510, OverlapTokens: 64, MaxTokens: 8192, MaxWindows: 20, TimeoutMs: 500, StartupTimeoutMs: 30000}
}

func (w WolfConfig) Validate() error {
	if !w.Enabled {
		return nil
	}
	if w.Variant != "small" && w.Variant != "full" {
		return fmt.Errorf("guardrail.wolf.variant must be small or full")
	}
	if !filepath.IsAbs(w.ModelDir) || !filepath.IsAbs(w.PythonExecutable) {
		return fmt.Errorf("guardrail.wolf requires absolute model_dir and python_executable paths")
	}
	if math.IsNaN(w.Threshold) || math.IsInf(w.Threshold, 0) || w.Threshold <= 0 || w.Threshold >= 1 {
		return fmt.Errorf("guardrail.wolf.threshold must be between 0 and 1")
	}
	if w.Threads < 1 || w.Threads > 32 {
		return fmt.Errorf("guardrail.wolf.threads must be 1..32")
	}
	if w.WindowTokens < 2 || w.WindowTokens > 2046 {
		return fmt.Errorf("guardrail.wolf.window_tokens must be 2..2046")
	}
	if w.OverlapTokens < 0 || w.OverlapTokens > 2045 {
		return fmt.Errorf("guardrail.wolf.overlap_tokens must be 0..2045")
	}
	if w.MaxTokens < 1 || w.MaxTokens > 32768 {
		return fmt.Errorf("guardrail.wolf.max_tokens must be 1..32768")
	}
	if w.MaxWindows < 1 || w.MaxWindows > 128 {
		return fmt.Errorf("guardrail.wolf.max_windows must be 1..128")
	}
	if w.TimeoutMs < 1 || w.TimeoutMs > 5000 {
		return fmt.Errorf("guardrail.wolf.timeout_ms must be 1..5000")
	}
	if w.StartupTimeoutMs < 1000 || w.StartupTimeoutMs > 120000 {
		return fmt.Errorf("guardrail.wolf.startup_timeout_ms must be 1000..120000")
	}
	if w.OverlapTokens >= w.WindowTokens {
		return fmt.Errorf("guardrail.wolf.overlap_tokens must be less than window_tokens")
	}
	return nil
}

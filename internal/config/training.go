// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

// TrainingConfig controls continuous model improvement via local fine-tuning.
type TrainingConfig struct {
	Enabled              bool                `mapstructure:"enabled" yaml:"enabled"`
	Backend              string              `mapstructure:"backend" yaml:"backend,omitempty"`
	ModelsDir            string              `mapstructure:"models_dir" yaml:"models_dir,omitempty"`
	LlamaServerPort      int                 `mapstructure:"llama_server_port" yaml:"llama_server_port,omitempty"`
	TrainingTimeoutHours int                 `mapstructure:"training_timeout_hours" yaml:"training_timeout_hours,omitempty"`
	TraceRetentionDays   int                 `mapstructure:"trace_retention_days" yaml:"trace_retention_days,omitempty"`
	BaseModels           []TrainingBaseModel `mapstructure:"base_models" yaml:"base_models,omitempty"`
	Categories           []TrainingCategory  `mapstructure:"categories" yaml:"categories,omitempty"`
}

// TrainingBaseModel defines a base model available for fine-tuning.
type TrainingBaseModel struct {
	ID      string `mapstructure:"id" yaml:"id"`
	HFRepo  string `mapstructure:"hf_repo" yaml:"hf_repo,omitempty"`
	MLXRepo string `mapstructure:"mlx_repo" yaml:"mlx_repo,omitempty"`
	Size    string `mapstructure:"size" yaml:"size,omitempty"`
}

// TrainingCategory defines a task category with its training policy.
type TrainingCategory struct {
	Name            string  `mapstructure:"name" yaml:"name"`
	BaseModel       string  `mapstructure:"base_model" yaml:"base_model"`
	Algorithm       string  `mapstructure:"algorithm" yaml:"algorithm,omitempty"`
	MinTraces       int     `mapstructure:"min_traces" yaml:"min_traces,omitempty"`
	EvalThreshold   float64 `mapstructure:"eval_threshold" yaml:"eval_threshold,omitempty"`
	EvalPrompts     int     `mapstructure:"eval_prompts" yaml:"eval_prompts,omitempty"`
	AutoTrigger     bool    `mapstructure:"auto_trigger" yaml:"auto_trigger,omitempty"`
	MonitorInterval int     `mapstructure:"monitor_interval" yaml:"monitor_interval,omitempty"`
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultSandboxRuntime = "auto"

// SandboxRuntimeConfig opts in to one adapter. Enablement is not evidence that
// an installed runtime can enforce a requested policy; admission checks that.
type SandboxRuntimeConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}

type SandboxRuntimesConfig struct {
	OpenShell SandboxRuntimeConfig `mapstructure:"openshell" yaml:"openshell"`
	AXIS      SandboxRuntimeConfig `mapstructure:"axis" yaml:"axis"`
}

// SandboxConfig is common policy and runtime selection. A nil Config.Sandbox
// preserves supported openshell configuration. Vendor installation, executable,
// gateway and image settings remain under openshell.
type SandboxConfig struct {
	// declared records explicit source leaves. Nil means a programmatic value,
	// for which nonzero values (including false pointers) are explicit changes.
	declared     map[string]bool
	Enabled      bool                     `mapstructure:"enabled" yaml:"enabled"`
	Runtime      string                   `mapstructure:"runtime" yaml:"runtime,omitempty"`
	Runtimes     SandboxRuntimesConfig    `mapstructure:"runtimes" yaml:"runtimes"`
	IngressPort  int                      `mapstructure:"ingress_port" yaml:"ingress_port,omitempty"`
	EgressPort   int                      `mapstructure:"egress_port" yaml:"egress_port,omitempty"`
	Pack         string                   `mapstructure:"pack" yaml:"pack,omitempty"`
	PackDir      string                   `mapstructure:"pack_dir" yaml:"pack_dir,omitempty"`
	Profile      string                   `mapstructure:"profile" yaml:"profile,omitempty"`
	Yolo         *bool                    `mapstructure:"yolo" yaml:"yolo,omitempty"`
	LLM          string                   `mapstructure:"llm" yaml:"llm,omitempty"`
	KeepHeadless bool                     `mapstructure:"keep_headless" yaml:"keep_headless,omitempty"`
	Workdir      OpenShellWorkdirConfig   `mapstructure:"workdir" yaml:"workdir,omitempty"`
	Egress       OpenShellEgressConfig    `mapstructure:"egress" yaml:"egress,omitempty"`
	Approvals    OpenShellApprovalsConfig `mapstructure:"approvals" yaml:"approvals,omitempty"`
	Resources    OpenShellResourcesConfig `mapstructure:"resources" yaml:"resources,omitempty"`
	Harnesses    []string                 `mapstructure:"harnesses" yaml:"harnesses,omitempty"`
	Wrappers     []string                 `mapstructure:"wrappers" yaml:"wrappers,omitempty"`
	MCP          OpenShellMCPConfig       `mapstructure:"mcp" yaml:"mcp,omitempty"`
	Admin        OpenShellAdminConfig     `mapstructure:"admin" yaml:"admin,omitempty"`
}

// SandboxEnabled reports the common switch, retaining legacy enablement when
// the common namespace is absent. It starts or probes no runtime.
func (c *Config) SandboxEnabled() bool {
	if c == nil {
		return false
	}
	if c.Sandbox != nil {
		return c.Sandbox.Enabled
	}
	return c.OpenShell.Enabled
}

func (c *Config) SandboxDefaultRuntime() string {
	if c == nil || c.Sandbox == nil || c.Sandbox.Runtime == "" {
		return DefaultSandboxRuntime
	}
	return c.Sandbox.Runtime
}

func (c *Config) SandboxRuntimeEnabled(runtime string) bool {
	if !c.SandboxEnabled() {
		return false
	}
	if c.Sandbox == nil {
		return runtime == "openshell"
	}
	switch runtime {
	case "openshell":
		return c.Sandbox.Runtimes.OpenShell.Enabled
	case "axis":
		return c.Sandbox.Runtimes.AXIS.Enabled
	default:
		return false
	}
}

// EffectiveSandboxPolicy projects common policy into the existing policy value
// type without changing installation-owned OpenShell settings. Callers must
// still perform runtime availability and capability admission before launch.
func (c *Config) EffectiveSandboxPolicy() (OpenShellConfig, error) {
	if c == nil {
		return OpenShellConfig{}, nil
	}
	o := c.OpenShell
	s := c.Sandbox
	if s == nil {
		return o, nil
	}
	o.Enabled = s.Enabled
	overlaySandboxPolicy(reflect.ValueOf(&o).Elem(), reflect.ValueOf(s).Elem(), s.declared, "")
	// A legacy administrative floor remains in force even if the new source
	// omits it. Different pins/packs must never replace a legacy requirement.
	for _, pair := range []struct{ key, old, next string }{
		{"required_pack", o.Admin.RequiredPack, s.Admin.RequiredPack},
		{"required_pack_digest", o.Admin.RequiredPackDigest, s.Admin.RequiredPackDigest},
	} {
		if pair.old != "" && pair.next != "" && pair.old != pair.next {
			path := "sandbox.admin." + pair.key
			return OpenShellConfig{}, settingErrorAt(path, fmt.Errorf("%s conflicts with openshell.admin.%s", path, pair.key))
		}
	}
	var err error
	o.Admin, err = TightenOpenShellAdmin(o.Admin, &s.Admin)
	if err != nil {
		return OpenShellConfig{}, sandboxSettingError("sandbox.admin", fmt.Errorf("sandbox.admin: %w", err))
	}
	return o, nil
}

// restoreSandboxConfig decodes the optional namespace directly from the source.
// Explicit overlap is compared before any loader defaults enter the common
// policy, so an implicit openshell.llm=auto cannot contradict sandbox.llm=none.
func restoreSandboxConfig(c *Config, raw []byte, dataDir string) error {
	doc, err := sourceYAMLNode(raw)
	if err != nil {
		return err
	}
	root := v8DocumentRoot(doc)
	node := v8YAMLMapValue(root, "sandbox")
	if node == nil {
		c.Sandbox = nil
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return settingErrorAt("sandbox", errors.New("sandbox: expected a configuration mapping"))
	}
	if err := sandboxSourceConflicts(v8YAMLMapValue(root, "openshell"), node, ""); err != nil {
		return err
	}
	s := defaultSandboxConfig(dataDir)
	if previous := v8YAMLMapValue(root, "openshell"); previous != nil {
		// Mirror inherited source leaves in the common model too. Decode only
		// into its modeled fields; vendor settings have no matching field.
		if err := previous.Decode(s); err != nil {
			return fmt.Errorf("sandbox: inherited policy: %w", err)
		}
		s.Enabled = false
	}
	if err := node.Decode(s); err != nil {
		return fmt.Errorf("sandbox: %w", err)
	}
	s.declared = make(map[string]bool)
	declareSandboxLeaves(node, "", s.declared)
	c.Sandbox = s
	return nil
}

func declareSandboxLeaves(node *yaml.Node, prefix string, declared map[string]bool) {
	if node.Kind != yaml.MappingNode {
		declared[prefix] = true
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		if prefix != "" {
			key = prefix + "." + key
		}
		declareSandboxLeaves(node.Content[i+1], key, declared)
	}
}

func overlaySandboxPolicy(dst, src reflect.Value, declared map[string]bool, prefix string) {
	if src.Kind() != reflect.Struct {
		if (declared != nil && declared[prefix]) || (declared == nil && !src.IsZero()) {
			dst.Set(src)
		}
		return
	}
	for i := 0; i < src.NumField(); i++ {
		field := src.Type().Field(i)
		if field.PkgPath != "" || field.Name == "Admin" || field.Name == "Enabled" && prefix == "" {
			continue
		}
		target := dst.FieldByName(field.Name)
		if !target.IsValid() {
			continue
		}
		key := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if prefix != "" {
			key = prefix + "." + key
		}
		overlaySandboxPolicy(target, src.Field(i), declared, key)
	}
}

func defaultSandboxConfig(dataDir string) *SandboxConfig {
	return &SandboxConfig{
		Runtime: DefaultSandboxRuntime,
		LLM:     OpenShellLLMAuto,
		PackDir: filepath.Join(dataDir, "policies", DefaultOpenShellPackDirName),
		Workdir: OpenShellWorkdirConfig{
			GitDepth: DefaultOpenShellGitDepth, OnExit: DefaultOpenShellOnExit,
			UndoIgnored: OpenShellUndoIgnoredConfig{MaxMB: DefaultOpenShellUndoIgnoredMaxMB, Dirs: append([]string(nil), DefaultOpenShellUndoIgnoredDirs...)},
		},
		Approvals: OpenShellApprovalsConfig{DebounceMs: DefaultOpenShellApprovalDebounceMs},
	}
}

// Only shared policy keys participate: legacy enablement and vendor settings
// do not conflict with the new master switch or adapter enablement.
var sandboxCommonPolicyKeys = []string{
	"ingress_port", "egress_port", "pack", "pack_dir", "profile", "yolo", "llm", "keep_headless",
	"workdir", "egress", "approvals", "resources", "harnesses", "wrappers", "mcp", "admin",
}

func sandboxSourceConflicts(old, next *yaml.Node, prefix string) error {
	if old == nil || next == nil {
		return nil
	}
	if prefix == "" {
		for _, key := range sandboxCommonPolicyKeys {
			if err := sandboxSourceConflicts(v8YAMLMapValue(old, key), v8YAMLMapValue(next, key), key); err != nil {
				return err
			}
		}
		return nil
	}
	if old.Kind == yaml.MappingNode && next.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(next.Content); i += 2 {
			key := next.Content[i].Value
			if err := sandboxSourceConflicts(v8YAMLMapValue(old, key), next.Content[i+1], prefix+"."+key); err != nil {
				return err
			}
		}
		return nil
	}
	var a, b any
	if err := old.Decode(&a); err != nil {
		return err
	}
	if err := next.Decode(&b); err != nil {
		return err
	}
	if !reflect.DeepEqual(a, b) {
		path := "sandbox." + prefix
		return settingErrorAt(path, fmt.Errorf("%s conflicts with explicitly configured openshell.%s; use one common policy source", path, prefix))
	}
	return nil
}

func (c *Config) ValidateSandbox() error {
	if c == nil || c.Sandbox == nil {
		return nil
	}
	if c.SecureClientIntegration() {
		return settingErrorAt("sandbox", errors.New("sandbox: common runtime configuration is not supported with the Secure Client integration"))
	}
	if err := validateOpenShellEnum("sandbox.runtime", c.Sandbox.Runtime, true, "auto", "openshell", "axis"); err != nil {
		return settingErrorAt("sandbox.runtime", errors.New("sandbox.runtime: select auto, openshell or axis"))
	}
	if c.Sandbox.Enabled && c.SandboxDefaultRuntime() == "axis" {
		return settingErrorAt("sandbox.runtime", errors.New("sandbox.runtime: AXIS runtime is not available in this build; keep sandbox.enabled false until its containment and execution gates are qualified"))
	}
	policy, err := c.EffectiveSandboxPolicy()
	if err != nil {
		return err
	}
	view := *c
	view.OpenShell = policy
	view.OpenShell.Enabled = c.SandboxRuntimeEnabled("openshell") && c.SandboxDefaultRuntime() != "axis"
	if err := view.ValidateOpenShell(); err != nil {
		if sandboxErrorIsTyped(err) {
			return err
		}
		return sandboxSettingError("sandbox", fmt.Errorf("sandbox: %s", strings.ReplaceAll(err.Error(), "openshell.", "sandbox.")))
	}
	return view.validateSandboxProfiles()
}

// applySandboxPolicy feeds the effective policy to existing consumers, so an
// accepted common namespace is never ignored by the OpenShell-only code paths.
// Active AXIS selections are refused by ValidateSandbox until qualified.
func (c *Config) applySandboxPolicy() error {
	if c == nil || c.Sandbox == nil {
		return nil
	}
	policy, err := c.EffectiveSandboxPolicy()
	if err != nil {
		return err
	}
	policy.Enabled = c.SandboxRuntimeEnabled("openshell") && c.SandboxDefaultRuntime() != "axis"
	c.OpenShell = policy
	return nil
}

// Keep the original typed source/profile error when one exists. Only common
// loader semantic refusals need a SettingError for field-level diagnostics.
func sandboxErrorIsTyped(err error) bool {
	var setting *SettingError
	var yamlError *V8YAMLError
	var schemaError *V8SchemaError
	var semanticError *V8SemanticError
	var profileError *UnknownGuardrailProfileError
	var pathError *V8ConfigPathError
	return errors.As(err, &setting) || errors.As(err, &yamlError) || errors.As(err, &schemaError) ||
		errors.As(err, &semanticError) || errors.As(err, &profileError) || errors.As(err, &pathError)
}

func sandboxSettingError(path string, err error) error {
	if err == nil || sandboxErrorIsTyped(err) {
		return err
	}
	return settingErrorAt(path, err)
}

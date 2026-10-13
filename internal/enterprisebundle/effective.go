// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"context"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// maxConfigBytes is the config loader's source limit.
const maxConfigBytes = config.V8YAMLMaxSourceBytes

// bundleTopDirs are the bundle directories config.yaml may point into.
var bundleTopDirs = map[string]bool{"policies": true, "discovery": true, "scanners": true}

// RenderConfig returns config.yaml with every value that names a bundle path
// rewritten to that path under root. A bundle path is relative and starts
// with policies/, discovery/ or scanners/; it must name a bundle file or
// directory, or (for a glob such as discovery/signature-packs/*.json) a
// bundle directory, else the bundle is refused (file_missing). bundle sign
// renders against its working copy and apply against the versioned install
// directory; the effective digest replaces either root with ${bundle_root}.
func RenderConfig(b *Bundle, root string) ([]byte, error) {
	raw, ok := b.Files[ConfigName]
	if !ok {
		return nil, refuse(CodeFileMissing, ConfigName, "the bundle has no config.yaml")
	}
	doc, err := parseConfigNode(raw)
	if err != nil {
		return nil, err
	}
	dirs := bundleDirs(b)
	var bad error
	var visit func(node *yaml.Node) bool
	visit = func(node *yaml.Node) bool {
		switch node.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, child := range node.Content {
				if !visit(child) {
					return false
				}
			}
		case yaml.MappingNode:
			// Keys are names, not paths: only values are rendered.
			for i := 1; i < len(node.Content); i += 2 {
				if !visit(node.Content[i]) {
					return false
				}
			}
		case yaml.ScalarNode:
			if node.Tag != "!!str" {
				return true
			}
			rendered, err := renderValue(node.Value, root, b, dirs)
			if err != nil {
				bad = err
				return false
			}
			node.Value = rendered
		}
		return true
	}
	visit(doc)
	if bad != nil {
		return nil, bad
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, refuse(CodeConfigInvalid, ConfigName, "cannot be rendered")
	}
	if err := enc.Close(); err != nil {
		return nil, refuse(CodeConfigInvalid, ConfigName, "cannot be rendered")
	}
	return out.Bytes(), nil
}

// bundleDirs is the set of directories that hold a bundle file.
func bundleDirs(b *Bundle) map[string]bool {
	dirs := map[string]bool{}
	for name := range b.Files {
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			dirs[dir] = true
		}
	}
	return dirs
}

func renderValue(value, root string, b *Bundle, dirs map[string]bool) (string, error) {
	top, _, nested := strings.Cut(value, "/")
	if !nested || !bundleTopDirs[top] {
		return value, nil
	}
	target := value
	if strings.ContainsAny(value, "*?[") {
		target = path.Dir(value)
		if strings.ContainsAny(target, "*?[") {
			return "", refuse(CodeConfigInvalid, ConfigName, "the bundle path %s has a pattern in a directory name", safePath(value))
		}
	}
	if err := checkPathName(target); err != nil {
		return "", refuse(CodeConfigInvalid, ConfigName, "%s is not a valid bundle path: %s", safePath(value), err.Detail)
	}
	if _, isFile := b.Files[target]; !isFile && !dirs[target] {
		return "", refuse(CodeFileMissing, target, "config.yaml names it, but the bundle has no such file or directory")
	}
	return filepath.Join(root, filepath.FromSlash(value)), nil
}

// LoadConfig renders config.yaml against root (RenderConfig) and loads it the
// way the enterprise lifecycle loads a candidate config. It returns the
// config and the rendered bytes. root must hold the bundle files: the
// loader and the effective digest read the policy files the config names.
func LoadConfig(b *Bundle, root string) (*config.Config, []byte, error) {
	rendered, err := RenderConfig(b, root)
	if err != nil {
		return nil, nil, err
	}
	configPath := filepath.Join(root, ConfigName)
	if message, bad := config.ScanManagedEnvSecretReferences(rendered).Refusal(configPath, "with `enterprise secret set --name <name> --from-stdin`", config.EnterpriseSettingsReferenceURL); bad {
		return nil, nil, refuse(CodeConfigInvalid, ConfigName, "%s", boundedDetail(message))
	}
	if _, err := config.ParseCompileObservabilityV8(configPath, rendered, config.ObservabilityV8CompileOptions{
		DefaultDataDir: root, Secrets: bundleSecretProbe{},
	}); err != nil {
		return nil, nil, refuse(CodeConfigInvalid, ConfigName, "%s", boundedDetail(err.Error()))
	}
	cfg, err := config.LoadRuntimeV8InspectionCandidateFromBytes(configPath, rendered)
	if err != nil {
		return nil, nil, refuse(CodeConfigInvalid, ConfigName, "%s", boundedDetail(err.Error()))
	}
	return cfg, rendered, nil
}

// bundleSecretProbe lets the canonical observability compiler check a bundle
// before the target device's protected credentials are available. Verify's
// secret_refs check confirms their presence on the device.
type bundleSecretProbe struct{}

func (bundleSecretProbe) ResolveObservabilitySecret(string) (string, bool) { return "probe", true }
func (bundleSecretProbe) ResolveObservabilityCredential(string) (string, bool) {
	return "probe", true
}

// validateTargetConfig runs the standalone lifecycle's config-only layout
// checks for each target. Device-specific file and credential checks remain
// in ensure and Verify, where the device state is available.
func validateTargetConfig(b *Bundle, cfg *config.Config, rendered []byte, platforms []string) error {
	for _, platform := range platforms {
		var layout managed.StandaloneLayout
		var err error
		switch platform {
		case PlatformLinux, PlatformDarwin:
			layout, err = managed.StandaloneLayoutFor(platform)
		case PlatformWindows:
			// Windows install roots and API port come from protected machine
			// registration, which an offline signer cannot read. The schema
			// and runtime loader ran above; require the declared profile that
			// the standalone service pins on the target.
			doc, err := config.ParseV8YAML(ConfigName, b.Files[ConfigName])
			if err != nil {
				return refuse(CodeConfigInvalid, ConfigName, "windows: %s", boundedDetail(err.Error()))
			}
			if _, explicit := doc.Plain["data_dir"]; explicit {
				return refuse(CodeConfigInvalid, ConfigName, "windows: config data_dir must be omitted; the device uses <registered ProgramData>\\Cisco\\DefenseClaw\\runtime (usually C:\\ProgramData\\Cisco\\DefenseClaw\\runtime)")
			}
			if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
				return refuse(CodeConfigInvalid, ConfigName, "windows: config deployment_mode must be %s", managed.DeploymentModeManagedEnterprise)
			}
			if cfg.DeclaredEnterpriseProfile() != managed.ProfileStandalone {
				return refuse(CodeConfigInvalid, ConfigName, "windows: config must set enterprise.profile: %s", managed.ProfileStandalone)
			}
			continue
		default:
			return refuse(CodeManifestInvalid, "target.platforms", "unknown platform %s", safePath(platform))
		}
		if err != nil {
			return refuse(CodeConfigInvalid, ConfigName, "%s", boundedDetail(err.Error()))
		}
		compiled, err := config.ParseCompileObservabilityV8(cfg.ConfigFilePath, rendered, config.ObservabilityV8CompileOptions{
			DefaultDataDir: layout.DataDir, Secrets: bundleSecretProbe{},
		})
		if err != nil {
			return refuse(CodeConfigInvalid, ConfigName, "%s: %s", platform, boundedDetail(err.Error()))
		}
		if err := config.ValidateManagedStandaloneConfig(b.Files[ConfigName], cfg, compiled.Plan, layout); err != nil {
			return refuse(CodeConfigInvalid, ConfigName, "%s: %s", platform, boundedDetail(err.Error()))
		}
	}
	return nil
}

// PolicyDigester computes the effective policy digest of cfg (loaded from
// raw) for goos with the bundle at bundleRoot. The gateway's
// ComputeEffectivePolicyFor is the implementation; it is passed in so this
// package stays below the gateway.
type PolicyDigester func(ctx context.Context, cfg *config.Config, raw []byte, goos, bundleRoot string) (string, error)

// EffectivePolicyDigests loads the bundle config against root and returns
// its effective policy digest for each platform. The config is loaded once,
// on this host; a config whose defaults differ by platform (data_dir, for
// example) digests as this host resolves it.
func EffectivePolicyDigests(ctx context.Context, b *Bundle, root string, platforms []string, digest PolicyDigester) (map[string]string, error) {
	cfg, rendered, err := LoadConfig(b, root)
	if err != nil {
		return nil, err
	}
	if err := validateTargetConfig(b, cfg, rendered, platforms); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(platforms))
	for _, platform := range platforms {
		if !knownPlatform(platform) {
			return nil, refuse(CodeManifestInvalid, "target.platforms", "unknown platform %s", safePath(platform))
		}
		value, err := digest(ctx, cfg, rendered, platform, root)
		if err != nil {
			return nil, refuse(CodeConfigInvalid, ConfigName, "effective policy for %s: %s", platform, boundedDetail(err.Error()))
		}
		out[platform] = value
	}
	return out, nil
}

func boundedDetail(text string) string {
	if len(text) > 512 {
		text = text[:512] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, text)
}

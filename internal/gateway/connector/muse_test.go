// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestMuseConnectorMetadata(t *testing.T) {
	c := NewMuseConnector()
	if c.Name() != "muse" {
		t.Errorf("Name()=%q, want muse", c.Name())
	}
	if c.Description() == "" {
		t.Error("Description() is empty")
	}
	if c.ToolInspectionMode() != ToolModeBoth {
		t.Errorf("ToolInspectionMode()=%q, want %q", c.ToolInspectionMode(), ToolModeBoth)
	}
	if c.SubprocessPolicy() != SubprocessNone {
		t.Errorf("SubprocessPolicy()=%q, want %q", c.SubprocessPolicy(), SubprocessNone)
	}
	if c.HookAPIPath() != "/api/v1/muse/hook" {
		t.Errorf("HookAPIPath()=%q, want /api/v1/muse/hook", c.HookAPIPath())
	}
}

func TestMuseConnectorHookCapabilities(t *testing.T) {
	c := NewMuseConnector()
	opts := SetupOpts{DataDir: t.TempDir()}
	caps := c.HookCapabilities(opts)

	if !caps.CanBlock {
		t.Error("expected CanBlock=true")
	}
	if caps.CanAskNative {
		t.Error("expected CanAskNative=false for edge devices")
	}
	if !caps.SupportsFailClosed {
		t.Error("expected SupportsFailClosed=true")
	}
	if len(caps.BlockEvents) == 0 {
		t.Error("expected at least one block event")
	}
	found := false
	for _, ev := range caps.BlockEvents {
		if ev == "PreToolUse" {
			found = true
		}
	}
	if !found {
		t.Error("expected PreToolUse in BlockEvents")
	}
}

func TestMuseConnectorSetCredentials(t *testing.T) {
	c := NewMuseConnector()
	c.SetCredentials("", "")
	c.SetCredentials("test-token", "test-master-key")
}

func TestMuseConfigRootLinux(t *testing.T) {
	root := museConfigRootFor("linux", SetupOpts{})
	if !filepath.IsAbs(root) {
		t.Errorf("Linux config root=%q is not absolute", root)
	}
	if filepath.Base(root) != "musegadget" {
		t.Errorf("Linux config root=%q, want leaf dir musegadget", root)
	}
}

func TestMuseConfigRootDarwin(t *testing.T) {
	root := museConfigRootFor("darwin", SetupOpts{})
	if !filepath.IsAbs(root) {
		t.Errorf("Darwin config root=%q is not absolute", root)
	}
}

func TestMuseConfigRootOverride(t *testing.T) {
	root := museConfigRootFor("linux", SetupOpts{ConfigHome: "/custom/muse"})
	if root != "/custom/muse" {
		t.Errorf("ConfigHome override root=%q, want /custom/muse", root)
	}
}

func TestMuseConfigPathOverride(t *testing.T) {
	prev := MuseHooksPathOverride
	MuseHooksPathOverride = "/tmp/test-muse-hooks.json"
	t.Cleanup(func() { MuseHooksPathOverride = prev })

	path := museConfigPath(SetupOpts{})
	if path != "/tmp/test-muse-hooks.json" {
		t.Errorf("override path=%q, want /tmp/test-muse-hooks.json", path)
	}
}

func TestMuseProfileDecode(t *testing.T) {
	payload := map[string]interface{}{
		"event":      "PreToolUse",
		"tool_name":  "system.run",
		"tool_args":  map[string]interface{}{"cmd": "ls -la"},
		"content":    "ls -la",
		"session_id": "sess-abc",
		"device_id":  "gadget-rpi4",
		"direction":  "request",
		"cwd":        "/home/pi",
	}

	req := museProfileDecode(payload)

	if req.ConnectorName != "muse" {
		t.Errorf("ConnectorName=%q, want muse", req.ConnectorName)
	}
	if req.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName=%q, want PreToolUse", req.HookEventName)
	}
	if req.ToolName != "system.run" {
		t.Errorf("ToolName=%q, want system.run", req.ToolName)
	}
	if !req.ToolArgsAuthoritative {
		t.Error("expected ToolArgsAuthoritative=true")
	}
	var args map[string]interface{}
	if err := json.Unmarshal(req.ToolArgs, &args); err != nil {
		t.Fatalf("Unmarshal ToolArgs: %v", err)
	}
	if args["cmd"] != "ls -la" {
		t.Errorf("ToolArgs.cmd=%v, want ls -la", args["cmd"])
	}
	if req.Content != "ls -la" {
		t.Errorf("Content=%q, want ls -la", req.Content)
	}
	if req.SessionID != "sess-abc" {
		t.Errorf("SessionID=%q, want sess-abc", req.SessionID)
	}
	if req.AgentID != "gadget-rpi4" {
		t.Errorf("AgentID=%q, want gadget-rpi4", req.AgentID)
	}
	if req.Direction != "request" {
		t.Errorf("Direction=%q, want request", req.Direction)
	}
	if req.CWD != "/home/pi" {
		t.Errorf("CWD=%q, want /home/pi", req.CWD)
	}
}

func TestMuseProfileDecodeMinimal(t *testing.T) {
	payload := map[string]interface{}{
		"event":     "PreToolUse",
		"tool_name": "device.health",
	}

	req := museProfileDecode(payload)
	if req.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName=%q, want PreToolUse", req.HookEventName)
	}
	if req.ToolName != "device.health" {
		t.Errorf("ToolName=%q, want device.health", req.ToolName)
	}
	if req.Content != "" {
		t.Errorf("Content=%q, want empty", req.Content)
	}
}

func TestMuseProfileRespondBlock(t *testing.T) {
	in := HookRespondInput{
		Action:            "block",
		Reason:            "shell execution blocked by policy",
		AdditionalContext: "system.run is escalated under strict policy",
	}
	out := museProfileRespond(in)
	if out.FieldName != "hook_output" {
		t.Errorf("FieldName=%q, want hook_output", out.FieldName)
	}
	if out.Output["decision"] != "block" {
		t.Errorf("decision=%v, want block", out.Output["decision"])
	}
	if out.Output["reason"] != "shell execution blocked by policy" {
		t.Errorf("reason=%v", out.Output["reason"])
	}
	if out.Output["context"] != "system.run is escalated under strict policy" {
		t.Errorf("context=%v", out.Output["context"])
	}
}

func TestMuseProfileRespondAllow(t *testing.T) {
	in := HookRespondInput{Action: "allow"}
	out := museProfileRespond(in)
	if out.Output["decision"] != "allow" {
		t.Errorf("decision=%v, want allow", out.Output["decision"])
	}
	if _, ok := out.Output["reason"]; ok {
		t.Error("expected no reason field for allow with empty reason")
	}
	if _, ok := out.Output["context"]; ok {
		t.Error("expected no context field for allow with empty context")
	}
}

func TestMuseRegisteredInDefaultRegistry(t *testing.T) {
	reg := NewDefaultRegistry()
	c, ok := reg.Get("muse")
	if !ok {
		t.Fatal("muse connector not found in default registry")
	}
	if c.Name() != "muse" {
		t.Errorf("Name()=%q, want muse", c.Name())
	}
}

func TestMusePlatformSupportWindows(t *testing.T) {
	support := ConnectorSupportOnOS("muse", "windows")
	if support.Status != PlatformUnsupported {
		t.Errorf("Windows status=%q, want unsupported", support.Status)
	}
}

func TestMusePlatformSupportLinux(t *testing.T) {
	support := ConnectorSupportOnOS("muse", "linux")
	if support.Status != PlatformSupported {
		t.Errorf("Linux status=%q, want supported", support.Status)
	}
}

func TestMusePlatformSupportDarwin(t *testing.T) {
	support := ConnectorSupportOnOS("muse", "darwin")
	if support.Status != PlatformSupported {
		t.Errorf("Darwin status=%q, want supported", support.Status)
	}
}

func TestMuseVerifyCleanOnFreshDataDir(t *testing.T) {
	prev := MuseHooksPathOverride
	MuseHooksPathOverride = filepath.Join(t.TempDir(), "hooks.json")
	t.Cleanup(func() { MuseHooksPathOverride = prev })

	c := NewMuseConnector()
	opts := SetupOpts{
		DataDir:   t.TempDir(),
		ProxyAddr: "127.0.0.1:4000",
		APIAddr:   "127.0.0.1:18970",
	}
	if err := c.VerifyClean(opts); err != nil {
		t.Errorf("VerifyClean on fresh DataDir should return nil, got: %v", err)
	}
}

func TestMuseHookProfileDecodeWired(t *testing.T) {
	c := NewMuseConnector()
	opts := SetupOpts{DataDir: t.TempDir()}
	profile := c.HookProfile(opts)

	if profile.Decode == nil {
		t.Fatal("expected Decode callback to be wired for muse connector")
	}
	if profile.Respond == nil {
		t.Fatal("expected Respond callback to be wired for muse connector")
	}
	if profile.Name != "muse" {
		t.Errorf("profile.Name=%q, want muse", profile.Name)
	}
}

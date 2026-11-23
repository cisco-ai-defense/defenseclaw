// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// mountAttest attests a template of a clean, signed image (WORKDIR /work,
// HOME /sandbox, one checked settings file under /etc) with mounts.
func mountAttest(t *testing.T, connector string, vols []*ateapi.Volume, mounts ...*ateapi.VolumeMount) controller.Attestation {
	t.Helper()
	img := "reg.example.com/dc/claude@" + digA
	v := verified(digA, "1.0.10", time.Now().Add(time.Hour))
	v.Entrypoint = []string{kit.RelayBinary, "serve"}
	v.Workdir = "/work"
	v.Env = map[string]string{"HOME": "/sandbox"}
	v.Statement.Predicate.Template.Connector = connector
	v.Statement.Predicate.Hooks.Files = []attest.HookFile{
		{Path: "/etc/claude-code/managed-settings.json", OK: true},
		{Path: "/sandbox/.gemini/hooks.json", OK: true},
		{Path: "(image USER)", OK: true},
	}
	ta := &controller.TemplateAttestor{
		Verifier:   fakeVerifier{by: map[string]*attest.Verified{img: v}},
		Registries: []string{"reg.example.com"},
	}
	att, err := ta.Attest(context.Background(), &ateapi.ActorTemplate{
		Metadata:   &ateapi.ResourceMetadata{Atespace: "a", Name: "t"},
		Containers: []*ateapi.Container{{Image: img, VolumeMounts: mounts, SecurityContext: kitSecurityContext()}},
		Volumes:    vols,
	})
	if err != nil {
		t.Fatal(err)
	}
	return att
}

var (
	durable    = &ateapi.Volume{Name: "d", DurableDir: &ateapi.DurableDirVolume{}}
	systemInfo = &ateapi.Volume{Name: "system-info", SystemInfo: &ateapi.SystemInfoVolume{}}
)

func at(name, p string) *ateapi.VolumeMount { return &ateapi.VolumeMount{Name: name, MountPath: p} }

// RELAY4 acceptance (RKRELAY3 GAP-0368, TestRK3ProbeVolumeMountOverKitPaths):
// admission is default-deny over volume_mounts. A mount at, above or below
// an attested path, outside the WORKDIR, or with an unclean path, is
// refused with Allowlist set (owner D4), the field named and the path not
// shown; the kit's own system-info mount and data folders at or below the
// WORKDIR pass.
func TestAdmissionChecksVolumeMounts(t *testing.T) {
	refused := map[string]struct {
		connector string
		vols      []*ateapi.Volume
		m         *ateapi.VolumeMount
	}{
		"durable at the hook folder":           {"claudecode", nil, at("d", kit.HookDir)},
		"durable at the kit folder":            {"claudecode", nil, at("d", kit.KitDir)},
		"durable at the kit library":           {"claudecode", nil, at("d", kit.LibDir)},
		"durable at /etc/defenseclaw":          {"claudecode", nil, at("d", "/etc/defenseclaw")},
		"durable at a parent, /usr/local/lib":  {"claudecode", nil, at("d", "/usr/local/lib")},
		"durable at a parent, /etc":            {"claudecode", nil, at("d", "/etc")},
		"durable below the hook folder":        {"claudecode", nil, at("d", kit.HookDir+"/x")},
		"durable at a checked settings folder": {"claudecode", nil, at("d", "/etc/claude-code")},
		"durable at a checked settings file":   {"claudecode", nil, at("d", "/etc/claude-code/managed-settings.json")},
		"durable at the guarded ~/.gemini":     {"antigravity", nil, at("d", "/sandbox/.gemini")},
		"durable below ~/.gemini":              {"antigravity", nil, at("d", "/sandbox/.gemini/hooks")},
		"durable at /run/ate":                  {"claudecode", nil, at("d", "/run/ate")},
		"durable at HOME":                      {"claudecode", nil, at("d", "/sandbox")},
		"durable at /tmp (outside WORKDIR)":    {"claudecode", nil, at("d", "/tmp/data")},
		"trailing slash":                       {"claudecode", nil, at("d", kit.HookDir+"/")},
		"dot-dot into the hook folder":         {"claudecode", nil, at("d", "/work/../usr/local/lib/defenseclaw/hooks")},
		"dot-dot below the WORKDIR":            {"claudecode", nil, at("d", "/work/a/../b")},
		"relative path":                        {"claudecode", nil, at("d", "work/data")},
		"double slash":                         {"claudecode", nil, at("d", "/work//data")},
		"root":                                 {"claudecode", nil, at("d", "/")},
		"system_info elsewhere":                {"claudecode", []*ateapi.Volume{systemInfo}, at("system-info", "/etc/defenseclaw")},
		"system_info below the WORKDIR":        {"claudecode", []*ateapi.Volume{systemInfo}, at("system-info", "/work/ate")},
		"a mount of no volume":                 {"claudecode", []*ateapi.Volume{}, at("nope", "/work/data")},
	}
	for name, c := range refused {
		vols := c.vols
		if vols == nil {
			vols = []*ateapi.Volume{durable}
		}
		att := mountAttest(t, c.connector, vols, c.m)
		switch {
		case att.Attested:
			t.Errorf("%s: admitted", name)
		case !att.Allowlist || att.Digest == "" || att.Connector == "":
			t.Errorf("%s: refused without Allowlist and the attestation fields (D4 keeps running actors): %+v", name, att)
		case !strings.Contains(att.Reason, "volume_mounts[0]"):
			t.Errorf("%s: the reason does not name the field: %q", name, att.Reason)
		case c.m.MountPath != "/" && strings.Contains(att.Reason, c.m.MountPath):
			t.Errorf("%s: the reason shows the mount path: %q", name, att.Reason)
		}
	}
	for name, mounts := range map[string][]*ateapi.VolumeMount{
		"the kit's system-info at /run/ate": {at("system-info", controller.SystemInfoMount)},
		"durable at the WORKDIR":            {at("d", "/work")},
		"durable below the WORKDIR":         {at("system-info", "/run/ate"), at("d", "/work/cache")},
		"no mounts":                         nil,
	} {
		if att := mountAttest(t, "antigravity", []*ateapi.Volume{durable, systemInfo}, mounts...); !att.Attested {
			t.Errorf("%s: refused: %q", name, att.Reason)
		}
	}
}

// A WORKDIR that holds an attested path, or one admission cannot read,
// admits no data mount.
func TestAdmissionNeedsAProjectWorkdirForDataMounts(t *testing.T) {
	for _, wd := range []string{"", "/", "/usr", "/usr/local/lib/defenseclaw", "/etc"} {
		img := "reg.example.com/dc/claude@" + digA
		v := verified(digA, "1.0.10", time.Now().Add(time.Hour))
		v.Workdir = wd
		ta := &controller.TemplateAttestor{Verifier: fakeVerifier{by: map[string]*attest.Verified{img: v}}, Registries: []string{"reg.example.com"}}
		for _, p := range []string{"/usr/bin", "/work"} {
			att, err := ta.Attest(context.Background(), &ateapi.ActorTemplate{
				Metadata:   &ateapi.ResourceMetadata{Atespace: "a", Name: "t"},
				Containers: []*ateapi.Container{{Image: img, VolumeMounts: []*ateapi.VolumeMount{at("d", p)}}},
				Volumes:    []*ateapi.Volume{durable},
			})
			if err != nil {
				t.Fatal(err)
			}
			if att.Attested {
				t.Errorf("WORKDIR %q: a data mount at %s is admitted", wd, p)
			}
		}
	}
}

// RELAY4 acceptance (RKRELAY3 GAP-0370, TestRK3ProbeDuplicateEnvName): a
// name set twice is refused, whichever value comes first; the reason names
// the variable, not its values.
func TestAdmissionRefusesADuplicateEnvName(t *testing.T) {
	for name, env := range map[string][]*ateapi.EnvVar{
		"denied value first":  {{Name: "XDG_CONFIG_HOME", Value: "/sandbox/.evil"}, {Name: "XDG_CONFIG_HOME", Value: kit.XDGConfigHome}},
		"allowed value first": {{Name: "XDG_CONFIG_HOME", Value: kit.XDGConfigHome}, {Name: "XDG_CONFIG_HOME", Value: "/sandbox/.evil"}},
		"same value twice":    {{Name: "LANG", Value: "C.UTF-8"}, {Name: "LANG", Value: "C.UTF-8"}},
	} {
		att := specAttest(t, &ateapi.Container{Env: env})
		if att.Attested || !att.Allowlist {
			t.Errorf("%s: admitted (attested=%v allowlist=%v reason=%q)", name, att.Attested, att.Allowlist, att.Reason)
			continue
		}
		if !strings.Contains(att.Reason, "more than once") || !strings.Contains(att.Reason, env[0].Name) || strings.Contains(att.Reason, "/sandbox/.evil") {
			t.Errorf("%s: reason %q", name, att.Reason)
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

// kitAttest attests one container of a clean 1.0.10 kit image (the relay
// entrypoint, image USER root) with the template the caller shaped.
func kitAttest(t *testing.T, mut func(*ateapi.ActorTemplate)) controller.Attestation {
	t.Helper()
	img := "reg.example.com/dc/claude@" + digA
	v := verified(digA, "1.0.10", time.Now().Add(time.Hour))
	v.Entrypoint = []string{kit.RelayBinary, "serve"}
	v.Workdir = "/work"
	v.Env = map[string]string{"HOME": "/sandbox"}
	ta := &controller.TemplateAttestor{Verifier: fakeVerifier{by: map[string]*attest.Verified{img: v}}, Registries: []string{"reg.example.com"}}
	tmpl := &ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "a", Name: "t"},
		Containers: []*ateapi.Container{{Image: img, SecurityContext: &pb.SecurityContext{Capabilities: &pb.Capabilities{
			Add: []string{"SETUID", "SETGID"}, Drop: []string{"AUDIT_WRITE", "NET_BIND_SERVICE"}}}}}}
	if mut != nil {
		mut(tmpl)
	}
	att, err := ta.Attest(context.Background(), tmpl)
	if err != nil {
		t.Fatal(err)
	}
	return att
}

func unknownField(num protowire.Number) []byte {
	return protowire.AppendString(protowire.AppendTag(nil, num, protowire.BytesType), "x")
}

// GAP-0371: admission is default-deny over fields. A field the vendored API
// does not know (a newer Substrate server), in the template, a container,
// an env entry, a volume or a mount, is refused; so is a capability added in
// security_context, and, for a relay that runs the agent as its own user,
// dropping ALL or a capability that relay needs. Hardening drops pass.
func TestAdmissionRefusesFieldsItDoesNotCheck(t *testing.T) {
	if att := kitAttest(t, nil); !att.Attested {
		t.Fatalf("a clean kit template: %+v", att)
	}
	for name, mut := range map[string]func(*ateapi.ActorTemplate){
		"template": func(m *ateapi.ActorTemplate) { m.ProtoReflect().SetUnknown(unknownField(99)) },
		"container": func(m *ateapi.ActorTemplate) {
			m.Containers[0].ProtoReflect().SetUnknown(unknownField(99))
		},
		"env entry": func(m *ateapi.ActorTemplate) {
			e := &ateapi.EnvVar{Name: "LANG", Value: "C.UTF-8"}
			e.ProtoReflect().SetUnknown(unknownField(7))
			m.Containers[0].Env = []*ateapi.EnvVar{e}
		},
		"volume mount": func(m *ateapi.ActorTemplate) {
			vm := &ateapi.VolumeMount{Name: "d", MountPath: "/work/data"}
			vm.ProtoReflect().SetUnknown(unknownField(9))
			m.Volumes = []*ateapi.Volume{{Name: "d", DurableDir: &ateapi.DurableDirVolume{}}}
			m.Containers[0].VolumeMounts = []*ateapi.VolumeMount{vm}
		},
		"volume": func(m *ateapi.ActorTemplate) {
			vol := &ateapi.Volume{Name: "d", DurableDir: &ateapi.DurableDirVolume{}}
			vol.ProtoReflect().SetUnknown(unknownField(12))
			m.Volumes = []*ateapi.Volume{vol}
		},
		"capabilities.add": func(m *ateapi.ActorTemplate) {
			m.Containers[0].SecurityContext = &pb.SecurityContext{Capabilities: &pb.Capabilities{Add: []string{"DAC_OVERRIDE"}}}
		},
		"drop ALL": func(m *ateapi.ActorTemplate) {
			m.Containers[0].SecurityContext = &pb.SecurityContext{Capabilities: &pb.Capabilities{Drop: []string{"ALL"}}}
		},
		"drop CAP_KILL": func(m *ateapi.ActorTemplate) {
			m.Containers[0].SecurityContext = &pb.SecurityContext{Capabilities: &pb.Capabilities{Drop: []string{"NET_RAW", "CAP_KILL"}}}
		},
	} {
		att := kitAttest(t, mut)
		if att.Attested || !att.Allowlist || att.Reason == "" {
			t.Errorf("%s: admitted (%+v)", name, att)
		}
		if strings.Contains(att.Reason, "\"x\"") {
			t.Errorf("%s: the refusal shows a value: %s", name, att.Reason)
		}
	}
	if att := kitAttest(t, func(m *ateapi.ActorTemplate) {
		m.Containers[0].SecurityContext = &pb.SecurityContext{Capabilities: &pb.Capabilities{Add: []string{"SETUID", "SETGID"},
			Drop: []string{"NET_RAW", "MKNOD", "AUDIT_WRITE", "NET_BIND_SERVICE"}}}
	}); !att.Attested {
		t.Errorf("hardening drops are refused: %s", att.Reason)
	}
}

// GAP-0440, GAP-0441, GAP-0442: a volume named twice, a data mount in a
// system folder (a WORKDIR there), and an env name that is not a variable
// name are refused, and the refusal never shows the name or its value.
func TestAdmissionRefusesTwiceNamedVolumesSystemFolderMountsAndBadEnvNames(t *testing.T) {
	img := "reg.example.com/dc/claude@" + digA
	attestWith := func(workdir string, tmpl *ateapi.ActorTemplate) controller.Attestation {
		v := verified(digA, "1.0.10", time.Now().Add(time.Hour))
		v.Entrypoint, v.Workdir, v.Env = []string{kit.RelayBinary, "serve"}, workdir, map[string]string{"HOME": "/sandbox"}
		ta := &controller.TemplateAttestor{Verifier: fakeVerifier{by: map[string]*attest.Verified{img: v}}, Registries: []string{"reg.example.com"}}
		tmpl.Metadata = &ateapi.ResourceMetadata{Atespace: "a", Name: "t"}
		tmpl.Containers[0].Image = img
		tmpl.Containers[0].SecurityContext = &pb.SecurityContext{Capabilities: &pb.Capabilities{
			Add: []string{"SETUID", "SETGID"}, Drop: []string{"AUDIT_WRITE", "NET_BIND_SERVICE"}}}
		att, err := ta.Attest(context.Background(), tmpl)
		if err != nil {
			t.Fatal(err)
		}
		return att
	}
	twice := attestWith("/work", &ateapi.ActorTemplate{
		Volumes:    []*ateapi.Volume{{Name: "system-info", SystemInfo: &ateapi.SystemInfoVolume{}}, {Name: "system-info", DurableDir: &ateapi.DurableDirVolume{}}},
		Containers: []*ateapi.Container{{VolumeMounts: []*ateapi.VolumeMount{{Name: "system-info", MountPath: "/run/ate"}}}}})
	if twice.Attested || !strings.Contains(twice.Reason, "names a volume a second time") {
		t.Errorf("a volume named twice: %+v", twice)
	}
	for _, wd := range []string{"/usr/bin", "/bin", "/etc/app", "/lib", "/run/app"} {
		att := attestWith(wd, &ateapi.ActorTemplate{
			Volumes:    []*ateapi.Volume{{Name: "d", DurableDir: &ateapi.DurableDirVolume{}}},
			Containers: []*ateapi.Container{{VolumeMounts: []*ateapi.VolumeMount{{Name: "d", MountPath: wd}}}}})
		if att.Attested {
			t.Errorf("WORKDIR %s: a data mount over it is admitted", wd)
		}
	}
	if att := attestWith("/opt/app", &ateapi.ActorTemplate{
		Volumes:    []*ateapi.Volume{{Name: "d", DurableDir: &ateapi.DurableDirVolume{}}},
		Containers: []*ateapi.Container{{VolumeMounts: []*ateapi.VolumeMount{{Name: "d", MountPath: "/opt/app/data"}}}}}); !att.Attested {
		t.Errorf("a project WORKDIR /opt/app: %s", att.Reason)
	}
	for _, n := range []string{"LANG=C.UTF-8\nLD_PRELOAD=/tmp/x.so", "1ST", "A-B", "A\x00B", ""} {
		att := attestWith("/work", &ateapi.ActorTemplate{Containers: []*ateapi.Container{{Env: []*ateapi.EnvVar{{Name: n, Value: "v"}}}}})
		if att.Attested || !strings.Contains(att.Reason, "is not a variable name") {
			t.Errorf("env name %q: %+v", n, att)
		}
		if n != "" && (strings.Contains(att.Reason, n) || strings.Contains(att.Reason, "LD_PRELOAD")) {
			t.Errorf("env name %q: the refusal shows it: %s", n, att.Reason)
		}
	}
}

// GAP-0374: HOME is the kit's (/sandbox); a template that moves it is
// refused (the guarded folders, the kit's HOME files and the relay's state
// root are all below it). PATH takes any value (documented).
func TestAdmissionKeepsTheKitHome(t *testing.T) {
	v := verified(digA, "1.0.10", time.Now().Add(time.Hour))
	v.Entrypoint, v.Env = []string{kit.RelayBinary, "serve"}, map[string]string{"HOME": kit.ActorHome}
	env := func(kv ...string) *ateapi.Container {
		c := &ateapi.Container{}
		for i := 0; i < len(kv); i += 2 {
			c.Env = append(c.Env, &ateapi.EnvVar{Name: kv[i], Value: kv[i+1]})
		}
		return c
	}
	if why := controller.ContainerSpecRefusal(env("HOME", "/tmp/h"), v); !strings.Contains(why, "HOME") {
		t.Errorf("HOME=/tmp/h: %q", why)
	}
	for _, c := range []*ateapi.Container{env("HOME", kit.ActorHome), env("PATH", "/sandbox/bin:/usr/bin")} {
		if why := controller.ContainerSpecRefusal(c, v); why != "" {
			t.Errorf("%v: %q", c.GetEnv(), why)
		}
	}
}

// GAP-0373: owner decision D4 keeps running only the actors of a template
// built before the allowlist (a 1.0.9 kit). A template built with it (kit
// 1.0.10) passed it at build, so failing it now means it was edited since:
// its running actors are refused with the new ones (also after a
// controller restart), as an actor that boots the edit would be new.
func TestAnEditAfterTheUpgradeRefusesTheRunningActors(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if r.api.Policy(ref) == nil {
		t.Fatal("no policy")
	}
	reason := "container 0: env sets variables the actor environment allowlist does not permit: LD_PRELOAD (not on the allowlist)"
	r.att.Default = controller.Attestation{Allowlist: true, Reason: reason, KitVersion: "1.0.10", Connector: "claudecode"}
	r.clk.Add(31 * time.Second)
	r.pass()
	if r.api.Policy(ref) != nil {
		t.Fatal("a running actor keeps its network after its 1.0.10 template was edited to fail the allowlist")
	}
	if n := countMsg(r, controller.EventWarning, "keeps running on template"); n != 0 {
		t.Fatalf("warn-only rows for an edited 1.0.10 template: %d", n)
	}
	restart(r)
	r.pass()
	if r.api.Policy(ref) != nil {
		t.Fatal("the policy came back after a restart")
	}
}

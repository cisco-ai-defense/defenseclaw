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

//go:build !windows

package sandboxcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/wrapper"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// hostReport is a doctor report of a ready Linux host; edit adjusts it.
func hostReport(edit func(*openshell.DoctorReport)) func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
	return func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
		rep := &openshell.DoctorReport{CLIVersion: "0.1.1", DockerVersion: "29.4.0", GatewayVersion: "0.1.1", Checks: []openshell.Check{
			{ID: openshell.CheckIDPlatform, Title: "Platform", Status: openshell.StatusPass, Detail: "linux/arm64"},
			{ID: openshell.CheckIDUser, Title: "User", Status: openshell.StatusPass},
			{ID: openshell.CheckIDLandlock, Title: "Landlock", Status: openshell.StatusPass, Detail: "ABI 6"},
			{ID: openshell.CheckIDDocker, Title: "Docker", Status: openshell.StatusPass},
			{ID: openshell.CheckIDGatewayService, Title: "Gateway service", Status: openshell.StatusPass},
			{ID: openshell.CheckIDCLI, Title: "OpenShell CLI", Status: openshell.StatusPass},
			{ID: openshell.CheckIDRegistration, Title: "Gateway registration", Status: openshell.StatusPass},
			{ID: openshell.CheckIDMTLS, Title: "mTLS files", Status: openshell.StatusPass},
			{ID: openshell.CheckIDGatewayVersion, Title: "Gateway version", Status: openshell.StatusPass},
			{ID: openshell.CheckIDBindMounts, Title: "Bind mounts", Status: openshell.StatusWarn, Detail: "off"},
		}}
		if edit != nil {
			edit(rep)
		}
		return rep
	}
}

// mountsOn is a gateway that already allows bind mounts, so setup asks
// nothing about them.
var mountsOn = openshell.BindMounts{AllowDriverConfig: true, EnableBindMounts: true}

// setupApp is a testApp on a ready host whose config.yaml holds extra;
// settled also has the gateway allow bind mounts with OpenShell's telemetry
// off, so setup asks about neither.
func setupApp(t *testing.T, input, extra string, settled bool) *testApp {
	t.Helper()
	ta := newTestApp(t, input)
	writeConfig(t, ta, extra)
	ta.HostDoctor = hostReport(nil)
	if settled {
		ta.gateway.state.BindMounts = mountsOn
		ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
	}
	return ta
}

// noCloseClient keeps the shared fake gateway open when a command closes
// its client.
type noCloseClient struct{ openshell.Client }

func (noCloseClient) Close() error { return nil }

// useGateway gives ta a fake OpenShell gateway.
func useGateway(ta *testApp) (*openshelltest.Fake, openshell.Client) {
	fake := openshelltest.New()
	client := fake.Client(openshell.ClientOptions{})
	ta.OpenShell = func(context.Context) (openshell.Client, *openshell.Registration, error) {
		return noCloseClient{client}, &openshell.Registration{Name: "openshell"}, nil
	}
	return fake, client
}

// runningOn has n sandboxes of someone else run on ta's fake gateway.
func runningOn(t *testing.T, ta *testApp, n int) {
	t.Helper()
	fake, client := useGateway(ta)
	for i := range n {
		name := "dc-claude-theirs-" + string(rune('a'+i))
		if _, err := client.CreateSandbox(bg, name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{
			Labels: map[string]string{manager.LabelManaged: "true", manager.LabelOwner: "someone-else"}}); err != nil {
			t.Fatal(err)
		}
		if err := fake.SetPhase(openshell.DefaultWorkspace, name, openshell.PhaseReady); err != nil {
			t.Fatal(err)
		}
	}
}

// importProfile imports the profile id renders for in, as specID if set.
func importProfile(t *testing.T, client openshell.Client, id string, in profiles.Input, specID string) {
	t.Helper()
	p, err := profiles.Render(id, in)
	if err != nil {
		t.Fatal(err)
	}
	if specID != "" {
		p.Spec.ID = specID
	}
	if _, err := client.ImportProfiles(bg, []openshell.ProfileImportItem{{Profile: p.Spec, Source: "test"}}); err != nil {
		t.Fatal(err)
	}
}

// readyImages is a hook-verified image of this install for Claude Code.
func readyImages(ta *testApp) []image.Record {
	return []image.Record{{Connector: "claudecode", HookFireVerified: true, UID: os.Getuid(), DefenseClawVersion: manager.ImageVersion(),
		IngressPort: ta.Cfg.OpenShellIngressPort(), HarnessVersion: "2.1.156"}}
}

type fakeInstaller struct {
	consent func(*openshell.InstallPlan) (bool, error)
	ran     bool
	// err is the installer's failure once it runs.
	err error
	// e2fsprogs and resigned count the Homebrew steps for the MicroVM
	// driver; done runs after each.
	e2fsprogs, resigned int
	done                func()
}

func (f *fakeInstaller) InstallE2fsprogs(context.Context) error {
	f.e2fsprogs++
	if f.done != nil {
		f.done()
	}
	return nil
}

func (f *fakeInstaller) ResignVMDriver(context.Context) error {
	f.resigned++
	if f.done != nil {
		f.done()
	}
	return nil
}

func (f *fakeInstaller) Install(context.Context) (*openshell.InstallResult, error) {
	if ok, err := f.consent(&openshell.InstallPlan{Release: "v0.1.1"}); err != nil || !ok {
		return nil, errors.New("declined")
	}
	f.ran = true
	if f.err != nil {
		return nil, f.err
	}
	v, _ := openshell.ParseVersion("0.1.1")
	return &openshell.InstallResult{Installed: true, CLIVersion: v}, nil
}

func TestSetupNonInteractive(t *testing.T) {
	ta := setupApp(t, "", "", false)
	ta.IO.TTY = false
	ta.Cfg.OpenShell.Enabled = false
	toml := filepath.Join(t.TempDir(), "gateway.toml")
	writeFile(t, toml, "[openshell.drivers.docker]\nenable_bind_mounts = true\n")
	ta.gateway.applyRes = &openshell.GatewayApplyResult{Files: []openshell.AppliedFile{{Path: toml, Backup: toml + ".defenseclaw.bak"}}, Restarted: true}
	useGateway(ta) // no sandbox runs on the gateway, so setup may restart it
	ta.ok(t, ta.Setup(bg, SetupOptions{NonInteractive: true, Yes: true, Wrappers: true}))
	if len(ta.gateway.planned) != 1 || !ta.gateway.planned[0].EnableBindMounts || ta.gateway.planned[0].Env[openshell.EnvTelemetryEnabled] != "false" || ta.gateway.applied != 1 {
		t.Fatalf("gateway plans = %+v, applied %d", ta.gateway.planned, ta.gateway.applied)
	}
	if r, err := ta.loadReceipt(); err != nil || len(r.GatewayFiles) != 1 || r.GatewayFiles[0].Backup != toml+".defenseclaw.bak" || r.GatewayFiles[0].SHA256 == "" {
		t.Fatalf("receipt = %+v, %v", r, err)
	}
	if c := loadConfig(t, ta); !c.OpenShell.Enabled || !slices.Equal(c.OpenShell.Harnesses, []string{"claudecode", "codex"}) || c.OpenShell.UpstreamTelemetry {
		t.Fatalf("config openshell = %+v", c.OpenShell)
	}
	if !slices.Equal(ta.images.built, []string{"claudecode", "codex"}) {
		t.Fatalf("images built = %v", ta.images.built)
	}
	if b, err := wrapper.Read(filepath.Join(ta.home, ".bashrc")); err != nil || !b.Has("claude") || !b.Has("codex") {
		t.Fatalf("wrappers = %+v, %v", b, err)
	}
	has(t, ta.output(), "Checking this machine…  ✓ linux/arm64  ✓ Landlock  ✓ Docker 29.4.0  ✓ OpenShell 0.1.1",
		"gateway configured and restarted", "Done →  cd <project> && defenseclaw sandbox run claude")
}

// TestSetupShowsTheMachineCheckWhileItRuns pins that the machine check's
// line is on screen while the checks run: on a Mac they took about 40 s
// with nothing after the title (manual test M4).
func TestSetupShowsTheMachineCheckWhileItRuns(t *testing.T) {
	ta := setupApp(t, "", "", true)
	var during string
	ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		if during == "" {
			during = ta.output()
		}
		return hostReport(nil)(ctx, d)
	}
	ta.ok(t, ta.Setup(bg, SetupOptions{NonInteractive: true, SkipImages: true, NoWrappers: true}))
	has(t, during, "DefenseClaw sandbox setup\n  Checking this machine…")
	has(t, ta.output(), "  Checking this machine…  ✓ linux/arm64  ✓ Landlock  ✓ Docker 29.4.0  ✓ OpenShell 0.1.1\n")
}

// TestSetupLeavesTheGatewayRunningSandboxes pins that setup never restarts
// the shared OpenShell gateway under running sandboxes (of any owner) on
// its own: without a terminal (or with --yes) it leaves the change for
// `doctor --fix`, a terminal asks with no as the default, and
// --restart-gateway restarts it.
func TestSetupLeavesTheGatewayRunningSandboxes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		tty     bool
		o       SetupOptions
		applied int
	}{
		{"non-interactive", "", false, SetupOptions{NonInteractive: true}, 0},
		{"yes", "", true, SetupOptions{Yes: true}, 0},
		{"a terminal answers no by default", "\n\n\n", true, SetupOptions{}, 0},
		{"a terminal answers yes", "\n\ny\n", true, SetupOptions{}, 1},
		{"--restart-gateway", "", false, SetupOptions{NonInteractive: true, RestartGateway: true}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := setupApp(t, tc.input, "", false)
			ta.IO.TTY = tc.tty
			runningOn(t, ta, 2)
			o := tc.o
			o.SkipImages, o.NoWrappers = true, true
			ta.ok(t, ta.Setup(bg, o))
			if len(ta.gateway.planned) != 1 || ta.gateway.applied != tc.applied {
				t.Fatalf("gateway plans = %+v, applied %d, want %d\n%s", ta.gateway.planned, ta.gateway.applied, tc.applied, ta.output())
			}
			if tc.o.RestartGateway {
				return
			}
			has(t, ta.output(), "drops the connections of every sandbox on it, and 2 sandboxes run on it (dc-claude-theirs-a, dc-claude-theirs-b)")
			if tc.applied == 0 {
				has(t, ta.output(), "skipped: the OpenShell gateway change above (it restarts the gateway; apply it with `defenseclaw sandbox doctor --fix`")
			}
		})
	}
}

// Without a terminal nothing answers setup's questions, so setup refuses
// before it changes anything unless --yes or --non-interactive says which
// answers to take. It used to take yes for the bind mounts, edit and
// restart the gateway, turn sandboxes on, and then fail at the wrapper
// question.
func TestSetupWithoutATerminalNeedsYesOrNonInteractive(t *testing.T) {
	ta := setupApp(t, "", "", false)
	ta.IO.TTY = false
	before, _ := os.ReadFile(ta.ConfigPath)
	useGateway(ta)
	wantErr(t, ta.Setup(bg, SetupOptions{SkipImages: true}), "there is no terminal; pass --yes to accept the defaults, or --non-interactive")
	if len(ta.gateway.planned) != 0 || ta.gateway.applied != 0 {
		t.Fatalf("gateway plans = %+v, applied %d; want none", ta.gateway.planned, ta.gateway.applied)
	}
	if after, _ := os.ReadFile(ta.ConfigPath); string(after) != string(before) {
		t.Fatalf("the configuration changed:\n%s", after)
	}
}

func TestSetupNeedsConsentToInstall(t *testing.T) {
	ta := setupApp(t, "", "", false)
	ta.IO.TTY = false
	missing := hostReport(func(r *openshell.DoctorReport) {
		r.CLIVersion = ""
		r.Get(openshell.CheckIDCLI).Status = openshell.StatusFail
	})
	ta.HostDoctor = missing
	wantErr(t, ta.Setup(bg, SetupOptions{NonInteractive: true}), "--install-openshell")
	has(t, ta.output(), "✗ OpenShell not installed")
	inst := &fakeInstaller{}
	ta.Installer = func(consent func(*openshell.InstallPlan) (bool, error)) Installer {
		inst.consent = consent
		return inst
	}
	calls := 0
	ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		if calls++; calls == 1 {
			return missing(ctx, d)
		}
		return hostReport(nil)(ctx, d)
	}
	ta.ok(t, ta.Setup(bg, SetupOptions{NonInteractive: true, InstallOpenShell: true, SkipImages: true}))
	if !inst.ran {
		t.Fatal("the installer did not run")
	}
}

// TestSetupSaysWhatToDoWhenHomebrewFails: on macOS the installer fails when
// Homebrew refuses the nvidia/openshell formula (an Xcode older than it
// wants), and setup said only "install OpenShell: openshell: installer
// failed: /bin/sh: exit status 1"; it names Homebrew and the next step
// (manual test M6).
func TestSetupSaysWhatToDoWhenHomebrewFails(t *testing.T) {
	ta := setupApp(t, "", "", false)
	ta.GOOS = "darwin"
	ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) {
		r.CLIVersion = ""
		r.Get(openshell.CheckIDCLI).Status = openshell.StatusFail
	})
	inst := &fakeInstaller{err: fmt.Errorf("%w (/bin/sh: exit status 1)", openshell.ErrHomebrewInstall)}
	ta.Installer = func(consent func(*openshell.InstallPlan) (bool, error)) Installer {
		inst.consent = consent
		return inst
	}
	err := ta.Setup(bg, SetupOptions{NonInteractive: true, InstallOpenShell: true, SkipImages: true})
	var silent *Silent
	if !errors.As(err, &silent) || !errors.Is(err, openshell.ErrHomebrewInstall) {
		t.Fatalf("Setup = %v, want the Homebrew failure, already printed", err)
	}
	has(t, ta.output(), "✗ install OpenShell: Homebrew could not install the nvidia/openshell formula\n",
		"Homebrew says why above; most often Xcode or the Command Line Tools are older than it wants",
		"then run `defenseclaw sandbox setup` again", "docs/setup/sandbox/#troubleshooting")
}

// TestSetupInstallQuestionSaysHowItInstalls: NVIDIA's installer uses sudo
// on Linux and installs a Homebrew formula on macOS, and the install
// question says which (manual test M5).
func TestSetupInstallQuestionSaysHowItInstalls(t *testing.T) {
	for goos, want := range map[string]string{"linux": "(sudo; sha256 verified) [y/N]", "darwin": "(Homebrew; sha256 verified) [y/N]"} {
		// A Mac is asked about MicroVMs first.
		input := map[string]string{"linux": "n\n", "darwin": "y\nn\n"}[goos]
		ta := setupApp(t, input, "", false)
		ta.GOOS = goos
		ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) {
			r.CLIVersion = ""
			r.Get(openshell.CheckIDCLI).Status = openshell.StatusFail
		})
		wantErr(t, ta.Setup(bg, SetupOptions{}), "OpenShell 0.1.1 is needed")
		has(t, ta.output(), "Install OpenShell 0.1.1 with NVIDIA's installer? "+want)
	}
}

// TestSetupNamesTheHomebrewGatewayItNeeds: on a Mac with OpenShell
// installed from the release binaries (gateway healthy and registered),
// setup showed "✓ OpenShell 0.1.1", asked to install it again, and on "n"
// said "OpenShell 0.1.1 is needed" (manual test M9). The installer would
// find that CLI and change nothing; what is missing is the Homebrew
// formula whose service DefenseClaw restarts the gateway through.
func TestSetupNamesTheHomebrewGatewayItNeeds(t *testing.T) {
	notBrew := hostReport(func(r *openshell.DoctorReport) {
		c := r.Get(openshell.CheckIDGatewayService)
		c.Status, c.Detail = openshell.StatusFail, openshell.GatewayFormula+" is not installed"
		r.Service = &openshell.ServiceState{Manager: "brew", Unit: openshell.GatewayFormula}
	})
	ta := setupApp(t, "y\n", "", false)
	ta.GOOS = "darwin"
	ta.HostDoctor = notBrew
	inst := &fakeInstaller{}
	ta.Installer = func(consent func(*openshell.InstallPlan) (bool, error)) Installer {
		inst.consent = consent
		return inst
	}
	wantErr(t, ta.Setup(bg, SetupOptions{}), "on macOS OpenShell must come from the nvidia/openshell/openshell Homebrew formula")
	// The machine line marks the OpenShell setup refuses on the next line,
	// as the TUI's machine check does (RT-A-1: it showed "✓ OpenShell
	// 0.1.1").
	has(t, ta.output(), "  ✗ OpenShell 0.1.1 is not from Homebrew's nvidia/openshell formula\n",
		"✗ Gateway service: the nvidia/openshell/openshell Homebrew formula is not installed\n",
		"→ on macOS DefenseClaw starts and restarts the OpenShell gateway through that formula's service. The OpenShell 0.1.1 found here "+
			"was installed another way, so DefenseClaw cannot restart its gateway: stop that gateway and remove that OpenShell, "+
			"then run `defenseclaw sandbox setup --install-openshell`")
	lacks(t, ta.output(), "Install OpenShell", "is needed", "✓ OpenShell")
	if inst.ran {
		t.Fatal("the installer ran")
	}
	// On Linux the systemd unit is what the package installs: setup offers it.
	ta = setupApp(t, "n\n", "", false)
	ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) {
		c := r.Get(openshell.CheckIDGatewayService)
		c.Status, c.Detail = openshell.StatusFail, "openshell-gateway is not installed"
		r.Service = &openshell.ServiceState{Manager: "systemd", Unit: openshell.GatewayService}
	})
	wantErr(t, ta.Setup(bg, SetupOptions{}), "OpenShell 0.1.1 is needed")
	has(t, ta.output(), "✓ OpenShell 0.1.1\n", "Install OpenShell 0.1.1 with NVIDIA's installer? (sudo; sha256 verified) [y/N]")
	lacks(t, ta.output(), "not from Homebrew")
}

func TestSetupStopsOnHostFailure(t *testing.T) {
	ta := setupApp(t, "", "", false)
	before, _ := os.ReadFile(ta.ConfigPath)
	ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) {
		c := r.Get(openshell.CheckIDLandlock)
		c.Status, c.Detail = openshell.StatusFail, "ABI 1 is older than 3"
	})
	wantErr(t, ta.Setup(bg, SetupOptions{NonInteractive: true}), "Landlock")
	if after, _ := os.ReadFile(ta.ConfigPath); string(after) != string(before) {
		t.Fatal("a failed setup changed config.yaml")
	}
}

// macHost is a doctor report of a Mac whose Docker Desktop VM's Landlock
// check came out as landlock says, without OpenShell yet.
func macHost(landlock openshell.Check) func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
	return hostReport(func(r *openshell.DoctorReport) {
		r.CLIVersion, r.DockerVersion = "", "29.1.5"
		r.Get(openshell.CheckIDPlatform).Status, r.Get(openshell.CheckIDPlatform).Detail = openshell.StatusWarn, "darwin/arm64: macOS sandboxes run on Docker Desktop and are a preview"
		r.Get(openshell.CheckIDCLI).Status = openshell.StatusFail
		*r.Get(openshell.CheckIDLandlock) = landlock
	})
}

var (
	// noLandlockInTheVM is the Landlock check on Docker Desktop 29.1.5.
	noLandlockInTheVM = openshell.Check{ID: openshell.CheckIDLandlock, Title: "Landlock", Status: openshell.StatusFail,
		Detail: "Docker Desktop's Linux VM (kernel 6.12.65-linuxkit) has no Landlock, and OpenShell sandboxes need it",
		Fix: &openshell.Fix{Summary: "macOS sandboxes cannot run on Docker Desktop's kernel: run them in OpenShell MicroVMs, which have their own " +
			"(`defenseclaw sandbox setup` switches the gateway to them; details in the sandbox guide)", Command: openshell.TroubleshootingURL}}
	landlockNotChecked = "not checked: sandboxes run on the kernel of Docker Desktop's Linux VM, which DefenseClaw checks in the OpenShell base image, and that image is not on this machine yet"
)

// TestSetupChecksTheDockerVMBeforeInstalling: on a Mac setup installed
// OpenShell and built images although no sandbox could start, Docker
// Desktop's Linux VM having no Landlock (manual test M12). When the user
// keeps the docker driver (no to MicroVMs), setup stops at the machine
// check with the doctor's reason; when there is no image yet to check the
// VM in, it downloads the base image the harness images need anyway, with
// consent, and checks again before it installs anything.
func TestSetupChecksTheDockerVMBeforeInstalling(t *testing.T) {
	install := func(ta *testApp) *fakeInstaller {
		inst := &fakeInstaller{}
		ta.Installer = func(consent func(*openshell.InstallPlan) (bool, error)) Installer {
			inst.consent = consent
			return inst
		}
		return inst
	}
	unchecked := func(pulled *int) openshell.Check {
		return openshell.Check{ID: openshell.CheckIDLandlock, Title: "Landlock", Status: openshell.StatusWarn, Detail: landlockNotChecked,
			Fix: &openshell.Fix{Summary: "download the OpenShell base image", Automatic: true, Apply: func(context.Context) error { *pulled++; return nil }}}
	}

	t.Run("no Landlock in the VM", func(t *testing.T) {
		ta := setupApp(t, "n\n", "", false)
		ta.GOOS = "darwin"
		ta.HostDoctor = macHost(noLandlockInTheVM)
		inst := install(ta)
		wantErr(t, ta.Setup(bg, SetupOptions{InstallOpenShell: true}), "this machine cannot run sandboxes yet (Landlock)")
		has(t, ta.output(), "Checking this machine…  ✓ darwin/arm64  ✗ Landlock  ✓ Docker 29.1.5  ✗ OpenShell not installed\n",
			"Run sandboxes in OpenShell MicroVMs?",
			"✗ Landlock: Docker Desktop's Linux VM (kernel 6.12.65-linuxkit) has no Landlock, and OpenShell sandboxes need it\n",
			"→ macOS sandboxes cannot run on Docker Desktop's kernel: run them in OpenShell MicroVMs, which have their own "+
				"(`defenseclaw sandbox setup` switches the gateway to them; details in the sandbox guide) "+openshell.TroubleshootingURL)
		if inst.ran || len(ta.images.built) != 0 || len(ta.gateway.planned) != 0 {
			t.Fatalf("setup went on: installed %v, built %v, gateway plans %v", inst.ran, ta.images.built, ta.gateway.planned)
		}
	})

	t.Run("downloads the base image to check the VM", func(t *testing.T) {
		ta := setupApp(t, "n\ny\n", "", false)
		ta.GOOS = "darwin"
		pulled, runs := 0, 0
		ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
			if runs++; pulled == 0 {
				return macHost(unchecked(&pulled))(ctx, d)
			}
			return macHost(noLandlockInTheVM)(ctx, d)
		}
		inst := install(ta)
		wantErr(t, ta.Setup(bg, SetupOptions{}), "this machine cannot run sandboxes yet (Landlock)")
		has(t, ta.output(), "Checking this machine…  ✓ darwin/arm64  ⚠ Landlock not checked  ✓ Docker 29.1.5  ✗ OpenShell not installed\n",
			"Download the OpenShell base image now to check Docker Desktop's Linux VM for Landlock? (about 4 GB; the harness images are built on it) [Y/n]",
			"Downloading the OpenShell base image (about 4 GB)…",
			"Checking this machine again…  ✓ darwin/arm64  ✗ Landlock  ✓ Docker 29.1.5",
			"✗ Landlock: Docker Desktop's Linux VM (kernel 6.12.65-linuxkit) has no Landlock")
		if pulled != 1 || runs != 2 || inst.ran {
			t.Fatalf("pulled %d, doctor runs %d, installed %v", pulled, runs, inst.ran)
		}
	})

	t.Run("goes on unchecked without the images", func(t *testing.T) {
		ta := setupApp(t, "n\n", "", true)
		ta.GOOS = "darwin"
		pulled := 0
		ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) { *r.Get(openshell.CheckIDLandlock) = unchecked(&pulled) })
		ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
		lacks(t, ta.output(), "Download the OpenShell base image now")
		has(t, ta.output(), "⚠ Landlock: "+landlockNotChecked,
			"skipped: checking Docker Desktop's Linux VM for Landlock (`defenseclaw sandbox doctor --fix` downloads the base image and checks it)")
		if pulled != 0 {
			t.Fatal("pulled the base image with --skip-images")
		}

		// A probe that failed says why, and nothing downloads.
		ta = setupApp(t, "n\n", "", true)
		ta.GOOS = "darwin"
		failed := "could not check Docker Desktop's Linux VM (kernel 6.12.65-linuxkit): landlock_create_ruleset failed with errno 1 EPERM"
		ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) {
			c := r.Get(openshell.CheckIDLandlock)
			c.Status, c.Detail = openshell.StatusWarn, failed
		})
		ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
		has(t, ta.output(), "⚠ Landlock not checked", "⚠ Landlock: "+failed)
		lacks(t, ta.output(), "Download the OpenShell base image now", "skipped: checking Docker Desktop's Linux VM")
	})

	t.Run("checks in the images it built", func(t *testing.T) {
		ta := setupApp(t, "", "", true)
		ta.images.recs = []image.Record{{Tag: "defenseclaw/sandbox:claudecode-1a2b"}}
		var probe []string
		ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
			probe = d.ProbeImages
			return hostReport(nil)(ctx, d)
		}
		ta.ok(t, ta.Setup(bg, SetupOptions{NonInteractive: true, SkipImages: true, NoWrappers: true}))
		if !slices.Equal(probe, []string{"defenseclaw/sandbox:claudecode-1a2b"}) {
			t.Fatalf("probe images = %v", probe)
		}
	})
}

func TestSetupCopyOnlyWithoutMounts(t *testing.T) {
	ta := setupApp(t, "", "", false)
	ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
	ta.ok(t, ta.Setup(bg, SetupOptions{NonInteractive: true, NoMounts: true, SkipImages: true, Harnesses: []string{"codex"}}))
	if len(ta.gateway.planned) != 0 {
		t.Fatalf("gateway changed without need: %+v", ta.gateway.planned)
	}
	c := loadConfig(t, ta)
	if c.OpenShell.Workdir.Mode != "copy" || !slices.Equal(c.OpenShell.Harnesses, []string{"codex"}) {
		t.Fatalf("config = %+v", c.OpenShell)
	}
	// Setup again, allowing the mounts this time: the copy mode the first
	// setup recorded goes, so the answer takes effect.
	ta.Cfg.OpenShell.Workdir.Mode = c.OpenShell.Workdir.Mode
	ta.gateway.applyRes = &openshell.GatewayApplyResult{}
	again := SetupOptions{NonInteractive: true, Yes: true, SkipImages: true, Harnesses: []string{"codex"}}
	ta.ok(t, ta.Setup(bg, again))
	if len(ta.gateway.planned) != 1 || !ta.gateway.planned[0].EnableBindMounts {
		t.Fatalf("gateway plans = %+v", ta.gateway.planned)
	}
	if c := loadConfig(t, ta); c.OpenShell.Workdir.Mode != "" {
		t.Fatalf("workdir.mode after allowing mounts = %q, want the pack's", c.OpenShell.Workdir.Mode)
	}
	// Mounts already on and a copy mode in the config: setup says why runs
	// still copy.
	ta.gateway.state.BindMounts = mountsOn
	ta.Cfg.OpenShell.Workdir.Mode = "copy"
	ta.ok(t, ta.Setup(bg, again))
	has(t, ta.output(), "openshell.workdir.mode is copy")
}

// macReport is a doctor report of an Apple-silicon Mac, ready for the
// MicroVM driver (e2fsprogs installed, the driver signed), whose gateway
// runs driver; edit adjusts it.
func macReport(driver openshell.ComputeDriver, edit func(*openshell.DoctorReport)) func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
	return hostReport(func(r *openshell.DoctorReport) {
		r.DockerVersion = "29.1.5"
		c := r.Get(openshell.CheckIDPlatform)
		c.Status, c.Detail = openshell.StatusWarn, "darwin/arm64: macOS sandboxes run in OpenShell MicroVMs (the vm driver, experimental upstream)"
		r.Driver, r.ConfiguredDriver = driver, driver
		r.MicroVM = &openshell.MicroVMHost{E2fsprogs: "/opt/homebrew/opt/e2fsprogs/sbin", DriverBinary: "/opt/homebrew/opt/openshell/libexec/openshell-driver-vm",
			DriverFromFormula: true, HypervisorSigned: true, Identity: openshell.VMIdentity{UID: 501, GID: 20}, Recommended: openshell.VMResources{VCPUs: 4, MemMiB: 4096, OverlayDiskMiB: 16384}}
		r.Checks = slices.Insert(r.Checks, 4, openshell.Check{ID: openshell.CheckIDVMDriver, Title: "MicroVM driver", Status: openshell.StatusPass})
		if driver == openshell.DriverVM {
			*r.Get(openshell.CheckIDLandlock) = openshell.Check{ID: openshell.CheckIDLandlock, Title: "Landlock", Status: openshell.StatusPass,
				Detail: "enforced by the MicroVM's own kernel; OpenShell refuses to start a sandbox without it (hard requirement)"}
		}
		if edit != nil {
			edit(r)
		}
	})
}

// emptyPlans is a gateway whose configuration already holds every change
// asked for.
type emptyPlans struct{ *fakeGateway }

func (g emptyPlans) Plan(ctx context.Context, ch openshell.GatewayChanges) (*openshell.GatewayPlan, error) {
	_, _ = g.fakeGateway.Plan(ctx, ch)
	return &openshell.GatewayPlan{Restart: "brew services restart nvidia/openshell/openshell"}, nil
}

// TestSetupOnMacOSPlansMicroVMsNotBindMounts: on a Mac setup asks about
// MicroVMs, not bind mounts, and plans the vm driver with this user as
// every sandbox's and the recommended resources where the configuration
// has none, in one plan and one restart. It still changes OpenShell's
// telemetry only through the systemd unit: on macOS it neither asks about
// it nor edits gateway.env for it, and says how to turn it off (manual
// test M8).
func TestSetupOnMacOSPlansMicroVMsNotBindMounts(t *testing.T) {
	const note = "OpenShell's anonymous usage telemetry stays on: setup turns it off on Linux only. To turn it off here, set " +
		"OPENSHELL_TELEMETRY_ENABLED=false in ~/.config/openshell/gateway.env, which the Homebrew service reads, and restart the gateway " +
		"(`brew services restart nvidia/openshell/openshell`)"
	for _, upstream := range []bool{false, true} {
		// On a terminal: the MicroVM question; no sandbox runs, so the
		// restart is not asked.
		ta := setupApp(t, "y\n", "", false)
		ta.GOOS = "darwin"
		ta.HostDoctor = macReport(openshell.DriverDocker, nil)
		ta.gateway.state.EnvPath = filepath.Join(ta.home, ".config", "openshell", "gateway.env")
		ta.gateway.state.TOMLPath = filepath.Join(ta.home, ".config", "openshell", "gateway.toml")
		mem := int64(8192)
		ta.gateway.state.VM.MemMiB = &mem
		ta.gateway.applyRes = &openshell.GatewayApplyResult{}
		_, _ = useGateway(ta)
		ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true, UpstreamTelemetry: upstream}))
		p := ta.gateway.planned
		if len(p) != 1 || p[0].EnableBindMounts || p[0].ComputeDriver != openshell.DriverVM || len(p[0].Env) != 0 || len(p[0].UnsetEnv) != 0 ||
			p[0].VMIdentity == nil || *p[0].VMIdentity != (openshell.VMIdentity{UID: 501, GID: 20}) ||
			p[0].VMResources == nil || *p[0].VMResources != (openshell.VMResources{VCPUs: 4, OverlayDiskMiB: 16384}) || ta.gateway.applied != 1 {
			t.Fatalf("upstream %t: gateway plans = %+v, applied %d", upstream, p, ta.gateway.applied)
		}
		has(t, ta.output(), `Run sandboxes in OpenShell MicroVMs? macOS needs them: Docker Desktop's Linux kernel has no Landlock. `+
			`(sets compute_driver = "vm" in ~/.config/openshell/gateway.toml and restarts the gateway; OpenShell calls this driver experimental) [Y/n]`,
			"sandbox_uid and sandbox_gid are gateway-wide: every MicroVM sandbox on this gateway, including ones made outside DefenseClaw "+
				"with `openshell sandbox create`, then runs as 501:20",
			"✓ gateway configured and restarted: it runs sandboxes in OpenShell MicroVMs",
			"every run works on a copy (the MicroVM driver mounts no host folders); `defenseclaw sandbox pull` brings the changes back")
		lacks(t, ta.output(), "Allow sandboxes to mount", "Disable OpenShell's anonymous usage telemetry?", "does not read gateway.env",
			"Download the OpenShell base image")
		if shown := strings.Contains(ta.output(), note); shown == upstream {
			t.Fatalf("upstream %t: telemetry note shown = %t:\n%s", upstream, shown, ta.output())
		}
		// The driver clamps runs to a copy: the mode is not recorded.
		if c := loadConfig(t, ta); c.OpenShell.Workdir.Mode != "" {
			t.Fatalf("workdir.mode = %q, want none", c.OpenShell.Workdir.Mode)
		}
	}
}

// TestSetupSwitchesADockerDesktopMacToMicroVMs: a fresh Mac on Docker
// Desktop, whose Linux VM has no Landlock, still reaches the MicroVM
// question instead of stopping at the machine check; --yes and
// --non-interactive take its default, yes.
func TestSetupSwitchesADockerDesktopMacToMicroVMs(t *testing.T) {
	for _, o := range []SetupOptions{{NonInteractive: true}, {Yes: true}} {
		ta := setupApp(t, "", "", false)
		ta.IO.TTY = false
		ta.GOOS = "darwin"
		ta.HostDoctor = macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) { *r.Get(openshell.CheckIDLandlock) = noLandlockInTheVM })
		ta.gateway.applyRes = &openshell.GatewayApplyResult{}
		_, _ = useGateway(ta)
		o.SkipImages, o.NoWrappers = true, true
		ta.ok(t, ta.Setup(bg, o))
		has(t, ta.output(), "✓ darwin/arm64  ✗ Landlock  ✓ Docker 29.1.5  ✓ MicroVM driver  ✓ OpenShell 0.1.1\n",
			"Landlock: Docker Desktop's Linux VM (kernel 6.12.65-linuxkit) has no Landlock, and OpenShell sandboxes need it; MicroVMs have their own kernel, which enforces it")
		lacks(t, ta.output(), "✗ Landlock:", "cannot run sandboxes yet")
		if p := ta.gateway.planned; len(p) != 1 || p[0].ComputeDriver != openshell.DriverVM || ta.gateway.applied != 1 {
			t.Fatalf("%+v: gateway plans = %+v, applied %d", o, p, ta.gateway.applied)
		}
	}
}

// TestSetupWaitsForTheDaemonToDriveMicroVMs: the daemon learns that the
// gateway switched drivers when it next asks the gateway, so setup waits
// for its status to name the MicroVM driver, and says so when it never
// does.
func TestSetupWaitsForTheDaemonToDriveMicroVMs(t *testing.T) {
	for _, notices := range []bool{true, false} {
		ta := setupApp(t, "", "", false)
		ta.IO.TTY = false
		ta.GOOS = "darwin"
		ta.HostDoctor = macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) { *r.Get(openshell.CheckIDLandlock) = noLandlockInTheVM })
		ta.gateway.applyRes = &openshell.GatewayApplyResult{}
		_, _ = useGateway(ta)
		polls := 0
		ta.daemon.status.Gateway = &sandboxapi.Gateway{Name: "openshell", Driver: "docker"}
		ta.daemon.onStatus = func(st *sandboxapi.Status) {
			if polls++; notices && polls > 3 {
				st.Gateway.Driver = "vm"
			}
		}
		ta.ok(t, ta.Setup(bg, SetupOptions{Yes: true, SkipImages: true, NoWrappers: true}))
		const stale = "the daemon still drives the OpenShell gateway as the docker driver, not vm"
		if notices {
			has(t, ta.output(), "the daemon runs the sandbox subsystem")
			lacks(t, ta.output(), stale)
			continue
		}
		has(t, ta.output(), stale)
		lacks(t, ta.output(), "the daemon runs the sandbox subsystem")
	}
}

// TestSetupSaysASwitchNotAppliedLeavesDocker: a switch waits for the
// gateway restart, which --yes does not give while a sandbox runs on the
// gateway. Setup then does not say every run works on a copy in a
// MicroVM, or that it is done: on Docker Desktop no sandbox can start
// until the gateway runs MicroVMs.
func TestSetupSaysASwitchNotAppliedLeavesDocker(t *testing.T) {
	ta := setupApp(t, "", "", false)
	ta.IO.TTY = false
	ta.GOOS = "darwin"
	ta.HostDoctor = macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) { *r.Get(openshell.CheckIDLandlock) = noLandlockInTheVM })
	ta.gateway.applyRes = &openshell.GatewayApplyResult{}
	runningOn(t, ta, 1)
	ta.ok(t, ta.Setup(bg, SetupOptions{Yes: true, SkipImages: true, NoWrappers: true}))
	if ta.gateway.applied != 0 || ta.gateway.restarts != 0 {
		t.Fatalf("applied %d, restarts %d", ta.gateway.applied, ta.gateway.restarts)
	}
	has(t, ta.output(), "the gateway still runs the docker driver, where no sandbox can start (the Linux VM Docker runs in has no Landlock); "+
		"it runs sandboxes in MicroVMs once it restarts on them",
		"skipped: the OpenShell gateway change above",
		"not ready for sandboxes yet: restart the OpenShell gateway on the MicroVM driver (`defenseclaw sandbox setup --restart-gateway`)")
	lacks(t, ta.output(), "every run works on a copy (the MicroVM driver", "prepares its MicroVM disk", "Done →")

	// With --restart-gateway the switch is applied.
	ta = setupApp(t, "", "", false)
	ta.IO.TTY = false
	ta.GOOS = "darwin"
	ta.HostDoctor = macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) { *r.Get(openshell.CheckIDLandlock) = noLandlockInTheVM })
	ta.gateway.applyRes = &openshell.GatewayApplyResult{}
	runningOn(t, ta, 1)
	ta.ok(t, ta.Setup(bg, SetupOptions{Yes: true, RestartGateway: true, NoWrappers: true, SkipImages: true}))
	has(t, ta.output(), "every run works on a copy (the MicroVM driver", "Done →")
	lacks(t, ta.output(), "still runs the docker driver", "not ready for sandboxes yet")
}

// TestSetupOnAMacAlreadyOnMicroVMs asks nothing about the driver or
// mounts, and restarts nothing when the configuration is current; a
// configuration that selects MicroVMs on a gateway not restarted since
// is restarted, with consent.
func TestSetupOnAMacAlreadyOnMicroVMs(t *testing.T) {
	ta := setupApp(t, "", "", false)
	ta.GOOS = "darwin"
	ta.App.Gateway = emptyPlans{ta.gateway}
	ta.HostDoctor = macReport(openshell.DriverVM, nil)
	ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
	has(t, ta.output(), "✓ darwin/arm64  ✓ Landlock (MicroVM)  ✓ Docker 29.1.5  ✓ MicroVM driver  ✓ OpenShell 0.1.1\n",
		"every run works on a copy (the MicroVM driver mounts no host folders)",
		"the first run of each image prepares its MicroVM disk")
	lacks(t, ta.output(), "Run sandboxes in OpenShell MicroVMs?", "Allow sandboxes to mount", "Restart the OpenShell gateway")
	if len(ta.gateway.planned) != 1 || ta.gateway.applied != 0 || ta.gateway.restarts != 0 {
		t.Fatalf("plans %+v, applied %d, restarts %d", ta.gateway.planned, ta.gateway.applied, ta.gateway.restarts)
	}

	// Configured, not running yet: one restart, asked about when a
	// sandbox runs on the gateway.
	ta = setupApp(t, "\ny\n", "", false)
	ta.GOOS = "darwin"
	ta.App.Gateway = emptyPlans{ta.gateway}
	ta.HostDoctor = macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) { r.ConfiguredDriver = openshell.DriverVM })
	runningOn(t, ta, 1)
	ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
	has(t, ta.output(), "the gateway configuration already selects the MicroVM driver; the gateway has not been restarted on it",
		"the 1 sandbox on it (dc-claude-theirs-a) were made on the docker driver", "Restart the OpenShell gateway now? [y/N]",
		"✓ gateway restarted: it runs sandboxes in OpenShell MicroVMs")
	if ta.gateway.restarts != 1 || ta.gateway.applied != 0 {
		t.Fatalf("restarts %d, applied %d", ta.gateway.restarts, ta.gateway.applied)
	}
}

// Setup builds the images for the driver it sets the gateway up on: on a
// Mac the MicroVM ones, which answer localhost themselves, also when the
// gateway has not restarted on the vm driver yet; on Linux the docker ones.
func TestSetupBuildsTheImagesForItsDriver(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mac     bool
		driver  openshell.ComputeDriver
		microVM bool
	}{
		{"linux", false, openshell.DriverDocker, false},
		{"mac on MicroVMs", true, openshell.DriverVM, true},
		{"mac switching to MicroVMs", true, openshell.DriverDocker, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := setupApp(t, "", "", false)
			ta.IO.TTY = false
			if tc.mac {
				ta.GOOS = "darwin"
				ta.App.Gateway = emptyPlans{ta.gateway}
				ta.HostDoctor = macReport(tc.driver, nil)
			}
			ta.gateway.applyRes = &openshell.GatewayApplyResult{}
			_, _ = useGateway(ta)
			ta.ok(t, ta.Setup(bg, SetupOptions{Yes: true, NoWrappers: true, Harnesses: []string{"claude"}}))
			if len(ta.images.recs) != 1 || ta.images.recs[0].MicroVM != tc.microVM {
				t.Fatalf("built %+v, want MicroVM=%t:\n%s", ta.images.recs, tc.microVM, ta.output())
			}
		})
	}
}

// TestSetupInstallsWhatTheMicroVMDriverNeeds: e2fsprogs and the driver's
// Hypervisor signature follow the OpenShell install's consent: a question
// (no by default) on a terminal, yes with --yes or --install-openshell,
// nothing installed with --non-interactive alone, and a no stops setup
// with the command to run.
func TestSetupInstallsWhatTheMicroVMDriverNeeds(t *testing.T) {
	missing := func(inst *fakeInstaller) func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
		return macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) {
			m := r.MicroVM
			if inst.e2fsprogs == 0 {
				m.E2fsprogs = ""
			}
			if inst.resigned == 0 {
				m.HypervisorSigned = false
			}
		})
	}
	setup := func(t *testing.T, input string) (*testApp, *fakeInstaller) {
		ta := setupApp(t, input, "", false)
		ta.GOOS = "darwin"
		inst := &fakeInstaller{}
		ta.Installer = func(func(*openshell.InstallPlan) (bool, error)) Installer { return inst }
		ta.HostDoctor = missing(inst)
		ta.gateway.applyRes = &openshell.GatewayApplyResult{}
		_, _ = useGateway(ta)
		return ta, inst
	}
	const (
		e2fsprogs = "Install e2fsprogs with Homebrew? The MicroVM driver formats its disks with it (brew install e2fsprogs) [y/N]"
		resign    = "Re-run the OpenShell formula's post-install step so its MicroVM driver is signed for Apple's Hypervisor? " +
			"(brew postinstall nvidia/openshell/openshell) [y/N]"
	)

	ta, inst := setup(t, "y\ny\ny\n")
	ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
	has(t, ta.output(), e2fsprogs, "✓ e2fsprogs installed", resign, "✓ MicroVM driver signed for Apple's Hypervisor")
	if inst.e2fsprogs != 1 || inst.resigned != 1 || len(ta.gateway.planned) != 1 {
		t.Fatalf("e2fsprogs %d, resigned %d, plans %+v", inst.e2fsprogs, inst.resigned, ta.gateway.planned)
	}

	for _, o := range []SetupOptions{{Yes: true}, {InstallOpenShell: true, NonInteractive: true}} {
		ta, inst = setup(t, "")
		o.SkipImages, o.NoWrappers = true, true
		ta.ok(t, ta.Setup(bg, o))
		lacks(t, ta.output(), e2fsprogs, resign)
		if inst.e2fsprogs != 1 || inst.resigned != 1 {
			t.Fatalf("%+v: e2fsprogs %d, resigned %d", o, inst.e2fsprogs, inst.resigned)
		}
	}

	// --non-interactive alone installs no software.
	ta, inst = setup(t, "")
	ta.IO.TTY = false
	wantErr(t, ta.Setup(bg, SetupOptions{NonInteractive: true, SkipImages: true}), "the OpenShell MicroVM driver needs e2fsprogs")
	has(t, ta.output(), "✗ MicroVM driver: e2fsprogs, which it formats its disks with", "→ run `brew install e2fsprogs`, then `defenseclaw sandbox setup` again")
	if inst.e2fsprogs != 0 || len(ta.gateway.planned) != 0 {
		t.Fatalf("installed %d, plans %+v", inst.e2fsprogs, ta.gateway.planned)
	}

	// A no stops setup before the gateway changes.
	ta, inst = setup(t, "y\ny\nn\n")
	wantErr(t, ta.Setup(bg, SetupOptions{SkipImages: true}), "the OpenShell MicroVM driver needs /opt/homebrew/opt/openshell/libexec/openshell-driver-vm signed")
	has(t, ta.output(), "→ run `brew postinstall nvidia/openshell/openshell`, then `defenseclaw sandbox setup` again")
	if inst.e2fsprogs != 1 || inst.resigned != 0 || len(ta.gateway.planned) != 0 {
		t.Fatalf("e2fsprogs %d, resigned %d, plans %+v", inst.e2fsprogs, inst.resigned, ta.gateway.planned)
	}

	// The formula's post-install step signs only its own driver: for one
	// elsewhere setup neither asks nor runs it, and names that binary.
	ta, inst = setup(t, "")
	ta.HostDoctor = macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) {
		r.MicroVM.DriverBinary, r.MicroVM.DriverFromFormula, r.MicroVM.HypervisorSigned = "/opt/openshell/libexec/openshell-driver-vm", false, false
	})
	wantErr(t, ta.Setup(bg, SetupOptions{Yes: true, SkipImages: true}), "the OpenShell MicroVM driver needs /opt/openshell/libexec/openshell-driver-vm signed")
	has(t, ta.output(), "✗ MicroVM driver: /opt/openshell/libexec/openshell-driver-vm is not signed for Apple's Hypervisor",
		"→ sign /opt/openshell/libexec/openshell-driver-vm with the com.apple.security.hypervisor entitlement")
	lacks(t, ta.output(), resign)
	if inst.resigned != 0 || len(ta.gateway.planned) != 0 {
		t.Fatalf("resigned %d, plans %+v", inst.resigned, ta.gateway.planned)
	}
}

// TestSetupListsTheSandboxesASwitchStrands: before the switch, setup
// names DefenseClaw's sandboxes, which after it can neither start nor so
// be pulled; the restart consent names every sandbox on the gateway, of
// every owner, and no by default leaves the gateway alone.
func TestSetupListsTheSandboxesASwitchStrands(t *testing.T) {
	for _, tc := range []struct {
		landlock openshell.Check
		want     string
	}{
		{noLandlockInTheVM, "2 sandboxes were made on the docker driver and never ran here (dc-a, dc-b); after the switch they can only be deleted " +
			"(`defenseclaw sandbox delete NAME`)"},
		{openshell.Check{ID: openshell.CheckIDLandlock, Title: "Landlock", Status: openshell.StatusPass, Detail: "ABI 6 in the Linux VM Docker runs in"},
			"2 sandboxes run on the docker driver (dc-a, dc-b): pull their work now (`defenseclaw sandbox pull NAME`); after the switch it is reachable only by switching back"},
	} {
		ta := newTestApp(t, "\n\n", sandboxapi.Sandbox{Name: "dc-b"}, sandboxapi.Sandbox{Name: "dc-a"})
		writeConfig(t, ta, "")
		ta.GOOS = "darwin"
		ta.HostDoctor = macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) { *r.Get(openshell.CheckIDLandlock) = tc.landlock })
		fake, client := useGateway(ta)
		for _, name := range []string{"dc-a", "theirs"} {
			if _, err := client.CreateSandbox(bg, name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		_ = fake
		ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
		out := ta.output()
		has(t, out, tc.want, "the 2 sandboxes on it (dc-a, theirs) were made on the docker driver, stop if running, and cannot start again "+
			"unless the gateway is switched back", "Restart the OpenShell gateway now? [y/N]",
			"skipped: the OpenShell gateway change above")
		if strings.Index(out, tc.want) > strings.Index(out, "Run sandboxes in OpenShell MicroVMs?") {
			t.Fatalf("the sandboxes were listed after the question:\n%s", out)
		}
		if ta.gateway.applied != 0 {
			t.Fatalf("applied %d without consent", ta.gateway.applied)
		}
	}
}

// TestSetupTelemetryQuestionSaysItRestartsTheGateway pins that the
// telemetry question says, before it is answered, that a yes edits
// gateway.env and restarts the shared gateway, with what runs on it (manual
// test R2-31). A saved openshell.upstream_telemetry: true (an earlier "keep
// it") is not asked again, and not overwritten (R2-67).
func TestSetupTelemetryQuestionSaysItRestartsTheGateway(t *testing.T) {
	for _, tc := range []struct {
		running, applied int
		want             string
	}{
		{0, 1, "; no sandbox runs on it now) [Y/n]"},
		// The restart question that follows answers no by default.
		{2, 0, ", which drops the connections of the 2 sandboxes running on it) [Y/n]"},
	} {
		// The telemetry question (yes), then, with sandboxes running, the
		// restart (no).
		ta := setupApp(t, "\n\n", "", false)
		ta.gateway.state.BindMounts = mountsOn
		ta.gateway.state.EnvPath = filepath.Join(ta.home, ".config", "openshell", "gateway.env")
		runningOn(t, ta, tc.running)
		ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
		has(t, ta.output(), "Disable OpenShell's anonymous usage telemetry? (edits ~/.config/openshell/gateway.env and restarts the OpenShell gateway"+tc.want)
		if len(ta.gateway.planned) != 1 || ta.gateway.planned[0].Env[openshell.EnvTelemetryEnabled] != "false" || ta.gateway.applied != tc.applied {
			t.Fatalf("%d running: gateway plans = %+v, applied %d", tc.running, ta.gateway.planned, ta.gateway.applied)
		}
	}
	ta := setupApp(t, "", "  upstream_telemetry: true\n", false)
	ta.Cfg.OpenShell.UpstreamTelemetry = true
	ta.gateway.state.BindMounts = mountsOn
	ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
	has(t, ta.output(), "OpenShell's anonymous usage telemetry stays on (openshell.upstream_telemetry is true in")
	lacks(t, ta.output(), "Disable OpenShell's anonymous usage telemetry?")
	if len(ta.gateway.planned) != 0 || !loadConfig(t, ta).OpenShell.UpstreamTelemetry {
		t.Fatalf("setup changed the gateway (%+v) or the saved answer", ta.gateway.planned)
	}
}

// TestSetupHarnessLines pins the harness part of setup: one line per
// harness it sets up with the model credential or the next step, the
// --harness hint, the others by the names the command line takes, and an
// image question for a harness nobody named (manual test R2-34).
func TestSetupHarnessLines(t *testing.T) {
	ta := setupApp(t, "y\nn\n", "", true)
	ta.env["ANTHROPIC_API_KEY"] = "sk-test"
	ta.images.missing = map[string]bool{"claudecode": true, "codex": true}
	ta.ok(t, ta.Setup(bg, SetupOptions{NoWrappers: true}))
	has(t, ta.output(),
		"  Harnesses (add another with `defenseclaw sandbox setup --harness NAME`):\n"+
			"    Claude Code (claude)  model credential ANTHROPIC_API_KEY ✓\n"+
			"    Codex (codex)         model credential none found: before the first run, set OPENAI_API_KEY or log in with `codex login --with-api-key`, or set AWS_BEARER_TOKEN_BEDROCK for Amazon Bedrock; or log in inside the sandbox\n"+
			"  Other harnesses: amp (not verified yet), antigravity, copilot, cursor-agent (not verified yet), devin (not verified yet), hermes, kiro, omnigent, opencode, openhands\n",
		"Build the Claude Code image now? (the first build downloads about 3 GB; otherwise the first `defenseclaw sandbox run claude` builds it) [Y/n]",
		"Build the Codex image now?",
		"skipped: the Codex image (the first `defenseclaw sandbox run codex` builds it, or `defenseclaw sandbox image build codex`)")
	lacks(t, ta.output(), "[x]", "Credentials:")
	if !slices.Equal(ta.images.built, []string{"claudecode"}) {
		t.Fatalf("images built = %v, want only the one agreed to", ta.images.built)
	}
	// A harness named with --harness is asked for: its image is built
	// without a question, and an image already built is only checked.
	ta = setupApp(t, "", "", true)
	ta.images.missing = map[string]bool{"codex": true}
	ta.ok(t, ta.Setup(bg, SetupOptions{NoWrappers: true, Harnesses: []string{"codex"}}))
	if strings.Contains(ta.output(), "image now?") || !slices.Equal(ta.images.built, []string{"codex"}) {
		t.Fatalf("images built = %v:\n%s", ta.images.built, ta.output())
	}
	ta.out.Reset()
	ta.images.built, ta.images.missing = nil, nil
	ta.ok(t, ta.Setup(bg, SetupOptions{NoWrappers: true}))
	if strings.Contains(ta.output(), "image now?") || !slices.Equal(ta.images.built, []string{"codex"}) {
		t.Fatalf("a current image was asked about: built = %v:\n%s", ta.images.built, ta.output())
	}
}

// TestSetupCredentialFollowsOpenShellLLM pins that setup's credential line
// reports what the configured openshell.llm choice finds: a provider
// without its key is a refused run (no sandbox to log in inside), none
// shares nothing whatever keys are set, and a harness with no model
// credentials only logs in inside.
func TestSetupCredentialFollowsOpenShellLLM(t *testing.T) {
	claude, kiro := harnessSpec(t, "claudecode"), harnessSpec(t, "kiro")
	for _, c := range []struct {
		name, llm string
		env       map[string]string
		spec      *harness.Spec
		want      string
		not       []string
	}{
		{"provider without its key", "bedrock", map[string]string{"ANTHROPIC_API_KEY": "k"}, claude,
			"model credential none found: runs are refused until you set AWS_BEARER_TOKEN_BEDROCK (openshell.llm bedrock; `--llm auto` overrides it for one run)",
			[]string{"log in inside the sandbox", "ANTHROPIC_API_KEY"}},
		{"claude-oauth without its token", "claude-oauth", map[string]string{"ANTHROPIC_API_KEY": "k"}, claude,
			"model credential none found: runs are refused until you set CLAUDE_CODE_OAUTH_TOKEN from `claude setup-token` (openshell.llm claude-oauth;",
			[]string{"log in inside the sandbox", "ANTHROPIC_API_KEY"}},
		{"none", "none", map[string]string{"ANTHROPIC_API_KEY": "k"}, claude,
			"model credential none shared (openshell.llm none): you log in inside the sandbox on the first run",
			[]string{"ANTHROPIC_API_KEY", "found"}},
		{"provider with its key", "bedrock", map[string]string{EnvBedrockToken: "b", "ANTHROPIC_API_KEY": "k"}, claude,
			"model credential AWS_BEARER_TOKEN_BEDROCK ✓", nil},
		{"harness without model credentials", "bedrock", nil, kiro,
			"model credential none found: you log in inside the sandbox on the first run", []string{"refused"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.Cfg.OpenShell.LLM = c.llm
			for k, v := range c.env {
				ta.env[k] = v
			}
			got := ta.credentialText(c.spec)
			has(t, got, c.want)
			lacks(t, got, c.not...)
		})
	}
}

// TestSetupHarnessAddsToTheConfiguredOnes pins that --harness adds to
// openshell.harnesses instead of replacing it (manual test R2-72).
func TestSetupHarnessAddsToTheConfiguredOnes(t *testing.T) {
	ta := setupApp(t, "", "  harnesses: [opencode, copilot, kiro]\n", true)
	ta.IO.TTY = false
	ta.Cfg.OpenShell.Harnesses = []string{"opencode", "copilot", "kiro"}
	for _, step := range []struct {
		harness string
		want    []string
	}{
		{"opencode", []string{"opencode", "copilot", "kiro"}},
		{"claude", []string{"opencode", "copilot", "kiro", "claudecode"}},
	} {
		ta.ok(t, ta.fresh().Setup(bg, SetupOptions{NonInteractive: true, SkipImages: true, NoWrappers: true, Harnesses: []string{step.harness}}))
		if c := loadConfig(t, ta); !slices.Equal(c.OpenShell.Harnesses, step.want) {
			t.Fatalf("after setup --harness %s, openshell.harnesses = %v, want %v", step.harness, c.OpenShell.Harnesses, step.want)
		}
	}
	has(t, ta.output(), "  Set up before: copilot, kiro, opencode\n")
}

// TestSetupNamesKiroAsTyped pins that setup names a harness the way the
// command line takes it, not by an internal command, and offers no shell
// wrapper that would never run (manual test R2-73).
func TestSetupNamesKiroAsTyped(t *testing.T) {
	ta := setupApp(t, "", "", true)
	ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, Wrappers: true, Harnesses: []string{"kiro"}}))
	has(t, ta.output(), "    Kiro CLI (kiro)  model credential none found: you log in inside the sandbox on the first run\n",
		"Kiro CLI gets no shell wrapper: `kiro-cli` starts kiro-cli-chat itself, which a wrapper cannot catch; start it with `defenseclaw sandbox run kiro`",
		"Done →  cd <project> && defenseclaw sandbox run kiro\n")
	lacks(t, ta.output(), "run kiro-cli-chat", "`kiro-cli-chat` run sandboxed")
	if _, err := os.Stat(filepath.Join(ta.home, ".bashrc")); !os.IsNotExist(err) {
		t.Fatalf("setup installed a kiro-cli-chat wrapper: %v", err)
	}
}

func TestDoctorReportsDefenseClawChecks(t *testing.T) {
	ta := newTestApp(t, "")
	ta.HostDoctor = hostReport(nil)
	ta.images.recs = readyImages(ta)
	if _, err := wrapper.Enable(wrapper.Bash, filepath.Join(ta.home, ".bashrc"), "/nonexistent/defenseclaw-gateway", wrapper.Wrap{Command: "claude", Harness: "claude"}); err != nil {
		t.Fatal(err)
	}
	wantExit(t, ta.RunDoctor(bg, DoctorOptions{}), 1) // the broken wrapper
	has(t, ta.output(), "DefenseClaw daemon", "connected to OpenShell 0.1.1 gateway openshell", "Harness images",
		"not built yet: codex", "calls /nonexistent/defenseclaw-gateway, which is missing", "Organization policy")
	ta.ok(t, ta.fresh().RunDoctor(bg, DoctorOptions{Output: OutputJSON}))
	var rep struct {
		OK     bool
		Checks []openshell.Check
	}
	if err := json.Unmarshal(ta.out.Bytes(), &rep); err != nil || rep.OK || len(rep.Checks) < 10 {
		t.Fatalf("doctor json = %+v, %v", rep, err)
	}
}

// The doctor's same-user check compares this user with the uid the daemon
// reports, never with this process's own (which could not fail); a daemon
// that reports none leaves the check nothing to compare.
func TestDoctorComparesTheDaemonsOwnUID(t *testing.T) {
	other := os.Getuid() + 1
	for _, uid := range []*int{&other, nil} {
		ta := newTestApp(t, "")
		ta.daemon.status.DaemonUID = uid
		var got *int
		ran := false
		ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
			got, ran = d.DaemonUID, true
			return hostReport(nil)(ctx, d)
		}
		_ = ta.RunDoctor(bg, DoctorOptions{})
		if !ran || (uid == nil) != (got == nil) || (uid != nil && *got != *uid) {
			t.Fatalf("ran %t: daemon uid = %v, want %v", ran, got, uid)
		}
	}
}

// TestDoctorJudgesMicroVMsAgainstTheAdminMaximum: every MicroVM gets the
// gateway-wide resources, so the host doctor is given the organization's
// openshell.admin.max_resources to judge them by; and the daemon line says
// the gateway runs MicroVMs.
func TestDoctorJudgesMicroVMsAgainstTheAdminMaximum(t *testing.T) {
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.Admin.MaxResources = config.OpenShellResourcesConfig{CPU: "1500m", Memory: "3Gi"}
	ta.daemon.status.Gateway.Driver = string(openshell.DriverVM)
	var cpu, mem int64
	ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		cpu, mem = d.MaxCPUMillis, d.MaxMemoryBytes
		return hostReport(nil)(ctx, d)
	}
	_ = ta.RunDoctor(bg, DoctorOptions{})
	if cpu != 1500 || mem != 3<<30 {
		t.Fatalf("maximum = %d millicores, %d bytes", cpu, mem)
	}
	has(t, ta.output(), "connected to OpenShell 0.1.1 gateway openshell (MicroVM driver)")
}

// TestDoctorFixAsksBeforeARestartStopsSandboxes: a fix that restarts a
// MicroVM gateway stops every sandbox running on it, once its disk is
// flushed. With none running it is a yes by default, as every fix; with
// some running it names them and is a no by default, which --yes takes.
// On docker, whose stop keeps what a container wrote, nothing changes.
func TestDoctorFixAsksBeforeARestartStopsSandboxes(t *testing.T) {
	applied := 0
	on := func(driver openshell.ComputeDriver) func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
		return hostReport(func(r *openshell.DoctorReport) {
			r.Driver = driver
			r.Checks = append(r.Checks, openshell.Check{ID: openshell.CheckIDVMResources, Title: "MicroVM resources", Status: openshell.StatusWarn,
				Detail: "every MicroVM gets 2 vCPUs", Fix: &openshell.Fix{Summary: "raise them and restart the gateway", Automatic: true, RestartsGateway: true,
					Apply: func(context.Context) error { applied++; return nil }}})
		})
	}
	report := on(openshell.DriverVM)
	const question = `Fix "MicroVM resources": raise them and restart the gateway?`
	const stops = "MicroVM resources: this restarts the OpenShell gateway, which stops the 1 sandbox running on it (dc-claude-theirs-a), once their disks are flushed"

	ta := newTestApp(t, "\n")
	ta.IO.TTY = true
	ta.HostDoctor = report
	runningOn(t, ta, 1)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true})
	has(t, ta.output(), stops, question+" [y/N]")
	if applied != 0 {
		t.Fatalf("the default applied the fix %d times", applied)
	}

	ta = newTestApp(t, "")
	ta.HostDoctor = report
	runningOn(t, ta, 1)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
	has(t, ta.output(), stops, "not fixed with --yes while sandboxes run on the gateway")
	_ = ta.fresh().RunDoctor(bg, DoctorOptions{Fix: true, Yes: true, Output: OutputJSON})
	if applied != 0 {
		t.Fatalf("--yes applied the fix %d times", applied)
	}

	// None running: yes by default.
	ta = newTestApp(t, "\n")
	ta.IO.TTY = true
	ta.HostDoctor = report
	runningOn(t, ta, 0)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true})
	has(t, ta.output(), question+" [Y/n]")
	lacks(t, ta.output(), "this restarts the OpenShell gateway")
	if applied != 1 {
		t.Fatalf("applied %d times", applied)
	}

	ta = newTestApp(t, "")
	ta.HostDoctor = on(openshell.DriverDocker)
	runningOn(t, ta, 1)
	_ = ta.RunDoctor(bg, DoctorOptions{Fix: true, Yes: true})
	lacks(t, ta.output(), "this restarts the OpenShell gateway", "not fixed with --yes")
	if applied != 2 {
		t.Fatalf("docker: applied %d times", applied)
	}
}

// TestDoctorVerdict pins the doctor's last line: not "ready" while
// sandboxes are turned off, and no image to build for a harness the
// organization forbids.
func TestDoctorVerdict(t *testing.T) {
	ta := newTestApp(t, "")
	ta.HostDoctor, ta.images.recs = hostReport(nil), readyImages(ta)
	ta.daemon.status.Enabled = false
	ta.ok(t, ta.RunDoctor(bg, DoctorOptions{}))
	has(t, ta.output(), "not ready for sandboxes yet: openshell.enabled is false: sandboxes are off (defenseclaw sandbox setup)")
	ta.ok(t, ta.fresh().RunDoctor(bg, DoctorOptions{Output: OutputJSON}))
	var rep struct{ OK, Ready bool }
	if err := json.Unmarshal(ta.out.Bytes(), &rep); err != nil || !rep.OK || rep.Ready {
		t.Fatalf("doctor json ok/ready = %+v, %v", rep, err)
	}

	ta = newTestApp(t, "")
	ta.HostDoctor, ta.images.recs = hostReport(nil), readyImages(ta)
	ta.Cfg.OpenShell.Admin.AllowedHarnesses = []string{"claudecode"}
	ta.ok(t, ta.RunDoctor(bg, DoctorOptions{}))
	has(t, ta.output(), "hook-verified: claudecode 2.1.156; codex not allowed by your organization's policy (openshell.admin.allowed_harnesses)",
		"ready for sandboxes")
	lacks(t, ta.output(), "image build codex", "not built yet: codex")

	// A failing doctor ends with its verdict too, which counts the failed
	// checks (it ended on the last check's line, the #1019 retest), and
	// its JSON is as before.
	ta = newTestApp(t, "")
	ta.HostDoctor, ta.images.recs = hostReport(func(r *openshell.DoctorReport) {
		for _, id := range []string{openshell.CheckIDLandlock, openshell.CheckIDDocker} {
			c := r.Get(id)
			c.Status, c.Detail = openshell.StatusFail, "broken"
		}
	}), readyImages(ta)
	err := ta.RunDoctor(bg, DoctorOptions{})
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 1 {
		t.Fatalf("RunDoctor = %v", err)
	}
	if out := strings.TrimRight(ta.output(), "\n"); !strings.HasSuffix(out, "\n\n  ✗ not ready for sandboxes: 2 checks failed") {
		t.Fatalf("a failing doctor ends:\n%s", out)
	}
	lacks(t, ta.output(), "✓ ready for sandboxes")
	ta.ok(t, ta.fresh().RunDoctor(bg, DoctorOptions{Output: OutputJSON}))
	if err := json.Unmarshal(ta.out.Bytes(), &rep); err != nil || rep.OK || rep.Ready {
		t.Fatalf("failing doctor json ok/ready = %+v, %v", rep, err)
	}
	lacks(t, ta.output(), "not ready for sandboxes")
}

// The doctor's image check counts the images for the driver the gateway
// runs: a MicroVM gateway boots only an image built for it, so the image a
// docker gateway ran is not built for it yet.
func TestDoctorCountsTheImagesForTheGatewayDriver(t *testing.T) {
	for _, tc := range []struct {
		name         string
		driver       openshell.ComputeDriver
		microVMImage bool
		// verdict is the MicroVM check's: "pass", "problem" or "" (it
		// settled nothing).
		verdict string
		want    string
	}{
		{"docker image, docker gateway", openshell.DriverDocker, false, "", "hook-verified: claudecode 2.1.156"},
		{"docker image, vm gateway", openshell.DriverVM, false, "", "not built yet: claudecode"},
		{"MicroVM image, vm gateway", openshell.DriverVM, true, "pass", "hook-verified: claudecode 2.1.156"},
		{"MicroVM image, docker gateway", openshell.DriverDocker, true, "pass", "not built yet: claudecode"},
		// The next run checks an unsettled image again, and refuses one the
		// check found cannot start in a MicroVM: neither is ready.
		{"unchecked MicroVM image", openshell.DriverVM, true, "", "not checked for an OpenShell MicroVM yet: claudecode"},
		{"MicroVM image with a problem", openshell.DriverVM, true, "problem", "cannot start in an OpenShell MicroVM: claudecode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.Cfg.OpenShell.Harnesses = []string{"claudecode"}
			ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) { r.Driver = tc.driver })
			ta.images.recs = readyImages(ta)
			ta.images.recs[0].MicroVM = tc.microVMImage
			switch tc.verdict {
			case "pass":
				ta.images.recs[0].MicroVMVerified = true
			case "problem":
				ta.images.recs[0].MicroVMProblem = "it could not resolve localhost"
			}
			_ = ta.RunDoctor(bg, DoctorOptions{})
			has(t, ta.output(), tc.want)
		})
	}
}

// TestDoctorWrapperHintNamesAConfiguredHarness pins that the doctor's
// wrapper hint names a harness this install set up (manual test R2-44).
func TestDoctorWrapperHintNamesAConfiguredHarness(t *testing.T) {
	for _, tc := range []struct {
		harnesses []string
		want      string
	}{
		{nil, "none (`defenseclaw sandbox enable claude` makes `claude` run sandboxed)"},
		{[]string{"kiro", "hermes", "openhands"}, "none (`defenseclaw sandbox enable hermes` makes `hermes` run sandboxed)"},
		{[]string{"kiro"}, "none"},
	} {
		ta := newTestApp(t, "")
		ta.Cfg.OpenShell.Harnesses = tc.harnesses
		if c := ta.wrappersCheck(); c.Detail != tc.want {
			t.Errorf("harnesses %v: wrappers check = %q, want %q", tc.harnesses, c.Detail, tc.want)
		}
	}
}

// Teardown removes what this install created and nothing else (not another
// install's sandboxes and profiles, nor a gateway file the user edited
// since); its dry run lists the plan and changes nothing.
func TestTeardownRemovesEverythingDefenseClawCreated(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "  wrappers: [claudecode]\n")
	owner, err := image.NewStore(ta.Cfg.DataDir).Owner()
	if err != nil {
		t.Fatal(err)
	}
	_, client := useGateway(ta)
	ours := map[string]string{manager.LabelManaged: "true", manager.LabelOwner: owner}
	theirs := map[string]string{manager.LabelManaged: "true", manager.LabelOwner: "someone-else"}
	for name, labels := range map[string]map[string]string{"dc-claude-orphan": ours, "dc-claude-theirs": theirs} {
		if _, err := client.CreateSandbox(bg, name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{Labels: labels}); err != nil {
			t.Fatal(err)
		}
	}
	// Ingress profiles: this config's listener's, an earlier port's (our
	// orphan's provider uses it), another daemon's unused one (it is not
	// ours to remove) and the legacy gateway-wide one of earlier releases.
	ownPort := ta.Cfg.OpenShellIngressPort()
	oldPort, otherPort := ownPort+1000, ownPort+2000
	for _, port := range []int{ownPort, oldPort, otherPort} {
		importProfile(t, client, profiles.IngressID, profiles.Input{IngressPort: port}, "")
	}
	importProfile(t, client, profiles.IngressID, profiles.Input{IngressPort: 18000}, profiles.LegacyIngressID)
	importProfile(t, client, profiles.AnthropicID, profiles.Input{Binaries: []string{"/opt/defenseclaw-harness/claudecode/bin/claude"}}, "")
	for _, p := range []*openshell.Provider{
		{Name: "dc-claude-orphan-ingress", Type: profiles.IngressProfileID(oldPort), Labels: ours, Spec: openshell.ProviderSpec{Credentials: map[string]string{"DEFENSECLAW_SANDBOX_TOKEN": "t"}}},
		{Name: "dc-claude-theirs-llm", Type: profiles.AnthropicID, Labels: theirs, Spec: openshell.ProviderSpec{Credentials: map[string]string{"ANTHROPIC_API_KEY": "k"}}},
	} {
		if _, err := client.CreateProvider(bg, p); err != nil {
			t.Fatal(err)
		}
	}
	ta.daemon.add(sampleSandbox("dc-claude-live"))
	ta.images.recs = []image.Record{{Tag: "defenseclaw/sandbox:claudecode-1"}}
	// Setup changed two gateway files; the user edited one since.
	dir := t.TempDir()
	kept, edited := filepath.Join(dir, "gateway.toml"), filepath.Join(dir, "gateway.env")
	writeFile(t, kept, "dc\n")
	writeFile(t, edited, "dc\n")
	ta.ok(t, ta.recordGatewayApply(&openshell.GatewayApplyResult{Files: []openshell.AppliedFile{{Path: kept, Backup: kept + ".bak"}, {Path: edited}}}))
	writeFile(t, edited, "user edit\n")
	rc := filepath.Join(ta.home, ".bashrc")
	if _, err := wrapper.Enable(wrapper.Bash, rc, "/usr/local/bin/defenseclaw-gateway", wrapper.Wrap{Command: "claude", Harness: "claude"}); err != nil {
		t.Fatal(err)
	}
	// A staged copy an interrupted create left, which no record names.
	writeFile(t, filepath.Join(ta.Cfg.DataDir, "sandboxes", "dc-claude-stale", "copy", "stage", "proj", "README.md"), "x")

	ta.ok(t, ta.Teardown(bg, TeardownOptions{DryRun: true}))
	// The profiles, each labeled: this install's ingress ones, then the
	// earlier release's gateway-wide one.
	has(t, ta.output(), "leftover data     dc-claude-stale", "dc-claude-live, dc-claude-orphan",
		"provider profiles "+profiles.IngressProfileID(ownPort)+", "+profiles.IngressProfileID(oldPort)+" (this install's hook ingress)\n"+
			"                    "+profiles.LegacyIngressID+" (from an earlier DefenseClaw release)\n  images ")
	lacks(t, ta.output(), "dc-claude-theirs")
	if ta.calls("DELETE", "dc-claude-live") != 0 || len(ta.gateway.rollbacks) != 0 {
		t.Fatal("the dry run changed something")
	}

	ta.ok(t, ta.Teardown(bg, TeardownOptions{Yes: true}))
	ta.wantCalls(t, 1, "DELETE", "dc-claude-live")
	if _, err := os.Stat(filepath.Join(ta.Cfg.DataDir, "sandboxes", "dc-claude-stale")); !os.IsNotExist(err) {
		t.Fatalf("the leftover data is still there: %v", err)
	}
	for what, c := range map[string]struct {
		err  error
		gone bool
	}{
		"our orphan sandbox":                    {errOf(client.GetSandbox(bg, "dc-claude-orphan")), true},
		"another data dir's sandbox":            {errOf(client.GetSandbox(bg, "dc-claude-theirs")), false},
		"our provider":                          {errOf(client.GetProvider(bg, "dc-claude-orphan-ingress")), true},
		"our ingress profile":                   {errOf(client.GetProfile(bg, profiles.IngressProfileID(ownPort))), true},
		"our earlier port's ingress profile":    {errOf(client.GetProfile(bg, profiles.IngressProfileID(oldPort))), true},
		"the legacy ingress profile":            {errOf(client.GetProfile(bg, profiles.LegacyIngressID)), true},
		"another daemon's ingress profile":      {errOf(client.GetProfile(bg, profiles.IngressProfileID(otherPort))), false},
		"a profile another provider still uses": {errOf(client.GetProfile(bg, profiles.AnthropicID)), false},
	} {
		if gone := openshell.IsNotFound(c.err); gone != c.gone || (!gone && c.err != nil) {
			t.Errorf("%s: %v, want it gone: %t", what, c.err, c.gone)
		}
	}
	if !slices.Equal(ta.images.removed, []string{"defenseclaw/sandbox:claudecode-1"}) {
		t.Fatalf("images removed = %v", ta.images.removed)
	}
	if len(ta.gateway.rollbacks) != 1 || len(ta.gateway.rollbacks[0].Files) != 1 || ta.gateway.rollbacks[0].Files[0].Path != kept {
		t.Fatalf("rollbacks = %+v", ta.gateway.rollbacks)
	}
	has(t, ta.output(), edited+" changed after DefenseClaw edited it")
	if b, _ := wrapper.Read(rc); len(b.Wraps) != 0 {
		t.Fatalf("wrappers left: %+v", b)
	}
	if c := loadConfig(t, ta); c.OpenShell.Enabled || len(c.OpenShell.Wrappers) != 0 {
		t.Fatalf("config after teardown = %+v", c.OpenShell)
	}
}

// TestTeardownDryRunListsEveryStep pins the dry run a newcomer reads: every
// step, "none" and "nothing to restore" included, the provider profiles
// labeled by whose they are, and a closing "nothing was changed" (manual
// test R2-40). A teardown with only openshell.enabled left turns it off.
func TestTeardownDryRunListsEveryStep(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	_, client := useGateway(ta)
	ownPort := ta.Cfg.OpenShellIngressPort()
	claude := profiles.Input{Binaries: []string{"/opt/defenseclaw-harness/claudecode/bin/claude"}}
	importProfile(t, client, profiles.IngressID, profiles.Input{IngressPort: ownPort}, "")
	importProfile(t, client, profiles.IngressID, profiles.Input{IngressPort: ownPort + 1000}, "")
	importProfile(t, client, profiles.AnthropicID, claude, "")
	for _, id := range []string{"dc-cred-0001", "dc-cred-0002", "dc-cred-0003", "dc-cred-0004"} {
		importProfile(t, client, profiles.AnthropicID, claude, id)
	}
	ta.daemon.add(sampleSandbox("dc-claude-live"))
	ta.images.recs = []image.Record{{Tag: "defenseclaw/sandbox:claudecode-1"}}
	ta.ok(t, ta.Teardown(bg, TeardownOptions{DryRun: true}))
	has(t, ta.output(),
		"  sandboxes         dc-claude-live\n",
		"  providers         none\n",
		"  provider profiles "+profiles.IngressProfileID(ownPort)+" (this install's hook ingress)\n"+
			"                    "+profiles.AnthropicID+", 4 --credential profiles (dc-cred-…) (shared by every DefenseClaw install on this gateway "+
			"and unused now; an install that needs one imports it again)\n",
		"  images            defenseclaw/sandbox:claudecode-1\n",
		"  gateway config    nothing to restore (setup recorded no change to it)\n",
		"  shell wrappers    none\n",
		"  config            turn openshell.enabled off in "+ta.ConfigPath+"\n",
		"dry run: nothing was changed\n")
	lacks(t, ta.output(), profiles.IngressProfileID(ownPort+1000))
	if !loadConfig(t, ta).OpenShell.Enabled {
		t.Fatal("the dry run changed the config")
	}
	// Only openshell.enabled is left: teardown still turns it off.
	ta = newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.ok(t, ta.Teardown(bg, TeardownOptions{Yes: true}))
	if strings.Contains(ta.output(), "nothing to tear down") || loadConfig(t, ta).OpenShell.Enabled {
		t.Fatalf("teardown left openshell.enabled on:\n%s", ta.output())
	}
}

// The daemon's delete leaves the CLI's own state of a sandbox (the run log
// kept at a stop, the accepted undo point) under its data directory, which
// `sandbox delete` removes after it: teardown removes it too.
func TestTeardownForgetsTheCLIStateOfTheSandboxesItDeletes(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.OpenShell = func(context.Context) (openshell.Client, *openshell.Registration, error) {
		return nil, nil, errors.New("no gateway in this test")
	}
	ta.daemon.add(sampleSandbox("dc-claude-live"))
	// The daemon's record: the data under the sandbox's directory is not an
	// orphan's.
	sandboxes := filepath.Join(ta.Cfg.DataDir, "sandboxes")
	writeFile(t, filepath.Join(sandboxes, "manager", "dc-claude-live.json"), `{"version":1,"name":"dc-claude-live","harness":"claudecode"}`)
	dir, err := ta.cliStateDir("dc-claude-live")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "run.log"), "what the agent printed\n")
	ta.ok(t, ta.Teardown(bg, TeardownOptions{Yes: true, KeepImages: true}))
	ta.wantCalls(t, 1, "DELETE", "dc-claude-live")
	if _, err := os.Stat(filepath.Join(sandboxes, "dc-claude-live")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the sandbox's directory (and its kept run log) is still there: %v", err)
	}
}

func TestTeardownWithoutDaemonOrGateway(t *testing.T) {
	ta := newTestApp(t, "")
	ta.API = sandboxapi.NewClient("http://127.0.0.1:1", "x")
	ta.Cfg = nil
	// Without a config the data dir is the default one, the fixture's
	// here: a teardown that reads (and rewrites) the setup receipt must
	// not reach the developer's.
	if got, want := ta.dataDir(), filepath.Dir(ta.ConfigPath); got != want {
		t.Fatalf("data dir without a config = %s, want the fixture's %s", got, want)
	}
	ta.ok(t, ta.Teardown(bg, TeardownOptions{Yes: true}))
	has(t, ta.output(), "nothing to tear down")
}

// A teardown without the daemon also removes what the daemon's delete would
// have (the ingress binding, the run files, the record), for the gone
// sandboxes too; a daemon that is up but cannot list keeps its state.
func TestTeardownWithTheDaemonStopped(t *testing.T) {
	setup := func(t *testing.T) (*testApp, string, *sandboxauth.FileStore) {
		ta := newTestApp(t, "")
		writeConfig(t, ta, "")
		owner, err := image.NewStore(ta.Cfg.DataDir).Owner()
		if err != nil {
			t.Fatal(err)
		}
		_, client := useGateway(ta)
		labels := map[string]string{manager.LabelManaged: "true", manager.LabelOwner: owner}
		if _, err := client.CreateSandbox(bg, "dc-claude-live", &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{Labels: labels}); err != nil {
			t.Fatal(err)
		}
		store, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(ta.Cfg.DataDir), sandboxauth.WithRefreshInterval(0))
		if err != nil {
			t.Fatal(err)
		}
		b, _, err := store.Mint(sandboxauth.Spec{SandboxName: "dc-claude-live", Connector: "claudecode", Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}})
		if err != nil {
			t.Fatal(err)
		}
		sandboxes := filepath.Join(ta.Cfg.DataDir, "sandboxes")
		for name, rec := range map[string]string{
			"dc-claude-live": `{"version":1,"name":"dc-claude-live","harness":"claudecode","binding_id":"` + b.ID + `"}`,
			"dc-claude-kept": `{"version":1,"name":"dc-claude-kept","harness":"claudecode","retained":true}`,
		} {
			writeFile(t, filepath.Join(sandboxes, name, "run-config", "settings.json"), "{}")
			writeFile(t, filepath.Join(sandboxes, "manager", name+".json"), rec)
		}
		return ta, b.ID, store
	}
	t.Run("stopped", func(t *testing.T) {
		ta, id, store := setup(t)
		ta.API = sandboxapi.NewClient("http://127.0.0.1:1", "x")
		ta.ok(t, ta.Teardown(bg, TeardownOptions{Yes: true, KeepImages: true}))
		has(t, ta.output(), "gone sandboxes    dc-claude-kept (kept snapshot)", "deleted sandbox dc-claude-live",
			"removed what the gone sandbox dc-claude-kept left on this machine")
		if left := manager.RecordedSandboxes(ta.Cfg.DataDir); len(left) != 0 {
			t.Fatalf("records left: %+v", left)
		}
		for _, name := range []string{"dc-claude-live", "dc-claude-kept"} {
			if _, err := os.Stat(filepath.Join(ta.Cfg.DataDir, "sandboxes", name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s's directory is still there: %v", name, err)
			}
		}
		fresh, err := sandboxauth.OpenFileStore(store.Path(), sandboxauth.WithRefreshInterval(0))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.Get(id); !errors.Is(err, sandboxauth.ErrNotFound) {
			t.Fatalf("the binding survived the teardown: %v", err)
		}
	})
	t.Run("a daemon with sandboxes on that cannot list them", func(t *testing.T) {
		ta, id, store := setup(t)
		ta.daemon.errors = map[string]*sandboxapi.Error{
			http.MethodGet + " " + sandboxapi.PathSandboxes: {Code: sandboxapi.CodeUpstream, Message: "listing is down"},
		}
		ta.ok(t, ta.Teardown(bg, TeardownOptions{Yes: true, KeepImages: true}))
		if left := manager.RecordedSandboxes(ta.Cfg.DataDir); len(left) != 2 {
			t.Fatalf("records left = %+v; a daemon may still be managing them", left)
		}
		if _, err := store.Get(id); err != nil {
			t.Fatalf("the binding was revoked under a running daemon: %v", err)
		}
	})
}

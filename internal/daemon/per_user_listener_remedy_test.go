// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0706: the root-gateway remedy is written for the running OS. The macOS
// app is named on macOS only, a Unix remedy returns the root-owned files
// before the account start (GAP-0711, GAP-0713), and no remedy ends in a
// period that the sentence around it would double.
func TestGAP0706RootGatewayRemedyIsWrittenPerOS(t *testing.T) {
	home := filepath.Join(t.TempDir(), "account's home")
	for _, tc := range []struct {
		goos             string
		mac, sudo, chown bool
	}{
		{"linux", false, true, true},
		{"darwin", true, true, true},
		{"windows", false, false, false},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			remedy := rootGatewayRemedyFor(tc.goos, home)
			if got := strings.Contains(remedy, "DefenseClawMac"); got != tc.mac {
				t.Fatalf("names DefenseClawMac = %v: %q", got, remedy)
			}
			if got := strings.Contains(remedy, "Start Gateway"); got != tc.mac {
				t.Fatalf("names the app's Start Gateway = %v: %q", got, remedy)
			}
			if strings.Contains(remedy, "macOS") {
				t.Fatalf("remedy names macOS: %q", remedy)
			}
			if got := strings.Contains(remedy, "sudo env DEFENSECLAW_HOME="); got != tc.sudo {
				t.Fatalf("names the privileged stop = %v: %q", got, remedy)
			}
			if got := strings.Contains(remedy, `sudo chown -R "$(id -un)" `); got != tc.chown {
				t.Fatalf("returns the root-owned files = %v: %q", got, remedy)
			}
			if tc.chown && !strings.HasSuffix(remedy, " && defenseclaw-gateway start") {
				t.Fatalf("a Unix remedy ends with the account start: %q", remedy)
			}
			if strings.HasSuffix(remedy, ".") {
				t.Fatalf("remedy ends in a period the caller would double: %q", remedy)
			}
			for _, sentence := range []string{RootGatewayListenerReason + " " + remedy + ".", RootGatewayListenerReason + " " + remedy} {
				if strings.Contains(sentence, "..") {
					t.Fatalf("doubled period in %q", sentence)
				}
			}
		})
	}
	if got, want := RootGatewayListenerRemedy(home), rootGatewayRemedyFor(runtime.GOOS, home); got != want {
		t.Fatalf("RootGatewayListenerRemedy on %s = %q, want %q", runtime.GOOS, got, want)
	}
}

// GAP-0747: the Windows remedy is rendered by managed.WindowsCommandLine, so
// a path with a space or an apostrophe is one inert literal, and the answer is
// the same wherever the table is read. The plain path is the benign twin.
func TestGAP0747WindowsRootGatewayRemedyIsRenderedNotTyped(t *testing.T) {
	for _, tc := range []struct{ name, executable string }{
		{"plain", `C:\Users\account\.local\bin\defenseclaw-gateway.exe`},
		{"space and apostrophe", `C:\Users\O'Brien Jr\bin\defenseclaw-gateway.exe`},
		{"bare name", "defenseclaw-gateway.exe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stop := managed.WindowsCommandLine(tc.executable, "stop")
			start := managed.WindowsCommandLine(tc.executable, "start")
			want := "Stop it from an elevated PowerShell prompt (" + stop + "), then start it as yourself from a normal PowerShell prompt (" + start + ")"
			if got := windowsRootGatewayRemedy(tc.executable); got != want {
				t.Fatalf("remedy = %q, want %q", got, want)
			}
			if !strings.HasPrefix(stop, "& '") || strings.Contains(want, "(defenseclaw-gateway ") {
				t.Fatalf("remedy names a bare command: %q", want)
			}
			// The call-operator form runs only in PowerShell (not cmd.exe): the text must say so.
			if !strings.Contains(want, "from an elevated PowerShell prompt (") || !strings.Contains(want, "from a normal PowerShell prompt (") {
				t.Fatalf("remedy does not name PowerShell for both steps: %q", want)
			}
			if strings.Contains(want, "administrator prompt") {
				t.Fatalf("remedy names an unnamed-shell prompt: %q", want)
			}
			if strings.Contains(want, "sudo") {
				t.Fatalf("a Windows remedy names sudo: %q", want)
			}
		})
	}
	if got, want := rootGatewayRemedyFor("windows", t.TempDir()), windowsRootGatewayRemedy(rootGatewayWindowsExecutable()); got != want {
		t.Fatalf("the OS table answers %q, want %q", got, want)
	}
}

// GAP-0711, GAP-0713: a root run leaves root-owned files in the install home
// and in the store that home's config moved the data to, so the sequence
// returns both before the account start. It is the same sequence whichever
// surface prints it (status, the hook, doctor), because they share this call.
func TestGAP0711RootGatewayRemedyReturnsInstallHomeAndMovedStore(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "install home")
	store := filepath.Join(root, "moved store's data")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CONFIG", "")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	chowned := func(remedy string) string {
		t.Helper()
		_, rest, ok := strings.Cut(remedy, `sudo chown -R "$(id -un)" `)
		if !ok {
			t.Fatalf("remedy returns no files: %q", remedy)
		}
		dirs, afterChown, ok := strings.Cut(rest, " && chmod -R u+rwX ")
		if !ok {
			t.Fatalf("remedy does not restore owner access after the return: %q", remedy)
		}
		if restored, _, _ := strings.Cut(afterChown, " && defenseclaw-gateway start"); restored != dirs {
			t.Fatalf("owner access restored on %q, files returned from %q", restored, dirs)
		}
		return dirs
	}
	for _, goos := range []string{"linux", "darwin"} {
		write("data_dir: " + strconv.Quote(store) + "\n")
		got := chowned(rootGatewayRemedyFor(goos, home))
		if want := shellQuote(home) + " " + shellQuote(store); got != want {
			t.Fatalf("%s moved store: chown targets %q, want %q", goos, got, want)
		}
		// A relative data_dir is taken from the gateway's working directory (the home).
		write("data_dir: ../relative-store\n")
		if got, want := chowned(rootGatewayRemedyFor(goos, home)), shellQuote(home)+" "+shellQuote(filepath.Join(root, "relative-store")); got != want {
			t.Fatalf("%s relative store: chown targets %q, want %q", goos, got, want)
		}
	}
	// Benign twins: the store is the home, or no config names one.
	for _, body := range []string{"data_dir: " + strconv.Quote(home) + "\n", "gateway:\n  api_port: 18970\n", "data_dir: [unterminated\n"} {
		write(body)
		if got, want := chowned(rootGatewayRemedyFor("linux", home)), shellQuote(home); got != want {
			t.Fatalf("config %q: chown targets %q, want only the install home %q", body, got, want)
		}
	}
	if err := os.Remove(filepath.Join(home, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if got, want := chowned(rootGatewayRemedyFor("linux", home)), shellQuote(home); got != want {
		t.Fatalf("no config: chown targets %q, want %q", got, want)
	}
	// An explicit DEFENSECLAW_CONFIG outside the home is the config the gateway reads.
	other := filepath.Join(root, "elsewhere.yaml")
	if err := os.WriteFile(other, []byte("data_dir: "+strconv.Quote(store)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CONFIG", other)
	if got, want := chowned(rootGatewayRemedyFor("linux", home)), shellQuote(home)+" "+shellQuote(store); got != want {
		t.Fatalf("explicit config: chown targets %q, want %q", got, want)
	}
}

// GAP-0711, GAP-0713: the store is resolved the way the gateway resolves it,
// for every form of the configuration the gateway accepts. The gateway starts
// with the install home as its working directory, makes a relative
// DEFENSECLAW_CONFIG and a relative data_dir absolute from there, and opens a
// linked config. A form the remedy read differently returned the home only
// (store left root-owned) or a folder next to an unrelated config.
func TestGAP0711RootGatewayRemedyResolvesTheStoreLikeTheGateway(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "install home")
	store := filepath.Join(home, "moved store")
	outside := filepath.Join(root, "elsewhere")
	for _, dir := range []string{home, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// chowned returns the folders the printed chain returns and the note that
	// comes before the chain. The chain is the end of the remedy and nothing
	// else follows it, so it can be copied whole and run by a shell.
	chowned := func() (string, string) {
		t.Helper()
		remedy := rootGatewayRemedyFor("linux", home)
		command, note := rootGatewayRecoverySteps(home)
		if !strings.HasSuffix(remedy, command) || !strings.HasPrefix(remedy, note) {
			t.Fatalf("remedy does not end with its command: %q", remedy)
		}
		requireShellSyntax(t, command)
		_, rest, ok := strings.Cut(command, `sudo chown -R "$(id -un)" `)
		if !ok {
			t.Fatalf("remedy returns no files: %q", remedy)
		}
		dirs, afterChown, ok := strings.Cut(rest, " && chmod -R u+rwX ")
		if !ok {
			t.Fatalf("remedy does not restore owner access after the return: %q", command)
		}
		restored, tail, _ := strings.Cut(afterChown, " && defenseclaw-gateway start")
		if restored != dirs {
			t.Fatalf("owner access restored on %q, files returned from %q", restored, dirs)
		}
		if tail != "" {
			t.Fatalf("text follows the chain: %q", tail)
		}
		return dirs, note
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A relative DEFENSECLAW_CONFIG is read from the install home.
	write(filepath.Join(home, "other.yaml"), "data_dir: "+strconv.Quote(store)+"\n")
	t.Setenv("DEFENSECLAW_CONFIG", "other.yaml")
	if got, tail := chowned(); got != shellQuote(home)+" "+shellQuote(store) || tail != "" {
		t.Fatalf("relative DEFENSECLAW_CONFIG: chown targets %q (note %q)", got, tail)
	}

	// A config that is a link to the real file is followed, as the loader does.
	real := filepath.Join(outside, "real.yaml")
	write(real, "data_dir: "+strconv.Quote(store)+"\n")
	if err := os.Symlink(real, filepath.Join(home, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CONFIG", "")
	if got, tail := chowned(); got != shellQuote(home)+" "+shellQuote(store) || tail != "" {
		t.Fatalf("linked config: chown targets %q (note %q)", got, tail)
	}
	if err := os.Remove(filepath.Join(home, "config.yaml")); err != nil {
		t.Fatal(err)
	}

	// A config outside the home with a relative data_dir: the gateway makes
	// the data_dir absolute from its working directory (the home), not from
	// the folder of the config. The remedy must not chown a folder next to
	// an unrelated config.
	write(real, "data_dir: moved store\n")
	t.Setenv("DEFENSECLAW_CONFIG", real)
	if got, tail := chowned(); got != shellQuote(home)+" "+shellQuote(store) || tail != "" {
		t.Fatalf("external config, relative data_dir: chown targets %q (note %q)", got, tail)
	}
	if remedy := rootGatewayRemedyFor("linux", home); strings.Contains(remedy, outside) {
		t.Fatalf("the remedy names the folder of the external config: %q", remedy)
	}

	// A configuration that exists but cannot be read names the install home
	// and says so, instead of presenting the sequence as complete.
	t.Setenv("DEFENSECLAW_CONFIG", "")
	for name, prepare := range map[string]func(){
		"malformed": func() { write(filepath.Join(home, "config.yaml"), "data_dir: [unterminated\n") },
		"directory": func() {
			_ = os.Remove(filepath.Join(home, "config.yaml"))
			if err := os.Mkdir(filepath.Join(home, "config.yaml"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"oversized": func() {
			_ = os.Remove(filepath.Join(home, "config.yaml"))
			write(filepath.Join(home, "config.yaml"), "data_dir: x\n#"+strings.Repeat("a", maxRemedyConfigBytes))
		},
	} {
		_ = os.RemoveAll(filepath.Join(home, "config.yaml"))
		prepare()
		got, tail := chowned()
		if got != shellQuote(home) || !strings.Contains(tail, "could not be read here") {
			t.Fatalf("%s config: chown targets %q, note %q", name, got, tail)
		}
		if strings.Contains(rootGatewayRemedyFor("darwin", home), "(the configuration") {
			t.Fatalf("%s config: the note is inside the command", name)
		}
	}

	// Benign twins: no config, and a config that sets no data_dir, are complete.
	_ = os.RemoveAll(filepath.Join(home, "config.yaml"))
	if got, tail := chowned(); got != shellQuote(home) || tail != "" {
		t.Fatalf("no config: chown targets %q (note %q)", got, tail)
	}
	write(filepath.Join(home, "config.yaml"), "gateway:\n  api_port: 18970\n")
	if got, tail := chowned(); got != shellQuote(home) || tail != "" {
		t.Fatalf("config without data_dir: chown targets %q (note %q)", got, tail)
	}
}

// requireShellSyntax fails when command is not one valid shell command line
// (the review pasted the printed chain into a shell and got a syntax error).
func requireShellSyntax(t *testing.T, command string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	if out, err := exec.Command(bash, "-n", "-c", command).CombinedOutput(); err != nil {
		t.Fatalf("the printed command is not valid shell: %v: %s\n%s", err, out, command)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// hookOutageFailModeNow is the gateway-outage mode the config of the per-user
// hook runtime in hookDir gives connectorName's hooks now
// (config.HookOutageFailMode of its policy tier): "open" only when this
// release loads that config, the install is neither managed nor Secure
// Client, and the connector's rule pack is not strict. Every other case is
// "closed".
//
// A per-user hook asks only for a classified gateway outage. Its current
// config decides even when a setup-time record has a different tier.
//
// The policy source is the runtime's own config, config.yaml in the data
// directory above hookDir, whose data_dir is that directory: the folder the
// gateway rendered the hooks into. The hook process's DEFENSECLAW_CONFIG and
// DEFENSECLAW_HOME come from the agent and never choose it or its data
// directory (loadHookRuntimeConfig), so an agent that points them at another
// default-tier config cannot reopen a strict outage. A config kept outside
// its data directory closes the outage, except the account's own config when
// the data directory holds none (hookRuntimeConfigPath): `defenseclaw config
// set data_dir` moves the hooks and leaves config.yaml in the account's home.
// Hooks left in the folder a data_dir move went away from follow the folder
// the account's config names now (movedDataDirOutageMode), and the account's
// config is a floor whenever it names the hooks' data directory
// (accountConfigClosesOutage).
//
// An install or upgrade of this account's DefenseClaw is not an outage
// either: while any folder an installer of this account may hold carries its
// .install.lock, the answer is "closed" (hookOutageInstallHeld).
func hookOutageFailModeNow(connectorName, hookDir string) string {
	return hookOutageFailModeFor(connectorName, hookDir, false)
}

// hookOutageFailModeFor is hookOutageFailModeNow; installWindow leaves out
// the install-lock check only (hookOutageInstallHeld). It is the mode an
// install window gives a call this account's gateway answered: "open" (the
// default and permissive tiers, or a saved open) lets that answer through
// with a warning, "closed" (the strict tier, a saved closed, a managed or
// Secure Client install, any doubt) blocks it.
func hookOutageFailModeFor(connectorName, hookDir string, installWindow bool) string {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	hookDir = strings.TrimSpace(hookDir)
	if name == "" || hookDir == "" || !filepath.IsAbs(hookDir) {
		return "closed"
	}
	dataDir := filepath.Dir(filepath.Clean(hookDir))
	configFile := hookRuntimeConfigPath(dataDir)
	loaded, ownDataDir, err := loadHookRuntimeConfig(configFile)
	if err != nil || loaded == nil || managed.IsManagedEnterprise(loaded.DeploymentMode) || loaded.SecureClientIntegration() {
		return "closed"
	}
	// The machine installation marker is an independent managed signal. A
	// leftover per-user hook cannot reopen a managed host just because its
	// own config still says OSS; an unreadable marker state also closes it.
	if secureClientHost() {
		return "closed"
	}
	if _, present := managedHostWindowsStandalone(); present {
		return "closed"
	}
	// A Windows machine marker that exists but cannot be verified, or whose
	// registry key cannot be read, is not proof of an OSS host. Only a
	// definite absence may leave the per-user outage open.
	if managedHostWindowsMarkerUncertain() {
		return "closed"
	}
	if marker := managedHostDescriptorPath(); marker != "" {
		if _, err := os.Lstat(marker); err == nil || !errors.Is(err, os.ErrNotExist) {
			return "closed"
		}
	}
	// A config whose data_dir is elsewhere is not this runtime's config,
	// except the account's config after a data_dir move: hooks left behind
	// follow the moved folder's answer (movedDataDirOutageMode).
	// The data directory is the one hook-data-dir names for install.sh to
	// lock (loadHookRuntimeConfig): a relative data_dir is taken from the
	// config's folder, never from the agent's working directory.
	if ownDataDir == "" || !pathidentity.Same(ownDataDir, dataDir) {
		return movedDataDirOutageMode(name, dataDir, configFile, ownDataDir, installWindow)
	}
	if !installWindow && hookOutageInstallHeld(dataDir) {
		return "closed"
	}
	if loaded.EffectiveHookOutageFailModeForConnector(name) == "open" && !accountConfigClosesOutage(name, dataDir, configFile) {
		return "open"
	}
	return "closed"
}

// accountConfigClosesOutage reports whether the account's own config closes
// the outage of the hook runtime in dataDir although that runtime loads
// another config file, configFile (rel-1-0-6 GAP-0224 review). The gateway
// enforces the account's config (config.ConfigPath), and `config set
// data_dir` leaves it there, so when it names dataDir as its data
// directory, its strict tier, saved closed or managed mode must win over a
// default-tier config.yaml that dataDir keeps of its own (a stray from an
// install with DEFENSECLAW_HOME there, a planted file, a folder of another
// account). The account's config is found as hookRuntimeConfigPath finds it:
// the installed runtime's protected data root, then the account database's
// home, never the agent's environment. An account config this release cannot
// load decides by its plain data_dir: one that may name dataDir, or that
// cannot be read as YAML, closes.
//
// The installed data root (on a Windows PowerShell install, the user's own
// defenseclaw-hook-state.json) and the recorded config (.config-record) are
// pointers this account can rewrite (rel-1-0-6 GAP-0309). When the hooks'
// config, or their data directory, came through one of them, the account
// database's own config is a floor whatever folder it names: a redirected
// pointer can never open what that config closes.
func accountConfigClosesOutage(name, dataDir, configFile string) bool {
	accountDB := ""
	if home := outageAccountHome(); home != "" {
		accountDB = filepath.Join(home, config.DefaultDataDirName, config.DefaultConfigName)
	}
	viaPointer := false
	for _, pointer := range outagePointerConfigs(dataDir) {
		if pathidentity.Same(configFile, pointer) || pathidentity.Same(dataDir, filepath.Dir(pointer)) {
			viaPointer = true
			break
		}
	}
	for _, candidate := range accountConfigCandidates(dataDir) {
		info, err := os.Lstat(candidate)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || info.IsDir() {
			return true
		}
		if pathidentity.Same(candidate, configFile) {
			continue
		}
		account, named, err := loadHookRuntimeConfig(candidate)
		if err != nil || account == nil {
			raw, rawErr := plainConfigDataDir(candidate)
			if rawErr != nil || raw == "" || pathidentity.Same(raw, dataDir) {
				return true
			}
			continue
		}
		floor := viaPointer && accountDB != "" && pathidentity.Same(candidate, accountDB)
		if !floor && (named == "" || !pathidentity.Same(named, dataDir)) {
			continue
		}
		if managed.IsManagedEnterprise(account.DeploymentMode) || account.SecureClientIntegration() ||
			account.EffectiveHookOutageFailModeForConnector(name) != "open" {
			return true
		}
	}
	return false
}

// outagePointerConfigs are the account config candidates found through a
// pointer the account can rewrite: the installed runtime's data root and the
// config recorded beside the hooks (accountConfigClosesOutage).
func outagePointerConfigs(dataDir string) []string {
	var pointers []string
	if root, recognized := outageInstalledDataRoot(); recognized && filepath.IsAbs(root) {
		pointers = append(pointers, filepath.Join(filepath.Clean(root), config.DefaultConfigName))
	}
	if recorded := outageRecordedConfig(dataDir); recorded != "" {
		pointers = append(pointers, recorded)
	}
	return pointers
}

// accountConfigCandidates are the config files that can be this account's
// own config for the hooks of dataDir, in the order hookRuntimeConfigPath
// tries them: the installed runtime's protected data root (Windows), the
// config the gateway recorded beside these hooks when it rendered them
// (outageRecordedConfig: a custom install DEFENSECLAW_HOME, rel-1-0-6
// GAP-0307), then the account database's .defenseclaw.
func accountConfigCandidates(dataDir string) []string {
	var candidates []string
	if root, recognized := outageInstalledDataRoot(); recognized && filepath.IsAbs(root) {
		candidates = append(candidates, filepath.Join(filepath.Clean(root), config.DefaultConfigName))
	}
	if recorded := outageRecordedConfig(dataDir); recorded != "" {
		candidates = append(candidates, recorded)
	}
	if home := outageAccountHome(); home != "" {
		candidates = append(candidates, filepath.Join(home, config.DefaultDataDirName, config.DefaultConfigName))
	}
	return candidates
}

// plainConfigDataDir is the data directory a config this release cannot load
// names, read as plain YAML: its data_dir (a relative one from the config's
// folder), or the config's folder when it has none, as loadHookRuntimeConfig
// takes it. Never the environment's DEFENSECLAW_HOME or HOME.
func plainConfigDataDir(configFile string) (string, error) {
	raw, err := os.ReadFile(configFile)
	if err != nil {
		return "", err
	}
	var source map[string]any
	if err := yaml.Unmarshal(raw, &source); err != nil {
		return "", err
	}
	value, present := source["data_dir"]
	if !present || value == nil {
		return filepath.Dir(configFile), nil
	}
	dir, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("data_dir in %s is not a string", configFile)
	}
	if strings.TrimSpace(dir) == "" {
		return filepath.Dir(configFile), nil
	}
	return configDataDir(configFile, dir), nil
}

// movedDataDirOutageMode is the outage mode of hooks left in a data
// directory that `defenseclaw config set data_dir` moved away from: the
// config they load names ownDataDir (rel-1-0-6 GAP-0224, sweep 8). The
// gateway renders the hooks into the new <data_dir>/hooks, but an agent
// session started before the move keeps running the hooks it loaded at its
// start: Claude Code keeps a snapshot of its hook commands for the session
// (/clear does not reload it), Codex and OpenCode read theirs once. Before
// this, such a session failed closed on every outage while a new session
// failed open.
//
// Two folders qualify, both running under the account's own config, the
// one the moved folder's hooks read too (hookRuntimeConfigPath): the
// account's .defenseclaw (named by the account database only, never HOME or
// DEFENSECLAW_HOME), and a folder with no config.yaml of its own, whose
// hooks load the account's config (a move back from a custom data_dir).
// They get the answer the hooks of ownDataDir get now, with every check it
// makes (strict, a saved closed, an install lock, a config.yaml of the new
// folder), and an install lock in their own folder closes too. A folder with
// a config.yaml of its own that keeps its data elsewhere stays closed.
func movedDataDirOutageMode(name, dataDir, configFile, ownDataDir string, installWindow bool) string {
	// The account database's config is a floor on this route too: a
	// rewritten pointer (.config-record, the Windows installed root) that
	// makes these hooks a moved folder's never opens what it closes
	// (GAP-0309 review 3).
	if accountConfigClosesOutage(name, dataDir, configFile) {
		return "closed"
	}
	// The config these hooks loaded is the account's: its own tier and saved
	// mode are a floor, whatever config.yaml the moved folder keeps. (A belt
	// since the line above.)
	if left, _, err := loadHookRuntimeConfig(configFile); err != nil || left.EffectiveHookOutageFailModeForConnector(name) != "open" {
		return "closed"
	}
	// The empty and relative checks cannot change the answer today (a later
	// check closes too); they are kept as cheap fail-closed belts.
	if ownDataDir == "" || !filepath.IsAbs(ownDataDir) {
		return "closed"
	}
	// The account's own folders are the folders of its config candidates:
	// the account database's .defenseclaw, the installed runtime's protected
	// data root (Windows) and the install home the gateway recorded beside
	// these hooks (a custom DEFENSECLAW_HOME, GAP-0307).
	own := filepath.Join(dataDir, config.DefaultConfigName)
	qualifies := false
	for _, candidate := range accountConfigCandidates(dataDir) {
		if pathidentity.Same(dataDir, filepath.Dir(candidate)) ||
			(!pathidentity.Same(configFile, own) && pathidentity.Same(configFile, candidate)) {
			qualifies = true
			break
		}
	}
	if !qualifies {
		return "closed"
	}
	if !installWindow && hookOutageInstallHeld(dataDir) {
		return "closed"
	}
	// The new folder's config (its own config.yaml, or the account's when it
	// has none) must name ownDataDir as its data directory, so the answer
	// below takes one step and never comes back here. (movedOwn == "" is a
	// belt like the ones above.)
	_, movedOwn, err := loadHookRuntimeConfig(hookRuntimeConfigPath(ownDataDir))
	if err != nil || movedOwn == "" || !pathidentity.Same(movedOwn, ownDataDir) {
		return "closed"
	}
	return hookOutageFailModeFor(name, filepath.Join(ownDataDir, "hooks"), installWindow)
}

// hookRuntimeConfigPath is the config file of the per-user hook runtime
// whose data directory is dataDir: config.yaml in dataDir, or, when dataDir
// has none, the account's own config (accountConfigCandidates: on Windows the
// installed runtime's protected data root, the config the gateway recorded
// beside the hooks, then the account database's .defenseclaw), never from
// HOME, USERPROFILE, DEFENSECLAW_HOME or DEFENSECLAW_CONFIG. A custom data_dir (`defenseclaw config set data_dir`)
// keeps config.yaml in ~/.defenseclaw while the gateway renders the hooks
// into <data_dir>/hooks, so that config is the one those hooks run under.
// Before this a custom data_dir closed every outage (rel-1-0-6 GAP-0224).
// A config whose data_dir is not dataDir opens only for hooks left behind by
// a data_dir move (movedDataDirOutageMode). A config.yaml in dataDir that
// exists in any form, or cannot be shown absent, stays the answer, so a
// broken one still closes, and the account's config still closes it when it
// names dataDir and is strict or saved closed (accountConfigClosesOutage).
func hookRuntimeConfigPath(dataDir string) string {
	own := filepath.Join(dataDir, config.DefaultConfigName)
	if _, err := os.Lstat(own); !errors.Is(err, fs.ErrNotExist) {
		return own
	}
	for _, candidate := range accountConfigCandidates(dataDir) {
		if _, err := os.Lstat(candidate); err == nil {
			return candidate
		}
	}
	return own
}

// hookOutageInstallHeld reports whether an installer may hold this
// account's DefenseClaw while the hook runtime in dataDir asks to let an
// outage through. The installer stops the gateway and starts it again when
// it is done; that window is never an outage. It is held when the
// .install.lock of any folder below exists, as any file type, and is not
// stale (its installer is proven gone), or one of
// those folders exists but is not a folder that can be searched, so the lock
// cannot be shown absent (hookexec.InstallLockHeld):
//
//   - dataDir, the runtime's own data directory. install.sh holds a data_dir
//     set apart from DEFENSECLAW_HOME as well (hold_hook_data_dir).
//   - This account's .defenseclaw from the account database (getpwuid on
//     Linux and macOS, the Profile known folder on Windows), the installer's
//     default DEFENSECLAW_HOME. HOME and USERPROFILE never choose it.
//   - On Windows, the data root of the installed runtime's protected install
//     state, install.ps1's DEFENSECLAW_HOME. A recognized state that cannot
//     be read counts as held.
//   - The hook process's DEFENSECLAW_HOME, and .defenseclaw in its HOME (and
//     USERPROFILE on Windows), which a hook started by an agent inherits.
//
// The environment can only add a folder to look in. It never replaces one
// of the others, so an agent that runs the hook with a temporary HOME or
// another DEFENSECLAW_HOME cannot hide the installer's lock; it can only
// close an outage. Relative values name no installer folder and are skipped.
func hookOutageInstallHeld(dataDir string) bool {
	roots := []string{dataDir}
	if home := outageAccountHome(); home != "" {
		roots = append(roots, filepath.Join(home, config.DefaultDataDirName))
	}
	if root, recognized := outageInstalledDataRoot(); recognized {
		if !filepath.IsAbs(root) {
			return true
		}
		roots = append(roots, root)
	}
	// The install home the gateway recorded beside these hooks: the
	// installer of a custom DEFENSECLAW_HOME holds it (GAP-0307).
	if recorded := outageRecordedConfig(dataDir); recorded != "" {
		roots = append(roots, filepath.Dir(recorded))
	}
	if home := os.Getenv("DEFENSECLAW_HOME"); filepath.IsAbs(home) {
		roots = append(roots, home)
	}
	for _, name := range outageHomeEnvNames {
		if home := os.Getenv(name); filepath.IsAbs(home) {
			roots = append(roots, filepath.Join(home, config.DefaultDataDirName))
		}
	}
	for _, root := range roots {
		if outageInstallLockHeld(root) {
			return true
		}
	}
	return false
}

// outageInstallLockHeld reports whether the installer may hold root:
// root/.install.lock exists, as any file type, or cannot be shown absent,
// or root exists but is not a folder (Windows reports a child of a file as
// absent). A root that does not exist holds no lock; a link to a folder is
// read as that folder.
func outageInstallLockHeld(root string) bool {
	if hookexec.InstallLockHeld(root) {
		return true
	}
	info, err := os.Stat(root)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	return !info.IsDir()
}

func init() {
	var connectorName, hookDir string
	var installWindow, toolPayloadStdin bool
	cmd := &cobra.Command{
		Use:    "hook-outage-mode",
		Short:  "Print the gateway-outage mode the config gives a per-user connector's hooks now",
		Hidden: true,
		// A hook runs it while the gateway is down: no daemon bootstrap,
		// no audit store, only a read of config.yaml.
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode := hookOutageFailModeFor(connectorName, hookDir, installWindow)
			if mode == "open" && toolPayloadStdin {
				mode = outageToolDecision(cmd.InOrStdin(), filepath.Dir(hookDir))
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), mode)
			return err
		},
	}
	cmd.Flags().StringVar(&connectorName, "connector", "", "connector name")
	cmd.Flags().StringVar(&hookDir, "hook-dir", "", "absolute hooks folder of the hook runtime asking")
	cmd.Flags().BoolVar(&installWindow, "install-window", false, "print the mode for a call the gateway answered while an installer holds the data directory")
	cmd.Flags().BoolVar(&toolPayloadStdin, "tool-payload-stdin", false, "check the tool payload before an open outage answer")
	_ = cmd.MarkFlagRequired("connector")
	rootCmd.AddCommand(cmd)
}

type outageToolPayload struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
	CWD  string                 `json:"cwd"`
}

// outageToolDecision checks concrete protected targets on the rare path where
// the gateway is unavailable. The saved tier chooses whether ordinary calls
// may proceed.
func outageToolDecision(input io.Reader, dataDir string) string {
	const maxPayload = 256 << 10
	raw, err := io.ReadAll(io.LimitReader(input, maxPayload+1))
	if err != nil || len(raw) > maxPayload {
		return "closed"
	}
	var payload outageToolPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Name == "" || payload.Args == nil {
		return "closed"
	}
	home := outageAccountHome()
	if home == "" || !filepath.IsAbs(home) {
		return "closed"
	}
	cwd := payload.CWD
	if !filepath.IsAbs(cwd) {
		return "closed"
	}
	if workdir, ok := payload.Args["workdir"].(string); ok && workdir != "" {
		if workdir == "~" {
			cwd = home
		} else if strings.HasPrefix(workdir, "~/") {
			cwd = filepath.Join(home, workdir[2:])
		} else if filepath.IsAbs(workdir) {
			cwd = filepath.Clean(workdir)
		} else {
			cwd = filepath.Join(cwd, workdir)
		}
	}
	if strings.EqualFold(payload.Name, "apply_patch") {
		args, err := json.Marshal(payload.Args)
		if err != nil {
			return "closed"
		}
		targets, known := hookpaths.ApplyPatchWriteTargets(payload.Name, args, "", cwd, home)
		if !known {
			return "closed"
		}
		for _, target := range targets {
			if outagePathProtected(target, cwd, home, dataDir) {
				return "protected"
			}
		}
	}
	if outagePayloadNamesProtected(payload.Args, cwd, home, dataDir) {
		return "protected"
	}
	return "open"
}

func outagePayloadNamesProtected(args map[string]interface{}, cwd, home, dataDir string) bool {
	type field struct {
		key         string
		value       interface{}
		environment map[string]string
	}
	stack := []field{{value: args, environment: map[string]string{"HOME": home, "DEFENSECLAW_HOME": dataDir}}}
	for len(stack) != 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch item := current.value.(type) {
		case map[string]interface{}:
			environment := current.environment
			if raw, ok := item["env"].(map[string]interface{}); ok {
				environment = outageKnownEnvironment(raw, environment)
			}
			for key, value := range item {
				if !strings.EqualFold(key, "env") {
					stack = append(stack, field{key: key, value: value, environment: environment})
				}
			}
		case []interface{}:
			for _, value := range item {
				stack = append(stack, field{key: current.key, value: value, environment: current.environment})
			}
		case string:
			if item == "" {
				continue
			}
			switch strings.ToLower(current.key) {
			case "command", "cmd", "script", "command_line", "commandline":
				if outageCommandNamesProtected(item, cwd, home, dataDir, current.environment) {
					return true
				}
			case "path", "file", "filepath", "file_path", "target", "destination", "dest", "output", "output_path", "filename":
				path := strings.ReplaceAll(strings.ReplaceAll(item, "${HOME}", home), "$HOME", home)
				if path == "~" {
					path = home
				} else if strings.HasPrefix(path, "~/") {
					path = filepath.Join(home, path[2:])
				}
				if !filepath.IsAbs(path) {
					path = filepath.Join(cwd, path)
				}
				if outagePathProtected(path, cwd, home, dataDir) {
					return true
				}
			}
		}
	}
	return false
}

func outageKnownEnvironment(raw map[string]interface{}, inherited map[string]string) map[string]string {
	known := make(map[string]string, len(raw)+len(inherited))
	for key, value := range inherited {
		known[key] = value
	}
	for key, value := range raw {
		if text, ok := value.(string); ok && outageEnvironmentName(key) && !strings.ContainsRune(text, 0) {
			known[key] = text
		}
	}
	return known
}

func outageEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		char := name[i]
		if char != '_' && (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') &&
			(i == 0 || char < '0' || char > '9') {
			return false
		}
	}
	return true
}

// The shared hookpaths writer returns known write targets, including values
// from the tool environment. ActionFacts retains the named path reading for
// commands that identify a protected file without a writer operand.
func outageCommandNamesProtected(command, cwd, home, dataDir string, environment map[string]string) bool {
	if hookpaths.KnownProtectedWriteTarget(command, cwd, home, environment, func(path string) bool {
		return outagePathProtected(path, cwd, home, dataDir)
	}) {
		return true
	}
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "exec", Command: command, CWD: cwd, ActiveHome: home})
	for _, path := range facts.Paths {
		target := path.Resolved
		if target == "" {
			target = path.Normalized
		}
		if target == "" {
			target = path.Value
		}
		if target != "" {
			if !filepath.IsAbs(target) {
				target = filepath.Join(cwd, target)
			}
			if outagePathProtected(target, cwd, home, dataDir) {
				return true
			}
		}
	}
	return false
}

func outagePathProtected(path, cwd, home, dataDir string) bool {
	quoted := "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
	if runtime.GOOS == "windows" {
		quoted = `"` + path + `"`
	}
	command := "printf x > " + quoted
	return hookpaths.ActionStateTargetMention(command, cwd, home) ||
		hookpaths.ActionCommandDecision(command, cwd, home) == "protected-target" ||
		outageTargetInDataRoot(path, home, dataDir)
}

func outageTargetInDataRoot(target, home, dataDir string) bool {
	if dataDir == "" || filepath.Clean(dataDir) == filepath.Join(home, ".defenseclaw") {
		return false
	}
	root, rootOK := hookpaths.ResolveWriteTarget(dataDir)
	resolved, targetOK := hookpaths.ResolveWriteTarget(target)
	if !rootOK {
		return true
	}
	if !targetOK {
		resolved = filepath.Clean(target)
	}
	relative, err := filepath.Rel(root, resolved)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) &&
		!strings.HasPrefix(relative, "logs"+string(filepath.Separator)) {
		return true
	}
	return false
}

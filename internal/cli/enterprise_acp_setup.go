// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/jsonc"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/spf13/cobra"
)

const (
	maxACPClientConfigBytes = 4 << 20
	maxACPContractLockBytes = 64 << 10
)

var (
	enterpriseACPActivate    bool
	enterpriseACPAPIPort     int
	enterpriseACPGuardBinary string
	enterpriseACPAgentBinary string
)

// enterpriseACPSetupCmd is the user-side half of a managed enrollment. A
// managed host has no Python CLI, so the `defenseclaw acp setup --managed`
// the enrollment used to report did not exist there (GAP-0254); the gateway
// binary every managed package ships does the same user-owned writes.
var enterpriseACPSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Write the editor entry and contract lock of one managed ACP enrollment (run as that user)",
	Long: `Write the user-owned side of a managed ACP enrollment: the guarded editor
entry for Zed or JetBrains and the executable contract lock the guard checks
before it starts the agent.

Run it as the enrolled user, with the command that "enterprise acp enroll"
reports. It reads no central configuration and cannot change policy: the
administrator-owned credential and profile were fixed at enrollment, and the
gateway refuses a request that does not match them.`,
	Args: cobra.NoArgs,
	// The user cannot read the administrator-owned configuration, and setup
	// needs none. Secure Client keeps the command tree of main, which has no
	// setup (issue #1092).
	Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true", secureClientAbsentAnnotation: "true"},
	RunE:        runEnterpriseACPSetup,
}

func init() {
	flags := enterpriseACPSetupCmd.Flags()
	flags.StringVar(&enterpriseACPClient, "client", "", "ACP client ID (for example zed or jetbrains)")
	flags.StringVar(&enterpriseACPAgent, "agent", "", "ACP agent ID (for example kiro)")
	flags.StringVar(&enterpriseACPProfile, "profile", "", "Centrally configured ACP profile")
	flags.BoolVar(&enterpriseACPActivate, "activate", false, "Action mode, when central policy selects it for this profile")
	flags.StringVar(&enterpriseACPUserDataDir, "data-dir", "", "Per-user runtime data dir (default: <home>/.defenseclaw)")
	flags.IntVar(&enterpriseACPAPIPort, "api-port", 0, "Gateway API port on this computer")
	flags.StringVar(&enterpriseACPGuardBinary, "guard-binary", "", "Administrator-owned defenseclaw-acp (default: next to this executable)")
	flags.StringVar(&enterpriseACPAgentBinary, "agent-binary", "", "Path of the catalog agent executable when it is not on PATH (same name, for example kiro-cli)")
	flags.BoolVar(&enterpriseACPJSON, "json", false, "Emit machine-readable JSON")
	enterpriseACPCmd.AddCommand(enterpriseACPSetupCmd)
}

// enterpriseACPUserSetup is everything the user-side writes depend on.
type enterpriseACPUserSetup struct {
	client, agent, profile string
	mode                   acp.Mode
	dataDir                string
	guard                  string
	agentBinary            string
	gatewayURL             string
	// rerun is this setup command for another profile and mode, nil when
	// unknown.
	rerun func(profile string, mode acp.Mode) string
}

// enterpriseACPGuardCustody checks that the guard a managed lock pins is the
// administrator-owned executable: root or Administrators own every element
// of its path, none is a symlink and no one else can write it. Replaceable
// in tests, whose guard is the test binary.
var enterpriseACPGuardCustody = func(path string) error {
	return managed.ValidateTrustedFilePath(path, "managed ACP guard")
}

type enterpriseACPUserSetupResult struct {
	clientConfig string
	contractLock string
	tokenFile    string
}

func runEnterpriseACPSetup(cmd *cobra.Command, _ []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return enterpriseACPResult(cmd, nil, fmt.Errorf("resolve the home directory: %w", err))
	}
	dataDir := strings.TrimSpace(enterpriseACPUserDataDir)
	if dataDir == "" {
		dataDir = filepath.Join(home, ".defenseclaw")
	}
	if dataDir, err = filepath.Abs(dataDir); err != nil {
		return enterpriseACPResult(cmd, nil, fmt.Errorf("resolve the ACP data dir: %w", err))
	}
	if relative, relErr := filepath.Rel(home, dataDir); relErr != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return enterpriseACPResult(cmd, nil, errors.New("enterprise ACP per-user data dir must remain inside your home"))
	}
	if enterpriseACPAPIPort < 1 || enterpriseACPAPIPort > 65535 {
		return enterpriseACPResult(cmd, nil, errors.New("--api-port is required: use the command that enterprise acp enroll reported"))
	}
	guard := strings.TrimSpace(enterpriseACPGuardBinary)
	if guard == "" {
		executable, execErr := os.Executable()
		if execErr != nil {
			return enterpriseACPResult(cmd, nil, fmt.Errorf("locate the ACP guard: %w", execErr))
		}
		guard = filepath.Join(filepath.Dir(executable), "defenseclaw-acp"+filepath.Ext(executable))
	}
	mode := acp.ModeObserve
	if enterpriseACPActivate {
		mode = acp.ModeAction
	}
	client := strings.ToLower(strings.TrimSpace(enterpriseACPClient))
	agent := strings.ToLower(strings.TrimSpace(enterpriseACPAgent))
	agentBinary := strings.TrimSpace(enterpriseACPAgentBinary)
	windows := runtime.GOOS == "windows"
	invoke := managedHostGatewayCommand()
	if executable, execErr := os.Executable(); execErr == nil {
		invoke = enterpriseACPQuotePath(executable, windows)
	}
	if windows {
		invoke = "& " + invoke
	}
	result, err := setupEnterpriseACPUserFiles(enterpriseACPUserSetup{
		client:      client,
		agent:       agent,
		profile:     strings.TrimSpace(enterpriseACPProfile),
		mode:        mode,
		dataDir:     dataDir,
		guard:       guard,
		agentBinary: agentBinary,
		gatewayURL:  fmt.Sprintf("http://127.0.0.1:%d/api/v1/acp/evaluate", enterpriseACPAPIPort),
		rerun: func(profile string, mode acp.Mode) string {
			command := fmt.Sprintf("%s enterprise acp setup --client %s --agent %s --profile %s", invoke, client, agent, profile)
			if mode == acp.ModeAction {
				command += " --activate"
			}
			command += fmt.Sprintf(" --data-dir %s --api-port %d --guard-binary %s", enterpriseACPQuotePath(dataDir, windows),
				enterpriseACPAPIPort, enterpriseACPQuotePath(guard, windows))
			if agentBinary != "" {
				command += " --agent-binary " + enterpriseACPQuotePath(agentBinary, windows)
			}
			return command
		},
	})
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	return enterpriseACPResult(cmd, map[string]any{
		"ok": true, "client": strings.ToLower(strings.TrimSpace(enterpriseACPClient)),
		"agent": strings.ToLower(strings.TrimSpace(enterpriseACPAgent)), "profile": strings.TrimSpace(enterpriseACPProfile),
		"mode": string(mode), "path": result.clientConfig, "contract_lock": result.contractLock,
		"token_file": result.tokenFile,
	}, nil)
}

// setupEnterpriseACPUserFiles writes the guarded editor entry and the
// contract lock of one managed enrollment, and re-pins the locks of the other
// entries in the same editor file, whose configuration digest the new entry
// changed. A failure restores every file it touched.
func setupEnterpriseACPUserFiles(in enterpriseACPUserSetup) (result enterpriseACPUserSetupResult, err error) {
	clientPath, err := acpClientConfigPath(in.client)
	if err != nil {
		return result, err
	}
	err = withACPUserSetupLock(clientPath, func() error {
		result, err = setupEnterpriseACPUserFilesLocked(in)
		return err
	})
	return result, err
}

// The lock covers sibling discovery, snapshots, editor writes, re-pinning,
// and rollback. The editor path is the shared resource even when callers use
// different per-user data directories.
func setupEnterpriseACPUserFilesLocked(in enterpriseACPUserSetup) (result enterpriseACPUserSetupResult, err error) {
	catalog, err := acp.LookupAgent(in.agent)
	if err != nil {
		return result, fmt.Errorf("%w (the ACP agents are %s)", err, strings.Join(acp.AgentIDs(), ", "))
	}
	known := false
	for _, client := range acp.BuiltinCatalog().Clients {
		known = known || client.ID == in.client
	}
	if !known {
		return result, fmt.Errorf("unknown ACP client: %s (the ACP clients are %s)", in.client, strings.Join(enterpriseACPClientIDs(), ", "))
	}
	if in.profile == "" {
		return result, errors.New("enterprise ACP setup requires --client, --agent, and --profile")
	}
	agentCommand := catalog.Command
	if in.agentBinary != "" {
		// The override only finds the enrolled agent outside PATH. Any
		// executable used to be accepted, so an enrollment for one agent ran
		// another, which the gateway and the audit then named after the
		// enrollment (GAP-0398).
		if !acpExecutableNamed(in.agentBinary, catalog.Command) {
			return result, fmt.Errorf("--agent-binary %s is not the %s executable: the enrollment is for %s, whose executable is named %s",
				in.agentBinary, catalog.Name, in.agent, catalog.Command)
		}
		agentCommand = in.agentBinary
	}
	tokenPath, err := acp.EnterpriseUserTokenPath(in.dataDir, in.client, in.agent)
	if err != nil {
		return result, err
	}
	if err := validateEnterpriseACPUserToken(tokenPath); err != nil {
		return result, err
	}
	if note, ok := readEnterpriseACPUserEnrollment(tokenPath); ok && note.Profile != in.profile {
		// The copy holds the credential of a newer enrollment: this command
		// would point the working entry and lock at the replaced profile
		// (GAP-0733).
		next := "the setup command that enrollment reported"
		if in.rerun != nil {
			next = in.rerun(note.Profile, acp.Mode(note.Mode))
		}
		return result, fmt.Errorf("this setup command is for profile %s, but your administrator enrolled you for %s/%s in profile %s "+
			"(%s), which replaced it; nothing was changed. Run: %s", in.profile, in.client, in.agent, note.Profile, note.EnrolledAt, next)
	}
	guard, err := resolveACPExecutable(in.guard, "DefenseClaw ACP guard")
	if err != nil {
		return result, err
	}
	// The lock records managed custody, which lets an administrator upgrade
	// change the guard bytes. A copy of the guard in the home passed the
	// digest check and was recorded the same way, so the user ran a guard the
	// organization does not own (GAP-0426).
	if err := enterpriseACPGuardCustody(guard); err != nil {
		return result, fmt.Errorf("--guard-binary %s is not the administrator-owned DefenseClaw ACP guard (%v); "+
			"run the setup command the enrollment reports, which names the installed guard", guard, err)
	}
	agentExecutable, err := resolveACPExecutable(agentCommand, catalog.Name)
	if err != nil {
		return result, err
	}
	clientPath, err := acpClientConfigPath(in.client)
	if err != nil {
		return result, err
	}
	lockPath := acpContractLockPath(in.dataDir, in.client, in.agent)

	document, prefix, err := readACPClientConfig(clientPath)
	if err != nil {
		return result, err
	}
	servers, _ := document["agent_servers"].(map[string]any)
	if _, present := document["agent_servers"]; present && servers == nil {
		return result, fmt.Errorf("agent_servers must be an object in %s", clientPath)
	}
	siblings, err := acpSiblingLockPaths(in.dataDir, in.client, in.agent, servers)
	if err != nil {
		return result, err
	}
	touched := append([]string{clientPath, lockPath}, siblings...)
	snapshots := make(map[string][]byte, len(touched))
	for _, path := range touched {
		body, readErr := os.ReadFile(path)
		switch {
		case readErr == nil:
			snapshots[path] = body
		case !errors.Is(readErr, os.ErrNotExist):
			return result, readErr
		}
	}
	defer func() {
		if err == nil {
			return
		}
		var problems []string
		for _, path := range touched {
			var restoreErr error
			if body, existed := snapshots[path]; existed {
				restoreErr = safefile.Write(path, body)
			} else if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				restoreErr = removeErr
			}
			if restoreErr != nil {
				problems = append(problems, path)
			}
		}
		err = fmt.Errorf("ACP setup was rolled back: %w", err)
		if len(problems) > 0 {
			err = fmt.Errorf("%w; rollback problems: %s", err, strings.Join(problems, ", "))
		}
	}()

	if servers == nil {
		servers = map[string]any{}
		document["agent_servers"] = servers
	}
	args := []any{
		"--agent", in.agent, "--client", in.client, "--profile", in.profile, "--mode", string(in.mode),
		"--token-file", tokenPath, "--gateway", in.gatewayURL, "--contract-lock", lockPath, "--",
		agentExecutable,
	}
	for _, arg := range catalog.Args {
		args = append(args, arg)
	}
	entry := map[string]any{"command": guard, "args": args, "env": map[string]any{}}
	if in.client == "zed" {
		entry["type"] = "custom"
	}
	servers[acpManagedEntryName(in.agent)] = entry
	if err := writeACPClientConfig(clientPath, prefix, document); err != nil {
		return result, err
	}
	clientDigest, err := acpFileSHA256(clientPath)
	if err != nil {
		return result, err
	}
	// The lock pins this entry, not the whole file the editor rewrites
	// (GAP-0708).
	entryDigest, err := acp.ClientEntrySHA256(clientPath, in.client, in.agent)
	if err != nil {
		return result, err
	}
	agentDigest, err := acpFileSHA256(agentExecutable)
	if err != nil {
		return result, err
	}
	guardDigest, err := acpFileSHA256(guard)
	if err != nil {
		return result, err
	}
	var lock acp.RuntimeContractLock
	lock.Version = 1
	lock.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	lock.Protocol.SchemaVersion, lock.Protocol.SchemaSHA256 = acp.SchemaVersion, acp.SchemaSHA256
	lock.Client.ID, lock.Client.ConfigPath, lock.Client.ConfigSHA256 = in.client, clientPath, acp.EntryDigestPrefix+entryDigest
	// Setup does not run an operator-selected binary to decorate the lock: the
	// agent is pinned by absolute path and digest.
	lock.Agent.ID, lock.Agent.Path, lock.Agent.SHA256, lock.Agent.Version = in.agent, agentExecutable, agentDigest, "not-probed"
	lock.Guard.Path, lock.Guard.SHA256, lock.Guard.ManagedCustody = guard, guardDigest, true
	lock.Profile, lock.Mode = in.profile, string(in.mode)
	body, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return result, err
	}
	if err := safefile.WritePrivate(lockPath, append(body, '\n')); err != nil {
		return result, err
	}
	for _, sibling := range siblings {
		if err := repinACPContractLock(sibling, in.client, clientPath, clientDigest); err != nil {
			return result, err
		}
	}
	return enterpriseACPUserSetupResult{clientConfig: clientPath, contractLock: lockPath, tokenFile: tokenPath}, nil
}

// validateEnterpriseACPUserToken checks the bearer the administrator
// published for this user: a private regular file the user owns.
func validateEnterpriseACPUserToken(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<10 {
		return fmt.Errorf("managed ACP token is missing or unsafe: %s; ask your administrator to run enterprise acp enroll for you", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("managed ACP token permissions are too broad: %s", path)
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return fmt.Errorf("managed ACP token custody is unsafe: %s: %w", path, err)
	}
	return nil
}

// resolveACPExecutable finds an executable on PATH or by absolute path and
// returns it with symlinks resolved: the guard compares the path it runs from
// with the one the lock names.
func resolveACPExecutable(value, label string) (string, error) {
	candidate, err := exec.LookPath(value)
	if errors.Is(err, exec.ErrDot) {
		// Windows looks in the current folder first and Go refuses that
		// match; "was not found" sent the user looking for an install that
		// was on PATH all along (GAP-0734).
		where, _ := filepath.Abs(candidate)
		return "", fmt.Errorf("%s executable %s resolves to %s in the current folder, which DefenseClaw does not run; "+
			"run setup from another folder, or pass --agent-binary with the full path of the agent", label, value, where)
	}
	if err != nil {
		if !filepath.IsAbs(value) {
			return "", fmt.Errorf("%s executable was not found: %s", label, value)
		}
		candidate = value
	}
	absolute, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("%s executable was not found: %s", label, value)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("%s executable was not found: %s", label, value)
	}
	if info, statErr := os.Stat(resolved); statErr != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s executable was not found: %s", label, value)
	}
	return resolved, nil
}

// acpExecutableNamed reports whether path names the executable command (on
// Windows with any extension, in any case).
func acpExecutableNamed(path, command string) bool {
	base := filepath.Base(strings.TrimSpace(path))
	if runtime.GOOS == "windows" {
		base = strings.TrimSuffix(base, filepath.Ext(base))
		return strings.EqualFold(base, command)
	}
	return base == command
}

// acpClientConfigPath is the editor file that holds the ACP agent entries.
func acpClientConfigPath(client string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve the home directory: %w", err)
	}
	switch client {
	case "jetbrains":
		return filepath.Join(home, ".jetbrains", "acp.json"), nil
	case "zed":
		if runtime.GOOS == "windows" {
			appData := strings.TrimSpace(os.Getenv("APPDATA"))
			if appData == "" {
				return "", errors.New("APPDATA is required to configure Zed on Windows")
			}
			return filepath.Join(appData, "Zed", "settings.json"), nil
		}
		if base := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); base != "" {
			return filepath.Join(base, "zed", "settings.json"), nil
		}
		return filepath.Join(home, ".config", "zed", "settings.json"), nil
	}
	return "", fmt.Errorf("unknown ACP client: %s", client)
}

func acpContractLockPath(dataDir, client, agent string) string {
	return filepath.Join(dataDir, "acp", client+"-"+agent+".contract-lock.json")
}

// acpManagedEntryName is the editor entry name for an agent, the one the
// Python CLI writes and verifies.
func acpManagedEntryName(agent string) string { return acp.ManagedEntryName(agent) }

// acpSiblingLockPaths finds existing locks both in the new enrollment's data
// directory and in the managed entries of the shared editor settings file.
func acpSiblingLockPaths(dataDir, client, agent string, servers map[string]any) ([]string, error) {
	var paths []string
	seen := map[string]bool{}
	add := func(path string) error {
		if seen[path] {
			return nil
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > maxACPContractLockBytes {
			return fmt.Errorf("managed ACP contract lock is missing or unsafe: %s", path)
		}
		seen[path] = true
		paths = append(paths, path)
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	for _, other := range acp.AgentIDs() {
		if other == agent {
			continue
		}
		if err := add(acpContractLockPath(dataDir, client, other)); err != nil {
			return nil, err
		}
		entry, ok := servers[acpManagedEntryName(other)].(map[string]any)
		if !ok {
			continue
		}
		args, ok := entry["args"].([]any)
		if !ok {
			continue
		}
		for i := 0; i+1 < len(args); i++ {
			if args[i] != "--contract-lock" {
				continue
			}
			path, ok := args[i+1].(string)
			if !ok || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
				path != acpContractLockPath(filepath.Dir(filepath.Dir(path)), client, other) {
				return nil, fmt.Errorf("managed ACP contract lock path is unsafe for %s", other)
			}
			relative, relErr := filepath.Rel(home, path)
			if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("managed ACP contract lock for %s is outside the user home", other)
			}
			if err := add(path); err != nil {
				return nil, err
			}
			break
		}
	}
	return paths, nil
}

// repinACPContractLock points an existing lock at the editor file as it is
// now: another entry in the same file changed its digest.
func repinACPContractLock(path, client, clientPath, clientDigest string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("managed ACP contract lock is unreadable: %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("managed ACP contract lock is unreadable: %s: %w", path, err)
	}
	lockClient, _ := document["client"].(map[string]any)
	if lockClient == nil || lockClient["id"] != client {
		return fmt.Errorf("managed ACP contract lock identity does not match: %s", path)
	}
	if pinned, _ := lockClient["config_sha256"].(string); strings.HasPrefix(pinned, acp.EntryDigestPrefix) &&
		lockClient["config_path"] == clientPath {
		// It pins its own entry, which this setup did not change.
		return nil
	}
	lockClient["config_path"], lockClient["config_sha256"] = clientPath, clientDigest
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WritePrivate(path, append(body, '\n'))
}

// readACPClientConfig reads an editor settings file (JSON with comments and
// trailing commas) and the comment block that precedes its object, which the
// rewrite keeps. A missing or blank file is an empty object.
func readACPClientConfig(path string) (map[string]any, string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("cannot read %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("refusing unsafe client configuration path: %s", path)
	}
	if info.Size() > maxACPClientConfigBytes {
		return nil, "", fmt.Errorf("client configuration is too large: %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("cannot read %s: %w", path, err)
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	normalized := enterpriseACPNormalizeJSONC(raw)
	if len(bytes.TrimSpace(normalized)) == 0 {
		return map[string]any{}, "", nil
	}
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, "", fmt.Errorf("cannot read %s: %w", path, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, "", fmt.Errorf("cannot read %s: unexpected content after the JSON object", path)
	}
	if document == nil {
		return nil, "", fmt.Errorf("client configuration must contain a JSON object: %s", path)
	}
	return document, acpLeadingJSONCPrefix(raw), nil
}

func enterpriseACPNormalizeJSONC(raw []byte) []byte { return jsonc.Strip(raw) }

// acpLeadingJSONCPrefix is the whitespace and comments before the first
// token of a JSONC document.
func acpLeadingJSONCPrefix(raw []byte) string {
	index := 0
	for index < len(raw) {
		switch {
		case raw[index] == ' ' || raw[index] == '\t' || raw[index] == '\r' || raw[index] == '\n':
			index++
		case bytes.HasPrefix(raw[index:], []byte("//")):
			for index < len(raw) && raw[index] != '\n' && raw[index] != '\r' {
				index++
			}
		case bytes.HasPrefix(raw[index:], []byte("/*")):
			end := bytes.Index(raw[index+2:], []byte("*/"))
			if end < 0 {
				return ""
			}
			index += end + 4
		default:
			return string(raw[:index])
		}
	}
	return string(raw)
}

func writeACPClientConfig(path, prefix string, document map[string]any) error {
	var out bytes.Buffer
	out.WriteString(prefix)
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return err
	}
	return safefile.Write(path, out.Bytes())
}

func acpFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

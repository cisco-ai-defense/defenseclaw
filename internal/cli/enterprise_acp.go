// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/spf13/cobra"
)

var (
	enterpriseACPClient      string
	enterpriseACPAgent       string
	enterpriseACPProfile     string
	enterpriseACPUser        string
	enterpriseACPUserHome    string
	enterpriseACPUID         int
	enterpriseACPGID         int
	enterpriseACPSID         string
	enterpriseACPUserDataDir string
	enterpriseACPJSON        bool
)

const enterpriseACPLongIntro = `Manage administrator-owned ACP enrollments for interactive users.

Each enrollment receives a unique bearer scoped to one principal, editor,
agent, and central policy profile. The service record remains in protected
machine state; only the bearer copy is published into the target user's private
ACP runtime.`

var enterpriseACPCmd = &cobra.Command{
	Use:   "acp",
	Short: "Provision and revoke managed per-user ACP credentials",
	Long: enterpriseACPLongIntro + ` The administrator commands never write an editor profile; the
enrolled user runs "setup" to write their own editor entry.`,
	// Secure Client has no setup command and keeps the help of main (issue
	// #1092).
	Annotations: map[string]string{
		secureClientLongAnnotation: enterpriseACPLongIntro + " The gateway never writes an editor profile or user home.",
	},
	PersistentPreRunE: enterpriseACPPersistentPreRun,
}

// enterpriseACPRootPreRun loads the config; a variable so tests can supply
// one without a managed deployment.
var enterpriseACPRootPreRun = rootPersistentPreRunNoAuditE

func enterpriseACPPersistentPreRun(cmd *cobra.Command, args []string) error {
	// The administrator commands read the managed deployment (GAP-0249).
	// The user-side setup reads no central config and runs as the user
	// (GAP-0254).
	admin := cmd.Annotations["defenseclaw.skip-daemon-bootstrap"] != "true"
	if admin {
		if err := pinEnterpriseACPAdministratorEnv(cmd); err != nil {
			return err
		}
	}
	if err := enterpriseACPRootPreRun(cmd, args); err != nil {
		return err
	}
	if admin {
		// A directory account (AD, SSSD) resolves only through the
		// directory on the static gateway, as in the enterprise hooks
		// commands; without it enroll, verify and revoke refused every
		// such user (GAP-0269).
		configureEnterpriseACPTargetLookup(cmd.Context())
	}
	return nil
}

// pinEnterpriseACPAdministratorEnv points an administrator on a standalone
// host at the managed deployment, as status, audit export and enterprise
// policy do: root on Linux and macOS, an elevated administrator or
// LocalSystem on Windows. Both used to read their own missing per-user
// config.yaml and got the standard-user refusal (GAP-0249).
func pinEnterpriseACPAdministratorEnv(cmd *cobra.Command) error {
	applyManagedStandaloneAdminEnv(cmd.ErrOrStderr())
	return pinManagedAdministratorEnvironment("enterprise acp", func() string {
		return windowsManagedStandardUserViewAnswer("the ACP enrollments",
			"enterprise acp "+cmd.Name()+" --user <name> --client <client> --agent <agent> --profile <profile>")
	})
}

var enterpriseACPEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Provision one exact user/client/agent ACP credential",
	RunE:  runEnterpriseACPEnroll,
}

var enterpriseACPVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify service and user copies for one ACP enrollment",
	RunE:  runEnterpriseACPVerify,
}

var enterpriseACPRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke one exact managed ACP credential",
	RunE:  runEnterpriseACPRevoke,
}

func init() {
	for _, command := range []*cobra.Command{enterpriseACPEnrollCmd, enterpriseACPVerifyCmd, enterpriseACPRevokeCmd} {
		command.Flags().StringVar(&enterpriseACPClient, "client", "", "ACP client ID (for example zed or jetbrains)")
		command.Flags().StringVar(&enterpriseACPAgent, "agent", "", "ACP agent ID (for example kiro)")
		command.Flags().StringVar(&enterpriseACPProfile, "profile", "", "Centrally configured ACP profile")
		command.Flags().StringVar(&enterpriseACPUser, "user", "", "Target local user name")
		command.Flags().StringVar(&enterpriseACPUserHome, "user-home", "", "Target user's home directory")
		command.Flags().IntVar(&enterpriseACPUID, "uid", -1, "Target Unix uid")
		command.Flags().IntVar(&enterpriseACPGID, "gid", -1, "Target Unix gid")
		command.Flags().StringVar(&enterpriseACPSID, "sid", "", "Target Windows user SID")
		command.Flags().StringVar(&enterpriseACPUserDataDir, "data-dir", "", "Per-user runtime data dir (default: <user-home>/.defenseclaw)")
		command.Flags().BoolVar(&enterpriseACPJSON, "json", false, "Emit machine-readable JSON")
	}
	enterpriseACPCmd.AddCommand(enterpriseACPEnrollCmd, enterpriseACPVerifyCmd, enterpriseACPRevokeCmd)
	enterpriseCmd.AddCommand(enterpriseACPCmd)
}

type enterpriseACPEnrollment struct {
	target    enterpriseHookTarget
	principal string
	dataDir   string
	client    string
	agent     string
	profile   string
	// accountGone marks a --uid no account has any more, or a --sid with
	// no profile on this computer: verify and revoke act on its service
	// record only (GAP-0367).
	accountGone bool
}

// enterpriseACPGoneAccount says what is gone of an accountGone enrollment's
// account, and the selector that revokes it.
func enterpriseACPGoneAccount(enrollment enterpriseACPEnrollment) (what, selector string) {
	if sid := strings.TrimSpace(enrollment.target.sid); sid != "" {
		return enrollment.principal + " has no profile on this computer any more", "--sid " + sid
	}
	return enrollment.principal + " no longer exists", fmt.Sprintf("--uid %d", enrollment.target.uid)
}

func resolveEnterpriseACPEnrollment(requireAuthorization bool) (enterpriseACPEnrollment, error) {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return enterpriseACPEnrollment{}, errors.New("enterprise ACP enrollment requires deployment_mode: managed_enterprise")
	}
	client := strings.ToLower(strings.TrimSpace(enterpriseACPClient))
	agent := strings.ToLower(strings.TrimSpace(enterpriseACPAgent))
	profile := strings.TrimSpace(enterpriseACPProfile)
	if client == "" || agent == "" || profile == "" {
		return enterpriseACPEnrollment{}, errors.New("enterprise ACP enrollment requires --client, --agent, and --profile")
	}
	if _, err := acp.LookupAgent(agent); err != nil {
		if !cfg.SecureClientIntegration() {
			// Name the agents that exist (GAP-0355).
			err = fmt.Errorf("%w (the ACP agents are %s)", err, strings.Join(acp.AgentIDs(), ", "))
		}
		return enterpriseACPEnrollment{}, err
	}
	clientKnown := false
	for _, item := range acp.BuiltinCatalog().Clients {
		if item.ID == client {
			clientKnown = true
			break
		}
	}
	if !clientKnown {
		if !cfg.SecureClientIntegration() {
			return enterpriseACPEnrollment{}, fmt.Errorf("unknown ACP client: %s (the ACP clients are %s)", client, strings.Join(enterpriseACPClientIDs(), ", "))
		}
		return enterpriseACPEnrollment{}, fmt.Errorf("unknown ACP client: %s", client)
	}
	if requireAuthorization && !cfg.SecureClientIntegration() {
		if refusals := enterpriseACPAuthorizationRefusals(cfg.ACP, client, agent, profile); len(refusals) > 0 {
			return enterpriseACPEnrollment{}, fmt.Errorf("central ACP policy does not authorize %s/%s in profile %s: %s",
				client, agent, profile, strings.Join(refusals, "; "))
		}
	} else if requireAuthorization {
		// Secure Client keeps the pin-only rule and wording of main.
		clientBinding, clientOK := cfg.ACP.Clients[client]
		agentBinding, agentOK := cfg.ACP.Agents[agent]
		policy, profileOK := cfg.ACP.Profiles[profile]
		if !cfg.ACP.Enabled || !clientOK || !clientBinding.Enabled || clientBinding.Profile != profile ||
			!agentOK || !agentBinding.Enabled || agentBinding.Profile != profile || !profileOK ||
			!slices.Contains(policy.AllowedClients, client) || !slices.Contains(policy.AllowedAgents, agent) {
			return enterpriseACPEnrollment{}, fmt.Errorf(
				"central ACP policy does not explicitly authorize %s/%s in profile %s", client, agent, profile,
			)
		}
	}
	// The principal is the account RunAsTarget proves owns the home the
	// bearer is published to: the uid on Linux and macOS, the SID on
	// Windows. The gateway binds only that kind as the verified subject, so
	// the other kind is refused, not recorded (GAP-0200). Secure Client
	// binds no subject and keeps its selectors.
	if !cfg.SecureClientIntegration() {
		if runtime.GOOS == "windows" && (enterpriseACPUID >= 0 || enterpriseACPGID >= 0) {
			return enterpriseACPEnrollment{}, errors.New("enterprise ACP enrollment: --uid and --gid apply only on Linux and macOS; use --user or --sid")
		}
		if runtime.GOOS != "windows" && strings.TrimSpace(enterpriseACPSID) != "" {
			return enterpriseACPEnrollment{}, errors.New("enterprise ACP enrollment: --sid applies only on Windows; use --user or --uid")
		}
	}
	userHome := enterpriseACPUserHome
	if !cfg.SecureClientIntegration() && runtime.GOOS != "windows" && enterpriseACPUID >= 0 &&
		strings.TrimSpace(enterpriseACPUser) == "" && strings.TrimSpace(userHome) == "" {
		// --uid alone names the account; its home comes from the account
		// database. A deleted account has none, and revoke used to refuse
		// its service record until a --user-home was made up (GAP-0367).
		home, found, lookupErr := enterpriseACPHomeForUID(enterpriseACPUID)
		switch {
		case lookupErr != nil:
			return enterpriseACPEnrollment{}, fmt.Errorf("enterprise acp: look up uid %d: %w", enterpriseACPUID, lookupErr)
		case found:
			userHome = home
		case requireAuthorization:
			return enterpriseACPEnrollment{}, fmt.Errorf("enterprise acp: no account has uid %d on this computer", enterpriseACPUID)
		default:
			return enterpriseACPEnrollment{
				target:    enterpriseHookTarget{uid: enterpriseACPUID, gid: enterpriseACPGID},
				principal: fmt.Sprintf("uid:%d", enterpriseACPUID), client: client, agent: agent, profile: profile,
				accountGone: true,
			}, nil
		}
	}
	if !cfg.SecureClientIntegration() && runtime.GOOS == "windows" && !requireAuthorization &&
		strings.TrimSpace(enterpriseACPSID) != "" && strings.TrimSpace(enterpriseACPUser) == "" && strings.TrimSpace(userHome) == "" {
		// --sid alone names an account whose profile may be gone with it:
		// verify and revoke act on its service record, as --uid does on
		// Linux and macOS. The profile lookup used to fail, so no command
		// could revoke the credential of a deleted account (GAP-0367).
		sid := strings.ToUpper(strings.TrimSpace(enterpriseACPSID))
		if _, profileErr := enterpriseHookSIDProfilePath(sid); errors.Is(profileErr, os.ErrNotExist) {
			return enterpriseACPEnrollment{
				target:    enterpriseHookTarget{uid: -1, gid: -1, sid: sid},
				principal: "sid:" + sid, client: client, agent: agent, profile: profile,
				accountGone: true,
			}, nil
		}
	}
	target, err := resolveEnterpriseHookTargetValues(
		enterpriseACPUser, userHome, enterpriseACPUID, enterpriseACPGID,
		enterpriseACPSID, enterpriseACPUserDataDir,
	)
	if err != nil {
		if !cfg.SecureClientIntegration() {
			return enterpriseACPEnrollment{}, enterpriseACPPlainError(err, enterpriseACPUser)
		}
		return enterpriseACPEnrollment{}, err
	}
	dataDir := strings.TrimSpace(enterpriseACPUserDataDir)
	if dataDir == "" {
		dataDir = filepath.Join(target.home, ".defenseclaw")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return enterpriseACPEnrollment{}, fmt.Errorf("resolve target ACP data dir: %w", err)
	}
	homeAbs, err := filepath.Abs(target.home)
	if err != nil {
		return enterpriseACPEnrollment{}, err
	}
	relative, err := filepath.Rel(homeAbs, abs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return enterpriseACPEnrollment{}, errors.New("enterprise ACP per-user data dir must remain inside the target home")
	}
	principal := strings.TrimSpace(target.sid)
	if principal != "" {
		principal = "sid:" + strings.ToUpper(principal)
	} else if target.uid >= 0 {
		principal = fmt.Sprintf("uid:%d", target.uid)
	} else {
		hash := sha256.Sum256([]byte(filepath.Clean(homeAbs)))
		principal = "home:" + hex.EncodeToString(hash[:])
	}
	return enterpriseACPEnrollment{
		target: target, principal: principal, dataDir: abs, client: client, agent: agent, profile: profile,
	}, nil
}

// enterpriseACPAuthorizationRefusals applies the gateway's rule for a pair
// (config.ACPPairBindingRefusals), with the profile the pair resolves to and
// allow-lists that name the pair explicitly. Enrollment used to require both
// pins to name the profile, so the per-pair bindings the docs describe for
// several agents in one editor were refused, and the refusal did not say
// which pin was missing (GAP-0357).
func enterpriseACPAuthorizationRefusals(policy config.ACPConfig, client, agent, profile string) []string {
	if !policy.Enabled {
		return []string{"acp.enabled is false"}
	}
	var refusals []string
	resolved := policy.ACPProfileForPair(client, agent)
	if resolved == "" {
		resolved = "default"
	}
	if resolved != profile {
		refusals = append(refusals, fmt.Sprintf("the pair resolves to profile %q", resolved))
	}
	refusals = append(refusals, policy.ACPPairBindingRefusals(client, agent, profile)...)
	settings, defined := policy.Profiles[profile]
	if !defined {
		return append(refusals, fmt.Sprintf("acp.profiles.%s is not defined", profile))
	}
	if !slices.Contains(settings.AllowedClients, client) {
		refusals = append(refusals, fmt.Sprintf("acp.profiles.%s.allowed_clients does not name %s", profile, client))
	}
	if !slices.Contains(settings.AllowedAgents, agent) {
		refusals = append(refusals, fmt.Sprintf("acp.profiles.%s.allowed_agents does not name %s", profile, agent))
	}
	return refusals
}

func runEnterpriseACPEnroll(cmd *cobra.Command, _ []string) error {
	enrollment, err := resolveEnterpriseACPEnrollment(true)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	target := enterpriseACPTargetCredentials(enrollment)
	// Prove the bearer can be published as the target user before minting
	// it: a refused target (an elevated prompt instead of LocalSystem, a
	// SYSTEM-owned profile folder, an account the lookup cannot resolve)
	// used to leave a minted, indexed credential that no user held
	// (GAP-0260).
	// Secure Client keeps the order it has on main.
	secureClient := cfg.SecureClientIntegration()
	if !secureClient {
		if home := strings.TrimSpace(enrollment.target.home); home != "" {
			if _, statErr := os.Lstat(home); errors.Is(statErr, os.ErrNotExist) {
				return enterpriseACPResult(cmd, nil, errors.New(enterpriseACPNoHomeText(enterpriseACPWho(enrollment), home, enrollment.target.sid)))
			}
		}
		if err := enterprisehooks.RunAsTarget(target, func() error { return nil }); err != nil {
			return enterpriseACPResult(cmd, nil, enterpriseACPRefusal(err))
		}
	}
	var credential acp.EnterpriseCredential
	minted := false
	// discardMinted removes a credential this call minted when the
	// enrollment does not complete; a re-enrollment keeps the working one.
	discardMinted := func(cause error) error {
		if !minted || secureClient {
			return cause
		}
		if removeErr := withEnterpriseACPServiceOwner(cfg.DataDir, func() error {
			return acp.RemoveEnterpriseCredential(
				cfg.DataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile,
			)
		}); removeErr != nil {
			return fmt.Errorf("%w; the credential this enrollment minted could not be removed, revoke it with the same selectors: %v", cause, removeErr)
		}
		return cause
	}
	err = withEnterpriseACPServiceOwner(cfg.DataDir, func() error {
		existing, loadErr := acp.LoadEnterpriseCredential(
			cfg.DataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile,
		)
		var ensureErr error
		credential, ensureErr = acp.EnsureEnterpriseCredential(
			cfg.DataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile,
		)
		if ensureErr != nil {
			return ensureErr
		}
		minted = loadErr != nil || subtle.ConstantTimeCompare([]byte(existing.Token), []byte(credential.Token)) != 1
		return alignEnterpriseACPCredentialOwner(
			cfg.DataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile, credential.Token,
		)
	})
	if err != nil {
		return enterpriseACPResult(cmd, nil, discardMinted(err))
	}
	var tokenPath string
	err = enterprisehooks.RunAsTarget(target, func() error {
		var publishErr error
		tokenPath, publishErr = acp.PublishEnterpriseUserToken(
			enrollment.dataDir, enrollment.client, enrollment.agent, credential.Token,
		)
		return publishErr
	})
	if err != nil {
		return enterpriseACPResult(cmd, nil, discardMinted(enterpriseACPRefusal(err)))
	}
	payload := map[string]any{
		"ok": true, "principal": enrollment.principal, "client": enrollment.client,
		"agent": enrollment.agent, "profile": enrollment.profile, "token_file": tokenPath,
		"next": enterpriseACPSetupCommand(enrollment, tokenPath),
	}
	if !secureClient {
		// One user copy serves an editor/agent pair, so an enrollment under
		// another profile kept a second live credential and the last enroll
		// overwrote the copy the working entry used (GAP-0733).
		replaced, retireErr := retireEnterpriseACPOtherProfiles(enrollment)
		if len(replaced) > 0 {
			payload["replaced"] = replaced
		}
		if retireErr != nil {
			return enterpriseACPResult(cmd, payload, fmt.Errorf(
				"enterprise acp: enrolled %s %s/%s in profile %s, but its enrollment in another profile could not be revoked: %w; "+
					"revoke it with enterprise acp revoke and the same selectors", enterpriseACPWho(enrollment),
				enrollment.client, enrollment.agent, enrollment.profile, retireErr))
		}
	}
	return enterpriseACPResult(cmd, payload, nil)
}

// retireEnterpriseACPOtherProfiles revokes the enrollments of the same
// account, editor and agent in other profiles and returns those profiles.
func retireEnterpriseACPOtherProfiles(enrollment enterpriseACPEnrollment) (replaced []string, err error) {
	err = withEnterpriseACPServiceOwner(cfg.DataDir, func() error {
		enrollments, _, listErr := acp.ListEnterpriseEnrollments(cfg.DataDir)
		if listErr != nil {
			return listErr
		}
		for _, other := range enrollments {
			if other.Principal != enrollment.principal || other.ClientID != enrollment.client ||
				other.AgentID != enrollment.agent || other.Profile == enrollment.profile {
				continue
			}
			if removeErr := acp.RemoveEnterpriseCredential(cfg.DataDir, other.Principal, other.ClientID, other.AgentID, other.Profile); removeErr != nil {
				return fmt.Errorf("profile %s: %w", other.Profile, removeErr)
			}
			replaced = append(replaced, other.Profile)
		}
		return nil
	})
	return replaced, err
}

// enterpriseACPClientIDs lists the catalog's ACP clients.
func enterpriseACPClientIDs() []string {
	var ids []string
	for _, client := range acp.BuiltinCatalog().Clients {
		ids = append(ids, client.ID)
	}
	slices.Sort(ids)
	return ids
}

// enterpriseACPWho names the account of an enrollment in a message: the
// --user given, else the principal.
func enterpriseACPWho(enrollment enterpriseACPEnrollment) string {
	if name := strings.TrimSpace(enterpriseACPUser); name != "" {
		return name
	}
	if strings.HasPrefix(enrollment.principal, "home:") && enrollment.target.home != "" {
		// A digest of the folder named nothing the administrator typed.
		return "the owner of " + enrollment.target.home
	}
	return enrollment.principal
}

// enterpriseACPPlainError words a refusal of the shared account resolution
// for the ACP commands: it named the enterprise hooks commands and gave an
// unknown account as an os/user lookup error (GAP-0355).
func enterpriseACPPlainError(err error, userName string) error {
	if enterpriseACPUnknownAccount(err) && strings.TrimSpace(userName) != "" {
		// On Windows it was the LSA text with the name quoted, so every
		// backslash doubled (GAP-0735).
		return &enterpriseACPTargetRefusal{err: err, message: enterpriseACPNoAccountText(strings.TrimSpace(userName))}
	}
	if rest, ok := strings.CutPrefix(err.Error(), "enterprise hooks: "); ok {
		return &enterpriseACPTargetRefusal{err: err, message: "enterprise acp: " + rest}
	}
	return err
}

func enterpriseACPTargetCredentials(enrollment enterpriseACPEnrollment) enterprisehooks.TargetCredentials {
	return enterprisehooks.TargetCredentials{
		UserHome: enrollment.target.home, UID: enrollment.target.uid,
		GID: enrollment.target.gid, SID: enrollment.target.sid,
	}
}

// enterpriseACPQuotePath formats a path for the shell shown to the user.
func enterpriseACPQuotePath(path string, windows bool) string {
	if windows {
		return "'" + strings.ReplaceAll(path, "'", "''") + "'"
	}
	return fmt.Sprintf("%q", path)
}

// enterpriseACPSetupCommand is the user-side command an enrollment reports:
// this executable's own setup subcommand, because a managed host has no other
// DefenseClaw command to run (GAP-0254). Secure Client has no setup
// subcommand and reports the step of main (issue #1092).
func enterpriseACPSetupCommand(enrollment enterpriseACPEnrollment, tokenPath string) string {
	executable, guard := managedHostGatewayCommand(), "defenseclaw-acp"
	if path, err := os.Executable(); err == nil {
		executable = path
		guard = filepath.Join(filepath.Dir(path), "defenseclaw-acp"+filepath.Ext(path))
	}
	activate := ""
	mode := strings.TrimSpace(cfg.ACP.Mode)
	if mode == "" {
		mode = "observe"
	}
	if profile, ok := cfg.ACP.Profiles[enrollment.profile]; ok && strings.TrimSpace(profile.Mode) != "" {
		mode = strings.TrimSpace(profile.Mode)
	}
	if mode == "action" {
		activate = " --activate"
	}
	if cfg.SecureClientIntegration() {
		return fmt.Sprintf(
			"defenseclaw acp setup --managed --client %s --agent %s --profile %s%s --runtime-data-dir %q --token-file %q --guard-binary %q",
			enrollment.client, enrollment.agent, enrollment.profile, activate, enrollment.dataDir, tokenPath, guard,
		)
	}
	quote := func(path string) string { return enterpriseACPQuotePath(path, runtime.GOOS == "windows") }
	invoke := quote(executable)
	if runtime.GOOS == "windows" {
		invoke = "& " + invoke
	}
	return fmt.Sprintf(
		"%s enterprise acp setup --client %s --agent %s --profile %s%s --data-dir %s --api-port %d --guard-binary %s",
		invoke, enrollment.client, enrollment.agent, enrollment.profile, activate, quote(enrollment.dataDir), cfg.Gateway.APIPort, quote(guard),
	)
}

func runEnterpriseACPVerify(cmd *cobra.Command, _ []string) error {
	enrollment, err := resolveEnterpriseACPEnrollment(false)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	credential, err := acp.LoadEnterpriseCredential(
		cfg.DataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile,
	)
	if err != nil && errors.Is(err, os.ErrNotExist) && !cfg.SecureClientIntegration() {
		// The record path in an lstat error said nothing (GAP-0355).
		err = fmt.Errorf("enterprise acp: no ACP enrollment for %s %s/%s in profile %s; enroll it with enterprise acp enroll",
			enterpriseACPWho(enrollment), enrollment.client, enrollment.agent, enrollment.profile)
	}
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	if enrollment.accountGone {
		what, selector := enterpriseACPGoneAccount(enrollment)
		return enterpriseACPResult(cmd, nil, fmt.Errorf(
			"enterprise acp: %s, but its ACP enrollment for %s/%s in profile %s is still valid; revoke it with enterprise acp revoke %s --client %s --agent %s --profile %s",
			what, enrollment.client, enrollment.agent, enrollment.profile,
			selector, enrollment.client, enrollment.agent, enrollment.profile))
	}
	tokenPath, err := acp.EnterpriseUserTokenPath(enrollment.dataDir, enrollment.client, enrollment.agent)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	setupDone := false
	err = enterprisehooks.RunAsTarget(enterpriseACPTargetCredentials(enrollment), func() error {
		if !cfg.SecureClientIntegration() {
			lock := acpContractLockPath(enrollment.dataDir, enrollment.client, enrollment.agent)
			if info, statErr := os.Lstat(lock); statErr == nil && info.Mode().IsRegular() {
				setupDone = true
			}
		}
		if err := safefile.ValidatePrivateFile(tokenPath); err != nil {
			if errors.Is(err, os.ErrNotExist) && !cfg.SecureClientIntegration() {
				// Nothing restores a deleted copy; enrolling again
				// publishes the same credential (GAP-0391).
				return fmt.Errorf("enterprise acp: the user's copy of the credential is missing (%s); "+
					"run enterprise acp enroll with the same selectors to publish it again", tokenPath)
			}
			return err
		}
		body, err := safefile.ReadRegularFileBounded(tokenPath, 16<<10)
		if err != nil {
			return err
		}
		left := sha256.Sum256([]byte(strings.TrimSpace(string(body))))
		right := sha256.Sum256([]byte(credential.Token))
		if subtle.ConstantTimeCompare(left[:], right[:]) != 1 {
			return errors.New("target-user ACP token does not match the protected service enrollment")
		}
		return nil
	})
	if err != nil {
		return enterpriseACPResult(cmd, nil, enterpriseACPRefusal(err))
	}
	payload := map[string]any{
		"ok": true, "principal": enrollment.principal, "client": enrollment.client,
		"agent": enrollment.agent, "profile": enrollment.profile, "token_file": tokenPath,
	}
	if !cfg.SecureClientIntegration() {
		// A published token is not a working editor entry: verify was green
		// for users who never ran setup (GAP-0400).
		payload["setup_done"] = setupDone
		payload["setup_note"] = "the user has run setup (the contract lock is present)"
		if !setupDone {
			payload["setup_note"] = "the user has not run setup yet; as that user, run: " + enterpriseACPSetupCommand(enrollment, tokenPath)
		}
	}
	return enterpriseACPResult(cmd, payload, nil)
}

func runEnterpriseACPRevoke(cmd *cobra.Command, _ []string) error {
	enrollment, err := resolveEnterpriseACPEnrollment(false)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	// Revoke centrally first. From this point a copied or cached bearer has no
	// authority even if user-side cleanup is interrupted.
	found := true
	if err := withEnterpriseACPServiceOwner(cfg.DataDir, func() error {
		if !cfg.SecureClientIntegration() {
			// A revoke of an enrollment that never existed said "revoked"
			// (GAP-0355).
			found = enterpriseACPRecordExists(cfg.DataDir, enrollment)
		}
		return acp.RemoveEnterpriseCredential(
			cfg.DataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile,
		)
	}); err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	notFound := ""
	if !found {
		notFound = fmt.Sprintf("no ACP enrollment for %s %s/%s in profile %s was found; nothing was revoked",
			enterpriseACPWho(enrollment), enrollment.client, enrollment.agent, enrollment.profile)
	}
	if enrollment.accountGone {
		// No account, so no home to clean.
		what, _ := enterpriseACPGoneAccount(enrollment)
		return enterpriseACPResult(cmd, enterpriseACPRevokePayload(map[string]any{
			"ok": true, "principal": enrollment.principal, "client": enrollment.client,
			"agent": enrollment.agent, "profile": enrollment.profile, "centrally_revoked": true,
			"note": what + "; its home was not touched",
		}, notFound), nil)
	}
	tokenPath, err := acp.EnterpriseUserTokenPath(enrollment.dataDir, enrollment.client, enrollment.agent)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	err = enterprisehooks.RunAsTarget(enterpriseACPTargetCredentials(enrollment), func() error {
		return removeEnterpriseACPUserTokenCopy(tokenPath)
	})
	note := ""
	if !cfg.SecureClientIntegration() && found && enterpriseACPSignedOut(err) {
		// Access is revoked; only the user's inert copy waits for the user
		// (GAP-0718).
		note, err = enterpriseACPDeferUserCopyCleanup(enrollment, tokenPath), nil
	}
	err = enterpriseACPRefusal(err)
	if !cfg.SecureClientIntegration() && err != nil {
		switch {
		case !found:
			// Nothing was revoked, so the copy is only tidying; the error
			// used to say the service record was removed (GAP-0355).
			note, err = "the user's copy was not checked: "+strings.TrimPrefix(err.Error(), "enterprise acp: "), nil
		case errors.Is(err, os.ErrNotExist):
			// The home is gone with its account: nothing is left to remove,
			// and the revoke used to end in an error (GAP-0367).
			note, err = "the home "+enrollment.target.home+" no longer exists; nothing was left there to remove", nil
		default:
			err = fmt.Errorf("enterprise acp: the service record was removed, so the credential no longer works, "+
				"but the user's copy %s could not be removed: %w", tokenPath, err)
		}
	}
	payload := map[string]any{
		"ok": err == nil, "principal": enrollment.principal, "client": enrollment.client,
		"agent": enrollment.agent, "profile": enrollment.profile, "token_file": tokenPath,
		"centrally_revoked": true,
	}
	if note != "" {
		payload["note"] = note
	}
	return enterpriseACPResult(cmd, enterpriseACPRevokePayload(payload, notFound), err)
}

// enterpriseACPRevokePayload marks a revoke that found no enrollment.
func enterpriseACPRevokePayload(payload map[string]any, notFound string) map[string]any {
	if notFound != "" {
		payload["centrally_revoked"], payload["found"], payload["not_found"] = false, false, notFound
	}
	return payload
}

// enterpriseACPRecordExists reports whether the service record of an
// enrollment, or the tombstone of an interrupted revocation, is present.
func enterpriseACPRecordExists(dataDir string, enrollment enterpriseACPEnrollment) bool {
	path, err := acp.EnterpriseCredentialPath(dataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile)
	if err != nil {
		return true
	}
	for _, candidate := range []string{path, path + ".revoked"} {
		if _, statErr := os.Lstat(candidate); !errors.Is(statErr, os.ErrNotExist) {
			return true
		}
	}
	return false
}

func enterpriseACPResult(cmd *cobra.Command, payload map[string]any, err error) error {
	if enterpriseACPJSON {
		if payload == nil {
			payload = map[string]any{"ok": false}
		}
		if err != nil {
			payload["ok"] = false
			payload["error"] = err.Error()
		}
		if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(payload); encodeErr != nil {
			return encodeErr
		}
		if err != nil {
			return errors.New("enterprise ACP operation failed")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if next, ok := payload["next"].(string); ok {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s managed ACP credential enrolled\n", Style("✓", "fg=green", "bold"))
		if replaced, _ := payload["replaced"].([]string); len(replaced) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "    it replaces the %s/%s enrollment in profile %s, whose credential no longer works\n",
				payload["client"], payload["agent"], strings.Join(replaced, ", "))
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  Next (as target user): %s\n", next)
		return nil
	}
	if lock, ok := payload["contract_lock"].(string); ok {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s guarded %v entry written to %v (contract lock %s)\n",
			Style("✓", "fg=green", "bold"), payload["agent"], payload["path"], lock)
		return nil
	}
	if notFound, _ := payload["not_found"].(string); notFound != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s %s\n", Style("!", "fg=yellow", "bold"), notFound)
		if note, _ := payload["note"].(string); note != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", note)
		}
		return nil
	}
	if revoked, _ := payload["centrally_revoked"].(bool); revoked {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s managed ACP credential revoked\n", Style("✓", "fg=green", "bold"))
		if note, _ := payload["note"].(string); note != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", note)
		}
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  %s managed ACP credential verified\n", Style("✓", "fg=green", "bold"))
	if note, _ := payload["setup_note"].(string); note != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", note)
	}
	return nil
}

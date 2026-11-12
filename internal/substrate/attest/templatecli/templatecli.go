// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package templatecli is the logic of "defenseclaw substrate template
// build|verify|scan|publish|keygen". The launcher's command tree (A6) calls
// Run with the arguments after "template"; test/substrate/a9tool wraps it
// for the live cells. Every read command takes --json.
package templatecli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest/kitspec"
)

// Exit codes.
const (
	ExitOK         = 0
	ExitNotAdmit   = 1 // verify: not admitted; build and scan: blocked
	ExitUsageError = 2
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// common holds the flags every subcommand shares.
type common struct {
	json       bool
	plain      multi
	user       string
	passFile   string
	configPath string
	platform   string
}

func (c *common) bind(fs *flag.FlagSet) {
	fs.BoolVar(&c.json, "json", false, "print JSON")
	fs.Var(&c.plain, "insecure-registry", "registry host:port reached over plain HTTP (repeatable)")
	fs.StringVar(&c.user, "registry-user", "", "registry user")
	fs.StringVar(&c.passFile, "registry-password-file", "", "file with the registry password")
	fs.StringVar(&c.configPath, "config", "", "DefenseClaw config.yaml (scanner and admission settings)")
	fs.StringVar(&c.platform, "platform", "linux/amd64", "image platform")
}

func (c *common) registry() (*attest.Registry, error) {
	o := attest.RegistryOptions{PlainHTTP: c.plain, Username: c.user}
	if c.passFile != "" {
		b, err := os.ReadFile(c.passFile)
		if err != nil {
			return nil, err
		}
		o.Password = strings.TrimSpace(string(b))
	}
	return attest.NewRegistry(o), nil
}

func (c *common) platformValue() (attest.Platform, error) {
	os_, arch, ok := strings.Cut(c.platform, "/")
	if !ok || os_ == "" || arch == "" {
		return attest.Platform{}, fmt.Errorf("--platform wants os/arch, got %q", c.platform)
	}
	return attest.Platform{OS: os_, Architecture: arch}, nil
}

func (c *common) config() (*config.Config, error) {
	if c.configPath == "" {
		return &config.Config{}, nil
	}
	return config.LoadFromFile(c.configPath)
}

// Run executes one template subcommand and returns the exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsageError
	}
	var err error
	code := ExitOK
	switch args[0] {
	case "build":
		code, err = runBuild(ctx, args[1:], stdout)
	case "verify":
		code, err = runVerify(ctx, args[1:], stdout)
	case "scan":
		code, err = runScan(ctx, args[1:], stdout)
	case "publish":
		code, err = runPublish(ctx, args[1:], stdout)
	case "keygen":
		code, err = runKeygen(args[1:], stdout)
	case "help", "-h", "--help":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "unknown template command %q\n", args[0])
		usage(stderr)
		return ExitUsageError
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		if code == ExitOK {
			code = ExitUsageError
		}
	}
	return code
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: template <command> [flags]

  build    --connector C --from IMAGE --to REPO:TAG --hook-binary F --relay-binary F --key F [--trusted-base sha256:...]
  verify   IMAGE --anchors F [--min-policy-generation N] [--max-age 720h]
  scan     IMAGE
  publish  SOURCE@DIGEST TARGET:TAG --anchors F [--template ATESPACE/NAME [--class C] [--cpu N] [--memory N] [--env K=V] ...] [--dry-run]
  keygen   --out DIR

Every command takes --json.
`)
}

// scanners builds the scanners from the config.
func scanners(cfg *config.Config, noMCP bool, analyzers string) (scanner.Scanner, scanner.Scanner) {
	skill := scanner.NewSkillScannerFromLLM(cfg.Scanners.SkillScanner, cfg.ResolveLLM("scanners.skill"), cfg.CiscoAIDefense)
	if noMCP {
		return skill, nil
	}
	return skill, &attest.MCPStaticScanner{Analyzers: analyzers}
}

func parseFloor(s string) (scanner.Severity, error) {
	switch strings.ToLower(s) {
	case "", "high":
		return scanner.SeverityHigh, nil
	case "critical":
		return scanner.SeverityCritical, nil
	case "medium":
		return scanner.SeverityMedium, nil
	case "low":
		return scanner.SeverityLow, nil
	case "none":
		return attest.FloorNone, nil
	}
	return "", fmt.Errorf("--block-at wants critical, high, medium, low or none, got %q", s)
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ---------------------------------------------------------------- build

// BuildOutput is `template build --json`.
type BuildOutput struct {
	Pushed  bool               `json:"pushed"`
	Blocked bool               `json:"blocked"`
	Error   string             `json:"error,omitempty"`
	Image   string             `json:"image,omitempty"`
	Digest  string             `json:"digest,omitempty"`
	Base    attest.BaseInfo    `json:"base"`
	Kit     attest.KitInfo     `json:"kit"`
	Hooks   attest.HookChecks  `json:"hooks"`
	Scan    attest.ScanSummary `json:"scan"`
	KeyID   string             `json:"key_id,omitempty"`
	AttTag  string             `json:"attestation_tag,omitempty"`
}

func runBuild(ctx context.Context, args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	var c common
	c.bind(fs)
	var (
		connectorName = fs.String("connector", "claudecode", "claudecode or codex")
		from          = fs.String("from", "", "base image (the OpenShell harness image for the connector, with tmux)")
		to            = fs.String("to", "", "target repository and tag")
		kitVersion    = fs.String("kit-version", "dev", "kit version")
		hookBin       = fs.String("hook-binary", "", "defenseclaw-actor-hook (linux static)")
		relayBin      = fs.String("relay-binary", "", "defenseclaw-actor-relay (linux static)")
		keyFile       = fs.String("key", "", "attestation private key (PEM, mode 0600)")
		anchors       = fs.String("anchors", "", "trust anchors, to let an attested base count as trusted")
		allowUnv      = fs.Bool("allow-unverified-base", false, "build on a base that is not trusted (the cluster will refuse it by default)")
		blockAt       = fs.String("block-at", "high", "lowest finding severity that blocks the build (critical, high, medium, low, none)")
		gen           = fs.Int64("policy-generation", 1, "policy generation recorded in the attestation")
		builder       = fs.String("builder-id", "", "builder id recorded in the attestation")
		provider      = fs.String("provider", "", "model route (claudecode: bedrock|anthropic; codex: openai|bedrock-mantle)")
		model         = fs.String("model", "", "default model id")
		gateway       = fs.String("gateway-url", "", "actor listener URL (default the in-cluster Service)")
		failMode      = fs.String("fail-mode", "", "interactive outage mode: open or closed")
		noMCP         = fs.Bool("no-mcp-static", false, "do not run mcp-scanner over tool descriptions")
		analyzers     = fs.String("mcp-analyzers", "yara", "mcp-scanner analyzers")
		keepEP        = fs.Bool("keep-entrypoint", false, "keep the base image ENTRYPOINT and CMD (tests; a real actor image starts the relay)")
		dry           = fs.Bool("dry-run", false, "scan the composed image and stop before pushing")
		trusted       multi
		mcpHosts      multi
		sessionKeys   multi
	)
	fs.Var(&trusted, "trusted-base", "base image digest the admin trusts (repeatable)")
	fs.Var(&mcpHosts, "mcp-host", "remote MCP host that is allowed (repeatable)")
	fs.Var(&sessionKeys, "session-key", "relay session public key, kid=PEM file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return ExitUsageError, nil
	}
	if *from == "" || *to == "" || *hookBin == "" || *relayBin == "" || (*keyFile == "" && !*dry) {
		return ExitUsageError, errors.New("build needs --from, --to, --hook-binary, --relay-binary and --key")
	}
	reg, err := c.registry()
	if err != nil {
		return ExitUsageError, err
	}
	plat, err := c.platformValue()
	if err != nil {
		return ExitUsageError, err
	}
	cfg, err := c.config()
	if err != nil {
		return ExitUsageError, err
	}
	floor, err := parseFloor(*blockAt)
	if err != nil {
		return ExitUsageError, err
	}
	hook, err := os.ReadFile(*hookBin)
	if err != nil {
		return ExitUsageError, err
	}
	relay, err := os.ReadFile(*relayBin)
	if err != nil {
		return ExitUsageError, err
	}
	keys := map[string][]byte{}
	for _, kv := range sessionKeys {
		kid, file, ok := strings.Cut(kv, "=")
		if !ok {
			return ExitUsageError, fmt.Errorf("--session-key wants kid=path, got %q", kv)
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return ExitUsageError, err
		}
		keys[kid] = b
	}
	spec, tpl, harnessVersion, err := kitspec.Spec(kitspec.Options{Connector: *connectorName, KitVersion: *kitVersion, GatewayURL: *gateway,
		FailMode: *failMode, Provider: *provider, Model: *model, HookBinary: hook, RelayBinary: relay, SessionKeys: keys,
		Providers: providers(*connectorName, *provider)})
	if err != nil {
		return ExitUsageError, err
	}
	if *keepEP {
		spec.Entrypoint, spec.Cmd = nil, nil
	}
	var signer *attest.Signer
	if *keyFile != "" {
		if signer, err = attest.LoadSigner(*keyFile); err != nil {
			return ExitUsageError, err
		}
	}
	skill, mcp := scanners(cfg, *noMCP, *analyzers)
	opts := attest.BuildOptions{
		Registry: reg, Base: *from, Target: *to, Template: tpl, Kit: spec, Signer: signer,
		Skill: skill, MCPStatic: mcp, Compiled: policy.CompileAdmission(cfg),
		AllowedMCPHosts: mcpHosts, BlockAtOrAbove: floor,
		TrustedBases: trusted, AllowUnverifiedBase: *allowUnv, PolicyGeneration: *gen, BuilderID: *builder,
		Platform: plat, DryRun: *dry,
	}
	if *anchors != "" {
		ta, err := attest.LoadAnchors(*anchors)
		if err != nil {
			return ExitUsageError, err
		}
		opts.BaseAttestor = attest.NewVerifier(reg, func() attest.Policy {
			return attest.Policy{Anchors: ta, AllowUnverifiedBase: true}
		})
	}
	_ = harnessVersion
	res, err := attest.Build(ctx, opts)
	out := BuildOutput{}
	if res != nil {
		out.Base, out.Kit, out.Digest, out.Pushed = res.Base, res.Kit, res.Digest, res.Pushed
		if res.Report != nil {
			out.Hooks, out.Scan = res.Report.Hooks, res.Report.Summary
		}
		if res.Pushed {
			out.Image = res.Target[:strings.LastIndex(res.Target, ":")] + "@" + res.Digest
			out.AttTag, _ = attest.AttestationTag(res.Digest)
			out.KeyID = signer.KeyID()
		}
	}
	code := ExitOK
	var blocked *attest.BuildBlocked
	switch {
	case errors.As(err, &blocked):
		out.Blocked, out.Error, code = true, err.Error(), ExitNotAdmit
		err = nil
	case errors.Is(err, attest.ErrBaseUnverified):
		out.Blocked, out.Error, code = true, err.Error(), ExitNotAdmit
		err = nil
	case err != nil:
		return ExitUsageError, err
	}
	if c.json {
		return code, printJSON(stdout, out)
	}
	printBuild(stdout, out, *dry)
	return code, err
}

func providers(connectorName, provider string) []string {
	if provider != "" {
		return []string{provider}
	}
	return nil
}

func printBuild(w io.Writer, o BuildOutput, dry bool) {
	switch {
	case o.Blocked:
		fmt.Fprintf(w, "BLOCKED: %s\n", o.Error)
	case dry:
		fmt.Fprintf(w, "dry run: the image would be attested (scan verdict %s)\n", o.Scan.Verdict)
	default:
		fmt.Fprintf(w, "built %s\n  kit %s on base %s (%s)\n  attestation %s signed by key %s\n", o.Image, o.Kit.Version, o.Base.Digest, o.Base.Trust, o.AttTag, short(o.KeyID))
	}
	printScan(w, o.Scan, o.Hooks)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func printScan(w io.Writer, s attest.ScanSummary, h attest.HookChecks) {
	fmt.Fprintf(w, "scanned %d skills, %d MCP servers, %d plugins; verdict %s; findings", s.Skills, s.MCPServers, s.Plugins, s.Verdict)
	for _, k := range []string{"critical", "high", "medium", "low", "info"} {
		fmt.Fprintf(w, " %s=%d", k, s.Findings[k])
	}
	fmt.Fprintln(w)
	for _, it := range s.Items {
		if it.Verdict != attest.VerdictClean || it.Findings > 0 {
			fmt.Fprintf(w, "  %-5s %s %s (%s) %s\n", strings.ToUpper(it.Verdict), it.Kind, it.Name, it.Path, it.Reason)
		}
	}
	fmt.Fprintf(w, "hook files root-owned: %v; phone-home switches off: %v\n", h.RootOwned, h.PhoneHomeOff)
	for _, f := range h.Files {
		if !f.OK {
			fmt.Fprintf(w, "  %s: %s\n", f.Path, f.Note)
		}
	}
	for _, sw := range h.Switches {
		if !sw.OK {
			fmt.Fprintf(w, "  switch %s is not set\n", sw.Name)
		}
	}
}

// --------------------------------------------------------------- verify

// VerifyOutput is `template verify --json`.
type VerifyOutput struct {
	Admitted  bool                 `json:"admitted"`
	Image     string               `json:"image"`
	Digest    string               `json:"digest,omitempty"`
	Code      string               `json:"code,omitempty"`
	Reason    string               `json:"reason,omitempty"`
	Retryable bool                 `json:"retryable,omitempty"`
	KeyID     string               `json:"key_id,omitempty"`
	Template  *attest.TemplateInfo `json:"template,omitempty"`
	Kit       *attest.KitInfo      `json:"kit,omitempty"`
	Base      *attest.BaseInfo     `json:"base,omitempty"`
	Scan      *attest.ScanSummary  `json:"scan,omitempty"`
	PolicyGen int64                `json:"policy_generation,omitempty"`
	BuiltAt   *time.Time           `json:"built_at,omitempty"`
}

func runVerify(ctx context.Context, args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var c common
	c.bind(fs)
	anchors := fs.String("anchors", "", "trust anchors (PEM bundle of public keys)")
	minGen := fs.Int64("min-policy-generation", 0, "refuse attestations scanned under an older policy generation")
	maxAge := fs.Duration("max-age", 0, "refuse attestations older than this")
	allowUnv := fs.Bool("allow-unverified-base", false, "admit a template built on an untrusted base")
	allowTag := fs.Bool("allow-tag", false, "accept a tag reference (it can move; pin by digest in templates)")
	var revoked multi
	fs.Var(&revoked, "revoke", "key id to refuse (repeatable)")
	image, rest := splitFirst(args)
	if err := fs.Parse(rest); err != nil {
		return ExitUsageError, nil
	}
	if image == "" || *anchors == "" {
		return ExitUsageError, errors.New("verify needs an image and --anchors")
	}
	reg, err := c.registry()
	if err != nil {
		return ExitUsageError, err
	}
	ta, err := attest.LoadAnchors(*anchors)
	if err != nil {
		return ExitUsageError, err
	}
	for _, k := range revoked {
		ta.Revoke(k)
	}
	v := attest.NewVerifier(reg, func() attest.Policy {
		return attest.Policy{Anchors: ta, MinPolicyGeneration: *minGen, MaxAge: *maxAge, AllowUnverifiedBase: *allowUnv, RequireDigest: !*allowTag}
	})
	got, verr := v.Verify(ctx, image)
	out := VerifyOutput{Image: image}
	code := ExitOK
	if verr != nil {
		out.Admitted, code = false, ExitNotAdmit
		if r, ok := attest.AsRejection(verr); ok {
			out.Code, out.Reason, out.Retryable = r.Code, r.Detail, r.Retryable
		} else {
			out.Code, out.Reason = "error", verr.Error()
		}
	} else {
		p := got.Statement.Predicate
		out.Admitted, out.Digest, out.KeyID = true, got.Digest, got.KeyID
		out.Template, out.Kit, out.Base, out.Scan = &p.Template, &p.Kit, &p.Base, &p.Scan
		out.PolicyGen, out.BuiltAt = p.Policy.Generation, &p.Builder.BuiltAt
	}
	if c.json {
		return code, printJSON(stdout, out)
	}
	if !out.Admitted {
		fmt.Fprintf(stdout, "NOT ADMITTED: %s: %s\n", out.Code, out.Reason)
		return code, nil
	}
	fmt.Fprintf(stdout, "ADMITTED %s\n  connector %s, kit %s (hook contract %s), base %s (%s)\n  scan %s: %d skills, %d MCP servers; policy generation %d; signed by key %s\n",
		out.Digest, out.Template.Connector, out.Kit.Version, out.Kit.HookContract, short(out.Base.Digest), out.Base.Trust,
		out.Scan.Verdict, out.Scan.Skills, out.Scan.MCPServers, out.PolicyGen, short(out.KeyID))
	return code, nil
}

// splitFirst returns the first argument when it is not a flag.
func splitFirst(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// ----------------------------------------------------------------- scan

// ScanOutput is `template scan --json`.
type ScanOutput struct {
	Image   string             `json:"image"`
	Digest  string             `json:"digest"`
	Blocked bool               `json:"blocked"`
	Scan    attest.ScanSummary `json:"scan"`
	Hooks   attest.HookChecks  `json:"hooks"`
}

func runScan(ctx context.Context, args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var c common
	c.bind(fs)
	noMCP := fs.Bool("no-mcp-static", false, "do not run mcp-scanner over tool descriptions")
	analyzers := fs.String("mcp-analyzers", "yara", "mcp-scanner analyzers")
	blockAt := fs.String("block-at", "high", "lowest finding severity that blocks (critical, high, medium, low, none)")
	connectorName := fs.String("connector", "", "check the kit's hook files and switches for this connector (claudecode or codex)")
	var mcpHosts multi
	fs.Var(&mcpHosts, "mcp-host", "remote MCP host that is allowed (repeatable)")
	image, rest := splitFirst(args)
	if err := fs.Parse(rest); err != nil {
		return ExitUsageError, nil
	}
	if image == "" {
		return ExitUsageError, errors.New("scan needs an image")
	}
	reg, err := c.registry()
	if err != nil {
		return ExitUsageError, err
	}
	plat, err := c.platformValue()
	if err != nil {
		return ExitUsageError, err
	}
	cfg, err := c.config()
	if err != nil {
		return ExitUsageError, err
	}
	floor, err := parseFloor(*blockAt)
	if err != nil {
		return ExitUsageError, err
	}
	skill, mcp := scanners(cfg, *noMCP, *analyzers)
	so := attest.ScanOptions{Skill: skill, MCPStatic: mcp, Compiled: policy.CompileAdmission(cfg), AllowedMCPHosts: mcpHosts, BlockAtOrAbove: floor}
	if *connectorName != "" {
		spec, _, _, err := kitspec.Spec(kitspec.Options{Connector: *connectorName, KitVersion: "scan", HookBinary: []byte("x"), RelayBinary: []byte("x")})
		if err != nil {
			return ExitUsageError, err
		}
		so.Connector, so.PhoneHome, so.ConfigSwitches = *connectorName, spec.PhoneHome, spec.ConfigSwitches
		for _, f := range spec.Files {
			if !spec.UserFiles[f.Path] && !f.Dir && f.Symlink == "" {
				so.Expected = append(so.Expected, attest.ExpectedFile{Path: f.Path})
			}
		}
	}
	rep, digest, err := attest.ScanOnly(ctx, reg, image, plat, attest.Limits{}, so)
	if err != nil {
		return ExitUsageError, err
	}
	out := ScanOutput{Image: image, Digest: digest, Scan: rep.Summary, Hooks: rep.Hooks, Blocked: rep.Summary.Verdict == attest.VerdictBlock}
	code := ExitOK
	if out.Blocked {
		code = ExitNotAdmit
	}
	if c.json {
		return code, printJSON(stdout, out)
	}
	fmt.Fprintf(stdout, "%s\n", digest)
	printScan(stdout, rep.Summary, rep.Hooks)
	return code, nil
}

// -------------------------------------------------------------- publish

func runPublish(ctx context.Context, args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	var c common
	c.bind(fs)
	anchors := fs.String("anchors", "", "trust anchors (PEM bundle of public keys)")
	minGen := fs.Int64("min-policy-generation", 0, "refuse attestations scanned under an older policy generation")
	var tf templateFlags
	tf.bind(fs)
	var pos []string
	rest := args
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		pos, rest = append(pos, rest[0]), rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return ExitUsageError, nil
	}
	if len(pos) != 2 || *anchors == "" {
		return ExitUsageError, errors.New("publish needs SOURCE TARGET:TAG and --anchors")
	}
	reg, err := c.registry()
	if err != nil {
		return ExitUsageError, err
	}
	ta, err := attest.LoadAnchors(*anchors)
	if err != nil {
		return ExitUsageError, err
	}
	cfg, err := c.config()
	if err != nil {
		return ExitUsageError, err
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	plan, err := tf.plan(cfg, given)
	if err != nil {
		return ExitUsageError, err
	}
	v := attest.NewVerifier(reg, func() attest.Policy {
		return attest.Policy{Anchors: ta, MinPolicyGeneration: *minGen, RequireDigest: true}
	})
	if tf.dryRun {
		return runPublishDry(ctx, &c, v, plan, pos, stdout)
	}
	// With --template, find out first that the API answers: nothing is
	// copied to a cluster whose template cannot then be created.
	var api ateapi.Client
	if plan != nil {
		if api, err = dialAPI(plan.API); err != nil {
			return ExitUsageError, fmt.Errorf("connect to the Substrate API: %w (set --api-address, --api-ca-file and --api-token-file, or --config with substrate.api)", err)
		}
		defer api.Close()
		if _, err := getTemplate(ctx, api, plan.Atespace, plan.Name); err != nil {
			return apiFailure(err)
		}
	}
	ref, err := publishImage(ctx, attest.PublishOptions{Registry: reg, Source: pos[0], Target: pos[1], Verifier: v})
	if err != nil {
		return publishRejected(&c, stdout, err, "NOT PUBLISHED")
	}
	if plan == nil {
		if c.json {
			return ExitOK, printJSON(stdout, map[string]any{"published": true, "image": ref})
		}
		fmt.Fprintf(stdout, "published %s\n", ref)
		return ExitOK, nil
	}
	res, err := applyTemplate(ctx, api, plan, ref)
	if err != nil {
		if c.json {
			_ = printJSON(stdout, map[string]any{"published": true, "image": ref, "template_error": err.Error()})
		} else {
			fmt.Fprintf(stdout, "published %s\nthe template was not created; run the same command again once this is fixed\n", ref)
		}
		return apiFailure(err)
	}
	if c.json {
		return ExitOK, printJSON(stdout, map[string]any{"published": true, "image": ref, "template": res})
	}
	fmt.Fprintf(stdout, "published %s\n", ref)
	printResult(stdout, res)
	return ExitOK, nil
}

// publishRejected prints a verification failure (exit 1) or returns any other
// error as a usage error.
func publishRejected(c *common, stdout io.Writer, err error, head string) (int, error) {
	var r *attest.Rejection
	if !errors.As(err, &r) {
		return ExitUsageError, err
	}
	if c.json {
		_ = printJSON(stdout, map[string]any{"published": false, "code": r.Code, "reason": r.Detail})
	} else {
		fmt.Fprintf(stdout, "%s: %s: %s\n", head, r.Code, r.Detail)
	}
	return ExitNotAdmit, nil
}

// apiFailure maps an API error to its exit code: 75 when the API cannot be
// reached, 1 for anything the API refused. The error text is returned to the
// caller (the CLI prints it on stderr).
func apiFailure(err error) (int, error) {
	var un *templateUnavailable
	if errors.As(err, &un) {
		return ExitUnavailable, err
	}
	return ExitNotAdmit, err
}

// runPublishDry verifies the image and prints what publish would copy and
// create. It copies nothing and does not contact the Substrate API.
func runPublishDry(ctx context.Context, c *common, v *attest.Verifier, plan *templatePlan, pos []string, stdout io.Writer) (int, error) {
	dst, err := attest.ParseRef(pos[1])
	if err != nil {
		return ExitUsageError, err
	}
	if dst.Tag == "" {
		return ExitUsageError, errors.New("publish: the target needs a tag")
	}
	digest, err := verifyImage(ctx, v, pos[0])
	if err != nil {
		return publishRejected(c, stdout, err, "WOULD NOT PUBLISH")
	}
	image := dst.Name() + "@" + digest
	if plan == nil {
		if c.json {
			return ExitOK, printJSON(stdout, map[string]any{"published": false, "dry_run": true, "image": image})
		}
		fmt.Fprintf(stdout, "dry run: would publish %s\n", image)
		return ExitOK, nil
	}
	res, _, err := dryRunResult(plan, image)
	if err != nil {
		return ExitUsageError, err
	}
	if c.json {
		return ExitOK, printJSON(stdout, map[string]any{"published": false, "dry_run": true, "image": image, "template": res})
	}
	fmt.Fprintf(stdout, "dry run: would publish %s and create the actor template %s/%s:\n---\n", image, res.Atespace, res.Name)
	if err := printTemplateYAML(stdout, res.Template); err != nil {
		return ExitUsageError, err
	}
	fmt.Fprintf(stdout, "---\nIf %s/%s exists with another image or settings, the new revision is named %s-<first 8 hex of the digest> instead.\n", res.Atespace, res.Name, res.Name)
	return ExitOK, nil
}

// --------------------------------------------------------------- keygen

func runKeygen(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "directory for attestation.key and attestation.pub")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return ExitUsageError, nil
	}
	if *out == "" {
		return ExitUsageError, errors.New("keygen needs --out")
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return ExitUsageError, err
	}
	s, err := attest.GenerateSigner()
	if err != nil {
		return ExitUsageError, err
	}
	priv, _ := s.PrivateKeyPEM()
	pub, _ := s.PublicKeyPEM()
	if err := os.WriteFile(filepath.Join(*out, "attestation.key"), priv, 0o600); err != nil {
		return ExitUsageError, err
	}
	if err := os.WriteFile(filepath.Join(*out, "attestation.pub"), pub, 0o644); err != nil {
		return ExitUsageError, err
	}
	if *asJSON {
		return ExitOK, printJSON(stdout, map[string]string{"key_id": s.KeyID(), "private": filepath.Join(*out, "attestation.key"), "public": filepath.Join(*out, "attestation.pub")})
	}
	fmt.Fprintf(stdout, "wrote %s/attestation.key (keep it in the cluster Secret) and attestation.pub (the trust anchor); key id %s\n", *out, s.KeyID())
	return ExitOK, nil
}

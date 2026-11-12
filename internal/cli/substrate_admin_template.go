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

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/substrate/attest/templatecli"
)

// substrateTemplateRun runs one template command with the arguments after
// "template"; a seam for tests.
var substrateTemplateRun func(ctx context.Context, args []string, stdout, stderr io.Writer) int = templatecli.Run

// templateCommonFlags are the flags templatecli binds on build, verify, scan
// and publish.
const templateCommonFlags = `
Flags build, verify, scan and publish all take:
  --json                          print JSON
  --insecure-registry HOST:PORT   registry reached over plain HTTP (repeatable)
  --registry-user USER            registry user
  --registry-password-file FILE   file with the registry password
  --config FILE                   DefenseClaw config.yaml (scanner and admission settings)
  --platform OS/ARCH              image platform (default linux/amd64)
`

const templateBuildLong = `Builds a coding-agent image for the cluster from a base image: adds the DefenseClaw hook and relay, scans what is
inside, and pushes it with a signed attestation that the cluster checks before it runs the image.

Usage: defenseclaw substrate template build --from IMAGE --to REPO:TAG --hook-binary FILE --relay-binary FILE --key FILE [flags]

Flags:
  --connector NAME                claudecode or codex (default claudecode)
  --from IMAGE                    base image (the OpenShell harness image for the connector, with tmux)
  --to REPO:TAG                   target repository and tag
  --kit-version VERSION           kit version (default dev)
  --hook-binary FILE              defenseclaw-actor-hook (linux static)
  --relay-binary FILE             defenseclaw-actor-relay (linux static)
  --key FILE                      attestation private key (PEM, mode 0600); not needed with --dry-run
  --anchors FILE                  trust anchors, to let an attested base count as trusted
  --allow-unverified-base         build on a base that is not trusted (the cluster will refuse it by default)
  --block-at LEVEL                lowest finding severity that blocks the build: critical, high, medium, low or none (default high)
  --policy-generation N           policy generation recorded in the attestation (default 1)
  --builder-id ID                 builder id recorded in the attestation
  --provider NAME                 model route (claudecode: bedrock or anthropic; codex: openai or bedrock-mantle)
  --model ID                      default model id
  --gateway-url URL               actor listener URL (default the in-cluster Service)
  --fail-mode MODE                interactive outage mode: open or closed
  --no-mcp-static                 do not run mcp-scanner over tool descriptions
  --mcp-analyzers LIST            mcp-scanner analyzers (default yara)
  --keep-entrypoint               keep the base image ENTRYPOINT and CMD (tests; a real actor image starts the relay)
  --dry-run                       scan the composed image and stop before pushing
  --trusted-base sha256:DIGEST    base image digest the admin trusts (repeatable)
  --mcp-host HOST                 remote MCP host that is allowed (repeatable)
  --session-key KID=FILE          relay session public key, kid=PEM file (repeatable)
` + templateCommonFlags + `
Exit code: 0 built, 1 blocked, 2 usage error.`

const templateVerifyLong = `Checks the attestation of an image the way the cluster does, and says whether it would be admitted.

Usage: defenseclaw substrate template verify IMAGE --anchors FILE [flags]

Flags:
  --anchors FILE                  trust anchors (PEM bundle of public keys); required
  --min-policy-generation N       refuse attestations scanned under an older policy generation (default 0)
  --max-age DURATION              refuse attestations older than this, for example 720h (default 0, no limit)
  --allow-unverified-base         admit a template built on an untrusted base
  --allow-tag                     accept a tag reference (it can move; pin by digest in templates)
  --revoke KEYID                  key id to refuse (repeatable)
` + templateCommonFlags + `
Exit code: 0 admitted, 1 not admitted, 2 usage error.`

const templateScanLong = `Scans an image the way a build does (skills, MCP servers, plugins and the hook files) and prints the verdict. It
changes nothing.

Usage: defenseclaw substrate template scan IMAGE [flags]

Flags:
  --no-mcp-static                 do not run mcp-scanner over tool descriptions
  --mcp-analyzers LIST            mcp-scanner analyzers (default yara)
  --block-at LEVEL                lowest finding severity that blocks: critical, high, medium, low or none (default high)
  --connector NAME                check the kit's hook files and switches for this connector (claudecode or codex)
  --mcp-host HOST                 remote MCP host that is allowed (repeatable)
` + templateCommonFlags + `
Exit code: 0 clean, 1 blocked, 2 usage error.`

const templatePublishLong = `Copies a verified image, and its attestation, to the registry the cluster pulls from. It verifies first and refuses an
image that would not be admitted. With --template it then creates the ActorTemplate that runs the image, pinned by its
digest, so the image can be started with "defenseclaw substrate run --template NAME".

Usage: defenseclaw substrate template publish SOURCE@DIGEST TARGET:TAG --anchors FILE [flags]

Flags:
  --anchors FILE                  trust anchors (PEM bundle of public keys); required
  --min-policy-generation N       refuse attestations scanned under an older policy generation (default 0)
  --dry-run                       verify the image and print what would be copied and created; change nothing
  --template ATESPACE/NAME        create the ActorTemplate from the published image
  --class CLASS                   sandbox class: gvisor or microvm (default gvisor)
  --cpu CPU                       cpu limit, for example 1500m or 2 (default 1500m)
  --memory SIZE                   memory limit, for example 1536Mi or 2Gi (default 1536Mi)
  --workdir DIR                   the image decides its working directory (/work in the kit images); only that value is accepted
  --env K=V                       non-secret environment variable for the container (repeatable)
  --worker-label K=V              label a worker pool must carry (repeatable; replaces the label that --class selects)
  --api-address HOST:PORT         ate-api-server address (default substrate.api.address)
  --api-server-name NAME          TLS name of ate-api-server (default substrate.api.server_name)
  --api-ca-file FILE              CA bundle for ate-api-server's certificate (default substrate.api.ca_file)
  --api-token-file FILE           bearer token file (default substrate.api.token_file)
  --api-auth MODE                 serviceaccount or mtls (default substrate.api.auth)
` + templateCommonFlags + `
The --template flags need --template. The --api-* flags override the substrate.api section of the file given by --config.

A template cannot be changed once created. If ATESPACE/NAME already has this image and these settings, nothing happens
("already up to date"). If it has another image or other settings, a new template NAME-<first 8 hex of the digest> is
created and its name is printed: give that name to "run --template". No template is ever deleted.

Exit code: 0 published, 1 not published (or the API refused the template), 2 usage error, 75 the Substrate API cannot be
reached (run the same command again).`

const templateKeygenLong = `Makes a signing key pair for attestations: attestation.key (private, mode 0600; keep it in the cluster Secret) and
attestation.pub (the trust anchor).

Usage: defenseclaw substrate template keygen --out DIR [flags]

Flags:
  --out DIR                       directory for attestation.key and attestation.pub; required
  --json                          print JSON

Exit code: 0 done, 2 usage error.`

func newSubstrateTemplateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Build, check and publish actor images with their attestation (administrators)",
		Long: `Administrators build the images agents run in, check that an image would be admitted, scan one, publish it to the
registry the cluster pulls from, and make the signing key. These commands run on this computer and need no sign-in.

  build     build an image from a base image and push it with its attestation
  verify    check an image's attestation
  scan      scan an image
  publish   copy a verified image to the cluster's registry
  keygen    make a signing key pair

Run defenseclaw substrate template COMMAND --help for the flags.`,
	}
	cmd.AddCommand(
		newSubstrateTemplatePassthrough("build", "Build an actor image from a base image and push it with its attestation", templateBuildLong,
			"defenseclaw substrate template build --connector claudecode --from REGISTRY/base:TAG --to REGISTRY/actor:TAG --hook-binary hook --relay-binary relay --key attestation.key"),
		newSubstrateTemplatePassthrough("verify", "Check an image's attestation the way the cluster does", templateVerifyLong,
			"defenseclaw substrate template verify REGISTRY/actor@sha256:DIGEST --anchors attestation.pub"),
		newSubstrateTemplatePassthrough("scan", "Scan an image for risky skills, MCP servers and plugins", templateScanLong,
			"defenseclaw substrate template scan REGISTRY/actor@sha256:DIGEST --connector claudecode"),
		newSubstrateTemplatePassthrough("publish", "Copy a verified image to the cluster's registry", templatePublishLong,
			"defenseclaw substrate template publish SOURCE@sha256:DIGEST TARGET:TAG --anchors attestation.pub"),
		newSubstrateTemplatePassthrough("keygen", "Make a signing key pair for attestations", templateKeygenLong,
			"defenseclaw substrate template keygen --out ./keys"),
	)
	return cmd
}

// newSubstrateTemplatePassthrough hands the rest of the line to templatecli,
// which parses it with its own flag set. cobra parses nothing here, so the
// help is answered by this command from the same text the manifest holds.
func newSubstrateTemplatePassthrough(name, short, long, example string) *cobra.Command {
	return &cobra.Command{
		Use:                name + " [flags]",
		Short:              short,
		Long:               long,
		Example:            example,
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		Annotations:        map[string]string{"defenseclaw.passthrough": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, a := range args {
				if a == "--" {
					break
				}
				if a == "-h" || a == "--help" || a == "-help" {
					fmt.Fprintln(cmd.OutOrStdout(), cmd.Long)
					return nil
				}
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			code := substrateTemplateRun(ctx, append([]string{name}, args...), cmd.OutOrStdout(), cmd.ErrOrStderr())
			if code == 0 {
				return nil
			}
			// templatecli already printed what went wrong.
			cmd.SilenceErrors = true
			return withExitCode(fmt.Errorf("template %s ended with code %d", name, code), code)
		},
	}
}

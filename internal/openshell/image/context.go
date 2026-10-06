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

// Package image builds DefenseClaw's OpenShell overlay images: a
// deterministic docker build context (Dockerfile plus the connector's
// rendered artifacts and the harness launcher, with modes and ownership in
// the tar headers) streamed to `docker build -t <tag> -` on top of the
// digest-pinned community base, tagged by a content hash over every build
// input. A post-build probe (--network none) verifies the in-image bytes,
// modes and owners and records the harness realpaths, versions and digests
// in <data_dir>/sandboxes/images.json; a hook-fire probe, which Build runs
// before it returns an image, drives the harness against a built-in mock LLM
// and a stand-in hook ingress and proves the managed hooks actually fire,
// deny a blocked tool call and let an allowed one run.
package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// DefaultRepository names overlay images when BuildSpec.Repository is empty.
const DefaultRepository = "defenseclaw/sandbox"

// contextSchema versions the Dockerfile layout; bump it whenever the
// generated Dockerfile changes shape so older images stop matching.
const contextSchema = 1

// Image labels. The content hash is attached with `docker build --label`
// because it is computed over the context itself.
const (
	LabelSandboxImage   = "io.defenseclaw.sandbox-image"
	LabelContentHash    = "io.defenseclaw.content-hash"
	LabelConnector      = "io.defenseclaw.connector"
	LabelHarnessVersion = "io.defenseclaw.harness-version"
	LabelHookContract   = "io.defenseclaw.hook-contract"
	LabelUID            = "io.defenseclaw.uid"
	LabelGID            = "io.defenseclaw.gid"
	LabelIngressPort    = "io.defenseclaw.ingress-port"
	LabelVersion        = "io.defenseclaw.defenseclaw-version"
	// LabelOwner is the Store.Owner of the data dir that built the image.
	LabelOwner = "io.defenseclaw.owner"
)

// ErrUnknownContract is returned when the pinned harness version has no
// reviewed hook contract for sandboxes; the build never starts.
var ErrUnknownContract = harness.ErrUnknownContract

// BuildSpec is every input of one overlay image.
type BuildSpec struct {
	Harness *harness.Spec
	// HarnessVersion defaults to Harness.DefaultVersion.
	HarnessVersion string
	// BaseImage defaults to openshell.DefaultBaseImage and must be
	// digest-pinned.
	BaseImage string
	// UID/GID are the sandbox run-as identity (the host user in mount mode);
	// /sandbox is chowned to them. Root is refused.
	UID int
	GID int
	// IngressPort is baked into the hooks.
	IngressPort int
	// FailMode must be empty or "closed": sandbox hooks always fail closed,
	// and any other value is refused (see connector.SandboxRenderTarget).
	FailMode string
	// DefenseClawVersion is part of the content hash.
	DefenseClawVersion string
	// Repository defaults to DefaultRepository.
	Repository string
	// Owner is the Store.Owner of the data dir the image belongs to
	// (Builder fills it in). It is part of the content hash, so it names
	// the tag, and the LabelOwner label, which is applied with --label so
	// data dirs sharing a daemon still share every build layer.
	Owner string
	// MicroVM builds the image for a compute driver whose workload gets no
	// /etc/hosts (MicroVMTarget: OpenShell's MicroVM driver). Such an image
	// installs the pinned nss-myhostname (localhostStep), so localhost
	// resolves there, and its hook-fire probe also runs the harness with a
	// MicroVM's name resolution (ScenarioMicroVM). It is part of the
	// content hash only when set: an image for the docker driver has the
	// Dockerfile, the content hash and so the tag it had before MicroVM
	// images existed.
	MicroVM bool
}

// MicroVMTarget reports whether the images of sandboxes on compute driver
// d are built for a workload without /etc/hosts (BuildSpec.MicroVM): d is
// a driver DefenseClaw drives that writes none (openshell.Driver.HostsFile
// off). The zero Driver, of a driver DefenseClaw does not know, gets the
// docker driver's images.
func MicroVMTarget(d openshell.Driver) bool {
	return d.Name != "" && !d.HostsFile
}

// ContextFile is one build-context entry. UID/GID record the in-image owner
// in the tar header (the Dockerfile COPY --chown/--chmod applies them).
type ContextFile struct {
	Name string
	Mode os.FileMode
	UID  int
	GID  int
	Data []byte
}

// ImageFile is one file the overlay installs, with its in-image owner.
type ImageFile struct {
	Path  string
	Mode  os.FileMode
	UID   int
	GID   int
	Data  []byte
	Owner connector.SandboxOwner
}

// Context is a fully rendered, deterministic build context.
type Context struct {
	Spec           BuildSpec
	HarnessVersion string
	Contract       string
	Artifacts      connector.SandboxArtifacts
	// ImageFiles are the connector artifacts plus the harness launcher and
	// its shell environment files (harness.Spec.ShellFiles).
	ImageFiles []ImageFile
	// Dirs are the DefenseClaw-owned directories that must be root 0755.
	Dirs []string
	// ImageBinaries are programs from the base image that DefenseClaw's
	// in-image files exec by absolute path and that the post-build probe
	// cannot see run: the supervisor's interpreter, which only an
	// interactive launch in an orphaned terminal session starts. An image
	// may lack one (the launcher then does without it), but one the
	// workload could replace fails verification.
	ImageBinaries []string
	// UserDirs are the directories below the image HOME that hold
	// user-owned artifacts; the Dockerfile creates them (owned by the run-as
	// uid, 0755) before copying, because COPY --chmod would give the
	// directories it creates the file mode and make them untraversable.
	UserDirs   []string
	Dockerfile []byte
	// Files are the context entries (Dockerfile first, then files/...).
	Files       []ContextFile
	ContentHash string
	Tag         string
	Labels      map[string]string
}

var (
	digestRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)
	repositoryRE = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	versionRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
	safePathRE   = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

// systemDirs are never re-owned or re-moded by the overlay.
var systemDirs = map[string]bool{
	"/": true, "/etc": true, "/etc/profile.d": true, "/usr": true, "/usr/local": true, "/usr/local/lib": true, "/opt": true,
	connector.SandboxHomeDir: true,
}

// NewContext renders the build context for spec without touching docker.
func NewContext(spec BuildSpec) (*Context, error) {
	if spec.Harness == nil {
		return nil, errors.New("openshell image: harness is required")
	}
	if spec.BaseImage == "" {
		spec.BaseImage = openshell.DefaultBaseImage
	}
	if !digestRE.MatchString(spec.BaseImage) {
		return nil, fmt.Errorf("openshell image: base image %q is not digest-pinned", spec.BaseImage)
	}
	if spec.Repository == "" {
		spec.Repository = DefaultRepository
	}
	if !repositoryRE.MatchString(spec.Repository) || len(spec.Repository) > 200 {
		return nil, fmt.Errorf("openshell image: invalid repository %q", spec.Repository)
	}
	if spec.UID <= 0 || spec.GID <= 0 || spec.UID > 1<<31-1 || spec.GID > 1<<31-1 {
		return nil, fmt.Errorf("openshell image: run-as %d:%d must be a non-root uid/gid", spec.UID, spec.GID)
	}
	if !versionRE.MatchString(spec.DefenseClawVersion) {
		return nil, fmt.Errorf("openshell image: DefenseClaw version %q is invalid", spec.DefenseClawVersion)
	}
	if !ownerRE.MatchString(spec.Owner) {
		return nil, fmt.Errorf("openshell image: owner %q is not a store owner (16 lowercase hex digits)", spec.Owner)
	}
	switch strings.TrimSpace(spec.FailMode) {
	case "", connector.SandboxFailMode:
		spec.FailMode = connector.SandboxFailMode
	default:
		return nil, fmt.Errorf("openshell image: sandbox hooks always fail closed; fail mode %q is refused", spec.FailMode)
	}
	version := strings.TrimSpace(spec.HarnessVersion)
	if version == "" {
		version = spec.Harness.DefaultVersion
	}
	spec.HarnessVersion = version
	steps, err := spec.Harness.InstallSteps(version)
	if err != nil {
		return nil, fmt.Errorf("openshell image: %w", err)
	}
	artifacts, err := spec.Harness.Provider.SandboxArtifacts(connector.SandboxRenderTarget{
		IngressPort:  spec.IngressPort,
		FailMode:     spec.FailMode,
		AgentVersion: version,
	})
	if err != nil {
		return nil, fmt.Errorf("openshell image: %w", err)
	}
	if artifacts.Connector != spec.Harness.Name {
		return nil, fmt.Errorf("openshell image: harness %s rendered %s artifacts", spec.Harness.Name, artifacts.Connector)
	}

	c := &Context{Spec: spec, HarnessVersion: version, Contract: artifacts.HookContract, Artifacts: artifacts,
		ImageBinaries: []string{harness.SupervisorInterpreter}}
	sources := append([]connector.SandboxFile(nil), artifacts.Files...)
	sources = append(sources, spec.Harness.Launcher())
	sources = append(sources, spec.Harness.ShellFiles()...)
	dirSet := map[string]bool{}
	userDirSet := map[string]bool{}
	for _, f := range sources {
		if !safePathRE.MatchString(f.Path) || path.Clean(f.Path) != f.Path {
			return nil, fmt.Errorf("openshell image: artifact path %q is not a safe absolute path", f.Path)
		}
		file := ImageFile{Path: f.Path, Mode: f.Mode.Perm(), Data: f.Data, Owner: f.Owner}
		switch f.Owner {
		case connector.SandboxOwnerRoot:
			for dir := path.Dir(f.Path); !systemDirs[dir]; dir = path.Dir(dir) {
				dirSet[dir] = true
			}
		case connector.SandboxOwnerUser:
			file.UID, file.GID = spec.UID, spec.GID
			for dir := path.Dir(f.Path); dir != connector.SandboxHomeDir && strings.HasPrefix(dir, connector.SandboxHomeDir+"/"); dir = path.Dir(dir) {
				userDirSet[dir] = true
			}
		default:
			return nil, fmt.Errorf("openshell image: artifact %s has unknown owner %q", f.Path, f.Owner)
		}
		c.ImageFiles = append(c.ImageFiles, file)
	}
	sort.Slice(c.ImageFiles, func(i, j int) bool { return c.ImageFiles[i].Path < c.ImageFiles[j].Path })
	for i := 1; i < len(c.ImageFiles); i++ {
		if c.ImageFiles[i].Path == c.ImageFiles[i-1].Path {
			return nil, fmt.Errorf("openshell image: duplicate image file %s", c.ImageFiles[i].Path)
		}
	}
	for dir := range dirSet {
		c.Dirs = append(c.Dirs, dir)
	}
	sort.Strings(c.Dirs)
	for dir := range userDirSet {
		c.UserDirs = append(c.UserDirs, dir)
	}
	sort.Strings(c.UserDirs)

	c.Dockerfile = renderDockerfile(c, steps)
	c.Files = append(c.Files, ContextFile{Name: "Dockerfile", Mode: 0o644, Data: c.Dockerfile})
	for _, f := range c.ImageFiles {
		c.Files = append(c.Files, ContextFile{Name: contextName(f.Path), Mode: f.Mode, UID: f.UID, GID: f.GID, Data: f.Data})
	}
	c.ContentHash, err = contentHash(c)
	if err != nil {
		return nil, err
	}
	c.Tag = fmt.Sprintf("%s:%s-%s-u%d", spec.Repository, spec.Harness.Name, c.ContentHash[:16], spec.UID)
	c.Labels = map[string]string{
		LabelSandboxImage:   "1",
		LabelContentHash:    c.ContentHash,
		LabelConnector:      spec.Harness.Name,
		LabelHarnessVersion: version,
		LabelHookContract:   c.Contract,
		LabelUID:            strconv.Itoa(spec.UID),
		LabelGID:            strconv.Itoa(spec.GID),
		LabelIngressPort:    strconv.Itoa(spec.IngressPort),
		LabelVersion:        spec.DefenseClawVersion,
		LabelOwner:          spec.Owner,
	}
	return c, nil
}

// localhostStep is the Dockerfile step of an image for the MicroVM driver
// (BuildSpec.MicroVM) that makes it resolve localhost without /etc/hosts.
// An OpenShell MicroVM boots it with an empty /etc/hosts (the vm driver
// makes the root disk from a `docker export`, whose init layer masks the
// image's file, and its guest init writes none) and a loopback DNS relay
// that answers localhost with SERVFAIL, so every program that resolved
// localhost failed there: Antigravity CLI would not start. nss-myhostname
// (Ubuntu's libnss-myhostname) answers localhost, localhost.localdomain,
// *.localhost and the hostname with loopback addresses, and it does no
// network I/O. It would answer _gateway and _outbound with the default
// route's, which a MicroVM has none of (only its loopback is configured),
// so those names go on to the relay, which answers every name but
// localhost, even a nonexistent one, with a synthetic 198.18.x.x address;
// the egress proxy refuses a connection to _gateway's as an invalid
// destination. It is asked after /etc/hosts and before DNS, so a
// localhost query never leaves the sandbox. Go programs linked with cgo hand these names to libc when
// nsswitch.conf names myhostname; Go's own resolver and static musl
// programs read /etc/hosts and DNS themselves and still cannot resolve
// localhost in a MicroVM, which the hook-fire probe's MicroVM scenario
// catches.
//
// The package is the pinned openshell.NSSMyhostnameDebs file of the build
// architecture: downloaded by URL, checked with `sha256sum -c` and
// installed with `dpkg -i`, so two images with one content hash carry the
// same module and the build needs no package index (a base that already
// answers localhost this way installs nothing). Its postinst appends
// myhostname after dns, so the hosts line is rewritten with it right after
// files, and the build checks that the module answers localhost with
// 127.0.0.1.
func localhostStep() string {
	debs := openshell.NSSMyhostnameDebs
	arches := make([]string, 0, len(debs))
	for arch := range debs {
		arches = append(arches, arch)
	}
	sort.Strings(arches)
	pkg := "libnss-myhostname " + openshell.NSSMyhostnameVersion
	var b strings.Builder
	b.WriteString("# A MicroVM's /etc/hosts is empty and its DNS relay does not answer localhost: nss-myhostname answers it (and\n" +
		"# *.localhost and the hostname) with loopback addresses, after /etc/hosts and before DNS. The package is the pinned\n" +
		"# " + pkg + " (Ubuntu 24.04), checked by sha256; it needs only the base's libc6 and libcap2.\n")
	// The system PATH: dpkg needs ldconfig and start-stop-daemon from
	// /usr/sbin, which the base image's PATH leaves out.
	b.WriteString(`RUN set -eu; PATH=` + connector.SandboxHookPATH + `; if ! getent -s hosts:myhostname hosts localhost >/dev/null 2>&1; then `)
	b.WriteString(`arch="$(dpkg --print-architecture)"; case "$arch" in `)
	for _, arch := range arches {
		b.WriteString(arch + `) want=` + shQuote(debs[arch].SHA256) + `; urls=` + shQuote(strings.Join(debs[arch].URLs, " ")) + ` ;; `)
	}
	b.WriteString(`*) echo "` + pkg + ` is pinned for ` + strings.Join(arches, " and ") + ` only, not $arch" >&2; exit 1 ;; esac; `)
	b.WriteString(`tmp="$(mktemp -d)"; deb="$tmp/libnss-myhostname.deb"; ok=""; for url in $urls; do ` +
		`curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$deb" "$url" && printf '%s  %s\n' "$want" "$deb" | sha256sum -c --status - && { ok=1; break; }; ` +
		`echo "$url did not give the pinned ` + pkg + ` (sha256 $want)" >&2; done; `)
	b.WriteString(`[ -n "$ok" ] || { echo "could not download the pinned ` + pkg + ` for $arch" >&2; exit 1; }; `)
	b.WriteString(`dpkg -i "$deb"; rm -rf "$tmp"; fi; `)
	b.WriteString(`sed -i -E '/^hosts:/{s/[[:space:]]+myhostname([[:space:]]|$)/\1/g;s/^hosts:([[:space:]]+)files([[:space:]]|$)/hosts:\1files myhostname\2/}' /etc/nsswitch.conf; ` +
		`grep -Eq '^hosts:[[:space:]]+files myhostname([[:space:]]|$)' /etc/nsswitch.conf || ` +
		`{ echo "the base image's /etc/nsswitch.conf has no hosts line that starts with files, so myhostname cannot follow it" >&2; exit 1; }; ` +
		`getent -s hosts:myhostname ahosts localhost | grep -q '^127\.0\.0\.1[[:space:]]' || { echo "nss-myhostname does not answer localhost with 127.0.0.1" >&2; exit 1; }` + "\n")
	return b.String()
}

// contextName maps an in-image path to its build-context entry.
func contextName(imagePath string) string {
	return "files" + imagePath
}

func renderDockerfile(c *Context, steps []harness.InstallStep) []byte {
	spec := c.Spec
	var b bytes.Buffer
	fmt.Fprintf(&b, "# DefenseClaw OpenShell overlay: %s %s, hook contract %s.\n", spec.Harness.DisplayName, c.HarnessVersion, c.Contract)
	b.WriteString("# Generated by DefenseClaw; the image tag is a content hash of this context. Do not edit.\n")
	fmt.Fprintf(&b, "FROM %s\n", spec.BaseImage)
	// Static labels only: the content hash is added with docker build --label.
	fmt.Fprintf(&b, "LABEL %s=\"1\" %s=%q %s=%q %s=%q %s=\"%d\" %s=\"%d\" %s=\"%d\" %s=%q\n",
		LabelSandboxImage, LabelConnector, spec.Harness.Name, LabelHarnessVersion, c.HarnessVersion,
		LabelHookContract, c.Contract, LabelUID, spec.UID, LabelGID, spec.GID, LabelIngressPort, spec.IngressPort,
		LabelVersion, spec.DefenseClawVersion)
	b.WriteString("USER root\n")
	b.WriteString("# The hooks need jq and curl on the baked hook PATH, not just the image PATH.\n")
	b.WriteString(`RUN set -eu; PATH=` + connector.SandboxHookPATH + `; missing=""; for tool in jq curl; do command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"; done; ` +
		`if [ -n "$missing" ]; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $missing && rm -rf /var/lib/apt/lists/*; fi` + "\n")
	if spec.MicroVM {
		b.WriteString(localhostStep())
	}
	for _, step := range steps {
		fmt.Fprintf(&b, "# %s\n", step.Comment)
		fmt.Fprintf(&b, "RUN %s\n", step.Run)
	}
	// p2-render-9: fail if the base image has managed-settings.d files that
	// could override DC's drop-in (files are loaded alphabetically).
	b.WriteString("RUN set -eu; " +
		"if [ -f /etc/claude-code/managed-settings.json ]; then " +
		"echo 'Base image has /etc/claude-code/managed-settings.json that would be deep-merged with DC drop-in' >&2; " +
		"exit 1; fi; " +
		"if [ -d /etc/claude-code/managed-settings.d ]; then " +
		"for f in /etc/claude-code/managed-settings.d/*.json; do " +
		"[ ! -e \"$f\" ] || { echo \"Base image has managed-settings.d file $f that could override DC drop-in\" >&2; exit 1; }; " +
		"done; fi\n")
	b.WriteString("# DefenseClaw artifacts: root-owned and read-only to the workload unless under HOME.\n")
	if len(c.UserDirs) > 0 {
		fmt.Fprintf(&b, "RUN install -d -o %d -g %d -m 0755 %s\n", spec.UID, spec.GID, strings.Join(c.UserDirs, " "))
	}
	for _, f := range c.ImageFiles {
		fmt.Fprintf(&b, "COPY --chown=%d:%d --chmod=%04o %s %s\n", f.UID, f.GID, uint32(f.Mode), contextName(f.Path), f.Path)
	}
	dirs := strings.Join(c.Dirs, " ")
	fmt.Fprintf(&b, "RUN set -eu; for d in %s; do chown root:root \"$d\"; chmod 0755 \"$d\"; done; "+
		"install -d -o root -g root -m 0755 %s; chown -R %d:%d %s\n",
		dirs, harness.WorkRoot, spec.UID, spec.GID, connector.SandboxHomeDir)
	b.WriteString("RUN " + runAsUserStep(spec.UID, spec.GID, "/etc/passwd", "/etc/group") + "\n")
	b.WriteString("USER sandbox\n")
	return b.Bytes()
}

// runAsUserStep names the run-as uid and gid in the image: the workload
// runs as the host uid, which the base image's sandbox user does not have,
// so whoami and every tool that looks up the uid failed. Unless an entry
// already has the uid (or the gid), the sandbox user (and group) takes it,
// with HOME at the sandbox home; file owners are numbers and stay as they
// are.
func runAsUserStep(uid, gid int, passwd, group string) string {
	return fmt.Sprintf(`set -eu; `+
		`grep -q '^[^:]*:[^:]*:%[1]d:' %[3]s || sed -i -E 's#^sandbox:([^:]*):[0-9]+:[0-9]+:([^:]*):[^:]*:#sandbox:\1:%[1]d:%[2]d:\2:%[5]s:#' %[3]s; `+
		`grep -q '^[^:]*:[^:]*:%[2]d:' %[4]s || sed -i -E 's#^sandbox:([^:]*):[0-9]+:#sandbox:\1:%[2]d:#' %[4]s; `+
		`grep -q '^[^:]*:[^:]*:%[1]d:' %[3]s || { echo "the base image has no sandbox user in %[3]s to give the run-as uid %[1]d" >&2; exit 1; }`,
		uid, gid, passwd, group, connector.SandboxHomeDir)
}

// hashInput is the canonical description of every build input.
type hashInput struct {
	Schema             int    `json:"schema"`
	DefenseClawVersion string `json:"defenseclaw_version"`
	BaseImage          string `json:"base_image"`
	Connector          string `json:"connector"`
	Contract           string `json:"contract"`
	HarnessVersion     string `json:"harness_version"`
	UID                int    `json:"uid"`
	GID                int    `json:"gid"`
	IngressPort        int    `json:"ingress_port"`
	FailMode           string `json:"fail_mode"`
	Owner              string `json:"owner"`
	// MicroVM is left out when unset, which keeps the content hash of an
	// image for the docker driver what it was before MicroVM images.
	MicroVM bool        `json:"microvm,omitempty"`
	Files   []hashEntry `json:"files"`
}

type hashEntry struct {
	Name   string `json:"name"`
	Mode   string `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	SHA256 string `json:"sha256"`
}

func contentHash(c *Context) (string, error) {
	in := hashInput{
		Schema:             contextSchema,
		DefenseClawVersion: c.Spec.DefenseClawVersion,
		BaseImage:          c.Spec.BaseImage,
		Connector:          c.Spec.Harness.Name,
		Contract:           c.Contract,
		HarnessVersion:     c.HarnessVersion,
		UID:                c.Spec.UID,
		GID:                c.Spec.GID,
		IngressPort:        c.Spec.IngressPort,
		FailMode:           c.Spec.FailMode,
		Owner:              c.Spec.Owner,
		MicroVM:            c.Spec.MicroVM,
	}
	for _, f := range c.Files {
		sum := sha256.Sum256(f.Data)
		in.Files = append(in.Files, hashEntry{Name: f.Name, Mode: fmt.Sprintf("%04o", uint32(f.Mode)), UID: f.UID, GID: f.GID, SHA256: hex.EncodeToString(sum[:])})
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return "", fmt.Errorf("openshell image: hash inputs: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

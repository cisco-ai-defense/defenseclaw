// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Install and download facts for the landing page and /docs/get-started/download.
 *
 * Every value comes from the installers and the release pipeline, never from
 * marketing copy:
 *   - one-liners and options: scripts/install.sh `usage()`, scripts/install.ps1 `param()`
 *   - platform gates: install.sh (Linux x86_64/arm64, Apple silicon only) and
 *     install.ps1 (Windows x64; ARM64 refused; Windows PowerShell 5.1 or later)
 *   - artifact names: .goreleaser.yaml (archives, nfpms) and
 *     .github/workflows/release.yaml (macOS app, enterprise Setup and .pkg)
 * Links always point at `releases/latest`; never hard-code a version here.
 */

export type OsId = 'macos' | 'linux' | 'windows';

export const OS_ORDER: OsId[] = ['macos', 'linux', 'windows'];

export const REPO_URL = 'https://github.com/cisco-ai-defense/defenseclaw';
export const RELEASES_LATEST_URL = `${REPO_URL}/releases/latest`;
const LATEST_DOWNLOAD = `${REPO_URL}/releases/latest/download`;

export const INSTALL_SH = `curl -LsSf ${LATEST_DOWNLOAD}/install.sh | bash`;
export const INSTALL_PS1 = `irm ${LATEST_DOWNLOAD}/install.ps1 | iex`;

export const INIT_COMMAND = 'defenseclaw init';

export interface OsDownload {
  id: OsId;
  label: string;
  /** Architectures the installer accepts. */
  arch: string;
  shell: 'bash' | 'powershell';
  install: string;
  /** Short facts for the download tile; each one is checked by the installer or the release. */
  facts: string[];
  extra?: { label: string; value: string; note?: string; preview?: boolean };
}

export const DOWNLOADS: Record<OsId, OsDownload> = {
  macos: {
    id: 'macos',
    label: 'macOS',
    arch: 'Apple silicon (arm64)',
    shell: 'bash',
    install: INSTALL_SH,
    facts: ['Intel Macs are not supported; the installer stops before changing anything.'],
    extra: {
      label: 'Menu-bar app',
      value: 'DefenseClawMac-<version>-macos-arm64.dmg',
      note: 'macOS 14 or newer. The installer updates an installed app; it does not install one.',
      preview: true,
    },
  },
  linux: {
    id: 'linux',
    label: 'Linux',
    arch: 'x86_64 or arm64',
    shell: 'bash',
    install: INSTALL_SH,
    facts: ['Needs bash and curl. Certified on RHEL in this release.'],
  },
  windows: {
    id: 'windows',
    label: 'Windows',
    arch: 'x64',
    shell: 'powershell',
    install: INSTALL_PS1,
    facts: ['Windows PowerShell 5.1 or later. Runs as you, without administrator rights.'],
  },
};

/** Release artifacts for managed (enterprise, standalone profile) deployments. */
export interface EnterpriseArtifact {
  os: string;
  files: { name: string; note?: string }[];
}

export const ENTERPRISE_ARTIFACTS: EnterpriseArtifact[] = [
  {
    os: 'Windows x64',
    files: [
      { name: 'DefenseClawSetup-Enterprise-Standalone-x64.exe', note: 'Setup for MDMs' },
    ],
  },
  {
    os: 'macOS (Apple silicon)',
    files: [
      { name: 'defenseclaw-enterprise-<version>-darwin-arm64.pkg' },
      { name: 'defenseclaw-enterprise-<version>-darwin-arm64.tar.gz', note: 'tarball' },
    ],
  },
  {
    os: 'Linux (amd64, arm64)',
    files: [
      { name: 'defenseclaw-enterprise-<version>-linux-<arch>.rpm', note: 'certified on RHEL' },
      { name: 'defenseclaw-enterprise-<version>-linux-<arch>.deb', note: 'built, not certified this release' },
      { name: 'defenseclaw-enterprise-<version>-linux-<arch>.tar.gz', note: 'tarball' },
    ],
  },
];

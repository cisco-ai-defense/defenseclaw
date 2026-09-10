// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

/**
 * Policy Creator display metadata for deterministic detection.
 *
 * This deliberately mirrors the fixed runtime catalogs instead of defining
 * policy behavior. Keep it exact with:
 *   - internal/actionfacts/types.go and limits.go
 *   - internal/guardrail/tool_chain.go
 *   - policies/yara/mcp-tools/description_injection.yara
 *   - policies/guardrail-use-cases/*
 *
 * ActionFacts, chain, and YARA entries are read-only inventory. Selectable
 * pack rule bodies come from the generated policy-use-case-packs asset; this
 * file supplies only their human-facing summaries. Runtime source remains
 * authoritative.
 */

export interface ActionFactsCapability {
  readonly title: string;
  readonly summary: string;
  readonly values: readonly string[];
}

export interface BoundedChain {
  readonly id: string;
  readonly title: string;
  readonly severity: 'HIGH' | 'CRITICAL';
  readonly eventWindow: 8 | 9;
  readonly timeWindowMinutes: 5 | 15 | 30;
  readonly mode: 'enforcement-capable' | 'alert-only';
}

export interface YaraRule {
  readonly id: string;
  readonly description: string;
  readonly category: string;
}

export interface HighAssurancePack {
  readonly id: string;
  readonly title: string;
  readonly status: 'selectable' | 'staged';
  readonly ruleCount: number;
  readonly coverage: string;
}

export const ACTIONFACTS_CAPABILITIES = [
  {
    title: 'Bounded inputs and parsing',
    summary:
      'Projects structured tool arguments, argv, and shell text without executing commands or resolving DNS.',
    values: [
      'argv, POSIX shell, PowerShell, and cmd dialects',
      '256 KiB argument JSON and 64 KiB command limits',
      'bounded syntax depth, node count, wrappers, and fact counts',
    ],
  },
  {
    title: 'Command structure',
    summary:
      'Retains only statically proven command structure needed by deterministic rules.',
    values: [
      'parent and pipeline identity',
      'execute, preview, and uncertain effects',
      'literal argv, quoting, wrappers, redirects, and control-flow uncertainty',
    ],
  },
  {
    title: 'Closed operation vocabulary',
    summary:
      'Classifies actions into a fixed semantic vocabulary; unknown operand grammars abstain.',
    values: [
      'read, write, append, delete, copy, move, list, and search',
      'fetch, upload, connect, listen, tunnel, scan, and decode',
      'privilege, permission, configuration, account, schedule, container, workload, and policy-bypass operations',
    ],
  },
  {
    title: 'Resources and data flow',
    summary:
      'Normalizes exact resource evidence while preserving uncertainty and bounded cardinality.',
    values: [
      'POSIX, Windows, device, and registry paths with access mode',
      'network action, host, port, scope, and target cardinality',
      'stdin, stdout, file, network, and process flow edges',
    ],
  },
  {
    title: 'Private identity joins',
    summary:
      'Builds value-free, domain-separated digests for exact same-resource sequence proofs.',
    values: [
      'artifacts, SQL connections/functions, Kubernetes objects, and BSSIDs',
      'cloud principals, target/principal tuples, and persistence paths',
      'raw credentials, payloads, SQL, and file content do not enter chain state',
    ],
  },
  {
    title: 'Proof boundary',
    summary:
      'Separates detection evidence from evidence allowed to participate in a synchronous deny.',
    values: [
      'complete parses may be authoritative',
      'partial, ambiguous, unsupported, invalid, or limit-exceeded parses cannot authorize a block',
      'preview, conditional, unresolved, and failed actions remain non-enforcing',
    ],
  },
] as const satisfies readonly ActionFactsCapability[];

export const BOUNDED_CHAINS = [
  {
    id: 'chain.guardrails_off_then_egress',
    title: 'Guardrails disabled before external egress',
    severity: 'HIGH',
    eventWindow: 8,
    timeWindowMinutes: 30,
    mode: 'enforcement-capable',
  },
  {
    id: 'chain.permission_denied_then_runtime_bypass',
    title: 'Permission denial followed by runtime bypass',
    severity: 'HIGH',
    eventWindow: 8,
    timeWindowMinutes: 5,
    mode: 'enforcement-capable',
  },
  {
    id: 'chain.privilege_discovery_then_elevation',
    title: 'Privilege discovery followed by elevation',
    severity: 'HIGH',
    eventWindow: 8,
    timeWindowMinutes: 15,
    mode: 'enforcement-capable',
  },
  {
    id: 'chain.secret_manager_read_then_egress',
    title: 'Secret-manager read followed by external egress',
    severity: 'HIGH',
    eventWindow: 8,
    timeWindowMinutes: 30,
    mode: 'enforcement-capable',
  },
  {
    id: 'chain.secret_read_then_egress',
    title: 'Secret read followed by external egress',
    severity: 'CRITICAL',
    eventWindow: 8,
    timeWindowMinutes: 30,
    mode: 'enforcement-capable',
  },
  {
    id: 'chain.workload_identity_then_lateral_execution',
    title: 'Workload identity access followed by lateral execution',
    severity: 'HIGH',
    eventWindow: 8,
    timeWindowMinutes: 15,
    mode: 'enforcement-capable',
  },
  {
    id: 'chain.download_decode_execute_same_artifact',
    title: 'Remote artifact downloaded, decoded, and executed',
    severity: 'CRITICAL',
    eventWindow: 8,
    timeWindowMinutes: 30,
    mode: 'enforcement-capable',
  },
  {
    id: 'chain.download_then_execute_same_artifact',
    title: 'Remote artifact downloaded and later executed',
    severity: 'HIGH',
    eventWindow: 8,
    timeWindowMinutes: 30,
    mode: 'alert-only',
  },
  {
    id: 'chain.sensitive_egress_artifact_then_execute',
    title: 'Sensitive-egress artifact created and later executed',
    severity: 'HIGH',
    eventWindow: 8,
    timeWindowMinutes: 30,
    mode: 'alert-only',
  },
  {
    id: 'chain.firewall_trust_expansion_then_destination_use',
    title: 'Firewall trust expansion followed by exact destination use',
    severity: 'HIGH',
    eventWindow: 8,
    timeWindowMinutes: 30,
    mode: 'alert-only',
  },
  {
    id: 'chain.sqlserver_xp_cmdshell_enable_then_invoke',
    title: 'SQL Server xp_cmdshell enabled and invoked on the same connection',
    severity: 'HIGH',
    eventWindow: 9,
    timeWindowMinutes: 30,
    mode: 'alert-only',
  },
  {
    id: 'chain.kubernetes_privileged_host_root_write_apply_exec',
    title: 'Privileged Kubernetes host-root manifest applied and entered',
    severity: 'HIGH',
    eventWindow: 9,
    timeWindowMinutes: 30,
    mode: 'alert-only',
  },
  {
    id: 'chain.wireless_capture_then_deauth_same_bssid',
    title: 'Targeted wireless capture followed by deauthentication of the same BSSID',
    severity: 'HIGH',
    eventWindow: 9,
    timeWindowMinutes: 30,
    mode: 'alert-only',
  },
  {
    id: 'chain.secretsdump_then_psexec_same_target_principal',
    title: 'Credential extraction followed by remote execution against the same target and principal',
    severity: 'HIGH',
    eventWindow: 9,
    timeWindowMinutes: 30,
    mode: 'alert-only',
  },
  {
    id: 'chain.cloud_iam_principal_create_then_admin_attach_same_principal',
    title: 'Cloud IAM principal created and granted AdministratorAccess',
    severity: 'HIGH',
    eventWindow: 9,
    timeWindowMinutes: 30,
    mode: 'alert-only',
  },
  {
    id: 'chain.kubernetes_privileged_cronjob_patch_then_create_job',
    title: 'Privileged Kubernetes CronJob patched and instantiated',
    severity: 'HIGH',
    eventWindow: 9,
    timeWindowMinutes: 30,
    mode: 'alert-only',
  },
  {
    id: 'chain.sql_command_udf_create_then_invoke_same_function',
    title: 'Command-executing SQL UDF created and invoked',
    severity: 'HIGH',
    eventWindow: 9,
    timeWindowMinutes: 30,
    mode: 'alert-only',
  },
  {
    id: 'chain.reverse_shell_payload_write_then_persistence_install_same_artifact',
    title: 'Reverse-shell payload written and installed for persistence',
    severity: 'CRITICAL',
    eventWindow: 9,
    timeWindowMinutes: 30,
    mode: 'enforcement-capable',
  },
] as const satisfies readonly BoundedChain[];

export const YARA_RULES = [
  {
    id: 'defenseclaw_sensitive_data_to_addressed_sink',
    description: 'Sensitive data sent to an explicitly addressed sink',
    category: 'Data exfiltration',
  },
  {
    id: 'defenseclaw_concrete_financial_action',
    description: 'Owned-account financial action with a concrete amount',
    category: 'Financial action',
  },
  {
    id: 'defenseclaw_exact_destructive_user_data',
    description: 'Narrow destructive operations against owned user data',
    category: 'Destructive action',
  },
  {
    id: 'defenseclaw_security_control_downgrade',
    description: 'Owned-account request to disable multifactor authentication',
    category: 'Security control downgrade',
  },
  {
    id: 'defenseclaw_profile_multi_attribute_change',
    description: 'Replacement of multiple sensitive profile attributes',
    category: 'Profile tampering',
  },
] as const satisfies readonly YaraRule[];

export const HIGH_ASSURANCE_PACKS = [
  {
    id: 'privacy-high-assurance',
    title: 'Privacy high assurance',
    status: 'selectable',
    ruleCount: 13,
    coverage: 'Label-bound PII, payment-card, financial, identity, and medical-record signals.',
  },
  {
    id: 'cloud-production-protection',
    title: 'Cloud production protection',
    status: 'selectable',
    ruleCount: 3,
    coverage: 'Closed destructive AWS, Google Cloud, Azure, and cloud-audit-control operations.',
  },
  {
    id: 'database-destruction-protection',
    title: 'Database destruction protection',
    status: 'selectable',
    ruleCount: 2,
    coverage: 'Unbounded deletes plus schema, database, and table-wide destructive SQL.',
  },
  {
    id: 'infrastructure-destruction-protection',
    title: 'Infrastructure destruction protection',
    status: 'selectable',
    ruleCount: 1,
    coverage: 'Full Terraform, OpenTofu, and Pulumi destruction.',
  },
  {
    id: 'kubernetes-production-protection',
    title: 'Kubernetes production protection',
    status: 'selectable',
    ruleCount: 2,
    coverage: 'Namespace deletion and closed bulk workload deletion through kubectl or oc.',
  },
  {
    id: 'ssh-authorized-keys-protection',
    title: 'SSH authorized keys protection',
    status: 'staged',
    ruleCount: 0,
    coverage:
      'Exact authorized_keys write and fingerprint allowlist contract; activation awaits trusted content and outcome bindings.',
  },
] as const satisfies readonly HighAssurancePack[];

export const DETERMINISTIC_COVERAGE_TOTALS = {
  chains: BOUNDED_CHAINS.length,
  enforcementCapableChains: BOUNDED_CHAINS.filter(
    (chain) => chain.mode === 'enforcement-capable',
  ).length,
  alertOnlyChains: BOUNDED_CHAINS.filter((chain) => chain.mode === 'alert-only').length,
  yaraRules: YARA_RULES.length,
  selectablePacks: HIGH_ASSURANCE_PACKS.filter((pack) => pack.status === 'selectable').length,
  stagedPacks: HIGH_ASSURANCE_PACKS.filter((pack) => pack.status === 'staged').length,
} as const;

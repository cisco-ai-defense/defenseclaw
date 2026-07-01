export type ScenarioId =
  | 'runtime-secret-exfiltration'
  | 'modes-same-event'
  | 'policy-decision-trace'
  | 'hitl-native-approval'
  | 'ai-discovery-evidence'
  | 'observability-correlation'
  | 'mcp-shadow-capability'
  | 'skill-quarantine'
  | 'registry-promote-require';

export type ScenarioTone =
  | 'neutral'
  | 'info'
  | 'warning'
  | 'danger'
  | 'success';

export interface ScenarioTab {
  id: string;
  label: string;
  language: 'json' | 'yaml' | 'bash' | 'rego' | 'text' | 'markdown';
  source: string;
}

export interface ScenarioHighlight {
  tabId: string;
  start: number;
  end: number;
  tone: Exclude<ScenarioTone, 'neutral'>;
}

export interface ScenarioStep {
  id: string;
  label: string;
  description: string;
  activeTab: string;
  highlightedLines?: ScenarioHighlight[];
  evidenceIds: string[];
  outcomeId?: string;
  dwellMs: number;
}

export interface EvidenceItem {
  id: string;
  label: string;
  value: string;
  detail?: string;
  tone: ScenarioTone;
}

export interface ScenarioOutcome {
  id: string;
  kind:
    | 'observe'
    | 'allow'
    | 'block'
    | 'pause'
    | 'quarantine'
    | 'disable'
    | 'promote'
    | 'review'
    | 'audit'
    | 'export';
  label: string;
  reason: string;
  action?: string;
}

export interface ScenarioVariant {
  id: string;
  label: string;
  description: string;
  steps: ScenarioStep[];
}

export interface ScenarioDefinition {
  id: ScenarioId;
  title: string;
  summary: string;
  syntheticDataNotice: string;
  connectorIds: string[];
  tabs: ScenarioTab[];
  variants?: ScenarioVariant[];
  steps: ScenarioStep[];
  evidence: EvidenceItem[];
  outcomes: ScenarioOutcome[];
  boundaries: {
    did: string[];
    didNot: string[];
  };
}

export interface SerializedToken {
  content: string;
  color?: string;
  fontStyle?: number;
}

export interface HighlightedScenarioTab extends ScenarioTab {
  lightTokens: SerializedToken[][];
  darkTokens: SerializedToken[][];
}

export interface HighlightedScenarioDefinition
  extends Omit<ScenarioDefinition, 'tabs'> {
  tabs: HighlightedScenarioTab[];
}

export interface DefenseClawDemoProps {
  scenario: ScenarioId;
  variant?: string;
  autoplay?: boolean;
  className?: string;
}

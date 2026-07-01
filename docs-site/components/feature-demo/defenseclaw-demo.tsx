import { cache } from 'react';
import { codeToTokens } from 'shiki';
import { getFeatureDemo } from '@/data/feature-demos';
import { ScenarioPlayer } from './scenario-player';
import type {
  DefenseClawDemoProps,
  HighlightedScenarioTab,
  SerializedToken,
} from './types';

const languageMap = {
  json: 'json',
  yaml: 'yaml',
  bash: 'bash',
  rego: 'text',
  text: 'text',
  markdown: 'markdown',
} as const;

const highlightTab = cache(async (tab: Omit<HighlightedScenarioTab, 'lightTokens' | 'darkTokens'>): Promise<HighlightedScenarioTab> => {
  const lang = languageMap[tab.language];
  const [light, dark] = await Promise.all([
    codeToTokens(tab.source, { lang, theme: 'github-light' }),
    codeToTokens(tab.source, { lang, theme: 'github-dark' }),
  ]);
  const serialize = (lines: typeof light.tokens): SerializedToken[][] => lines.map((line) => line.map((token) => ({
    content: token.content,
    color: token.color,
    fontStyle: token.fontStyle,
  })));

  return {
    ...tab,
    lightTokens: serialize(light.tokens),
    darkTokens: serialize(dark.tokens),
  };
});

export async function DefenseClawDemo({
  scenario: scenarioId,
  variant,
  autoplay = true,
  className,
}: DefenseClawDemoProps) {
  const scenario = getFeatureDemo(scenarioId);
  const tabs = await Promise.all(scenario.tabs.map((tab) => highlightTab(tab)));
  return <ScenarioPlayer scenario={{ ...scenario, tabs }} variant={variant} autoplay={autoplay} className={className} />;
}

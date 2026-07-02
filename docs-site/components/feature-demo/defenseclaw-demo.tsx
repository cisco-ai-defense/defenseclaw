import { cache } from 'react';
import { codeToTokensWithThemes } from 'shiki';
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
  const tokens = await codeToTokensWithThemes(tab.source, {
    lang,
    themes: { light: 'github-light', dark: 'github-dark' },
  });
  const serialize = (theme: 'light' | 'dark'): SerializedToken[][] => tokens.map((line) => line.map((token) => ({
    content: token.content,
    color: token.variants[theme]?.color,
    fontStyle: token.variants[theme]?.fontStyle,
  })));

  return {
    ...tab,
    lightTokens: serialize('light'),
    darkTokens: serialize('dark'),
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

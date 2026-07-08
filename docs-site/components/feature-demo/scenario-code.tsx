'use client';

import { motion } from 'motion/react';
import type {
  HighlightedScenarioTab,
  ScenarioHighlight,
  ScenarioTone,
} from './types';
import { scenarioConnectorMappings } from './types';

function TokenLines({
  lines,
  theme,
  highlights,
  evidenceTones,
}: {
  lines: HighlightedScenarioTab['lightTokens'];
  theme: 'light' | 'dark';
  highlights: ScenarioHighlight[];
  evidenceTones: ScenarioTone[];
}) {
  const connectorMappings = scenarioConnectorMappings(
    highlights.map((highlight) => highlight.tone),
    evidenceTones,
  );

  return (
    <code className={`scenario-code-theme scenario-code-theme-${theme}`}>
      {lines.map((line, index) => {
        const lineNumber = index + 1;
        const highlightIndex = highlights.findIndex(
          (range) => lineNumber >= range.start && lineNumber <= range.end,
        );
        const highlight = highlightIndex >= 0 ? highlights[highlightIndex] : undefined;
        const markerNumbers = highlights.flatMap((range, rangeIndex) => {
          if (lineNumber !== range.end) return [];
          return connectorMappings
            .filter((mapping) => mapping.highlightIndex === rangeIndex)
            .map((mapping) => mapping.evidenceIndex + 1);
        });
        return (
          <span
            className={`scenario-code-line${highlight ? ` is-highlighted scenario-tone-${highlight.tone}` : ''}`}
            key={`${theme}-${lineNumber}`}
            data-scenario-highlight-index={highlight ? highlightIndex : undefined}
          >
            {highlight ? (
              <motion.span
                className="scenario-line-reveal"
                initial={{ scaleX: 0 }}
                animate={{ scaleX: 1 }}
                transition={{ duration: 0.22, ease: 'easeOut' }}
              />
            ) : null}
            <span className="scenario-line-number" aria-hidden>{lineNumber}</span>
            <span className="scenario-line-content">
              {line.length === 0 ? '\u00a0' : line.map((token, tokenIndex) => (
                <span
                  key={`${lineNumber}-${tokenIndex}`}
                  style={{ color: token.color, fontStyle: token.fontStyle === 1 ? 'italic' : undefined }}
                >
                  {token.content}
                </span>
              ))}
            </span>
            {markerNumbers.length > 0 ? (
              <span className="scenario-mobile-marker" aria-hidden>{markerNumbers.join(',')}</span>
            ) : null}
          </span>
        );
      })}
    </code>
  );
}

export function ScenarioCode({
  tab,
  highlights,
  evidenceTones,
  instanceId,
}: {
  tab: HighlightedScenarioTab;
  highlights: ScenarioHighlight[];
  evidenceTones: ScenarioTone[];
  instanceId: string;
}) {
  return (
    <div
      id={`${instanceId}-panel-${tab.id}`}
      role="tabpanel"
      aria-labelledby={`${instanceId}-tab-${tab.id}`}
      className="scenario-code-scroll"
      tabIndex={0}
      aria-label={`${tab.label} source with ${highlights.length} active annotation range${highlights.length === 1 ? '' : 's'}`}
    >
      <pre>
        <TokenLines lines={tab.lightTokens} theme="light" highlights={highlights} evidenceTones={evidenceTones} />
        <TokenLines lines={tab.darkTokens} theme="dark" highlights={highlights} evidenceTones={evidenceTones} />
      </pre>
    </div>
  );
}

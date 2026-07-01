'use client';

import { useEffect, useMemo, useReducer, useRef } from 'react';
import { useReducedMotion } from 'motion/react';
import { ShieldCheck } from 'lucide-react';
import { playerReducer, createInitialPlayerState } from './reducer';
import { ScenarioTabs } from './scenario-tabs';
import { ScenarioCode } from './scenario-code';
import { ScenarioAnnotations } from './scenario-annotations';
import { EvidenceRail } from './evidence-rail';
import { OutcomeStrip } from './outcome-strip';
import { ScenarioControls } from './scenario-controls';
import { ScenarioBoundary } from './scenario-boundary';
import type { HighlightedScenarioDefinition } from './types';

export function ScenarioPlayer({
  scenario,
  variant,
  autoplay = true,
  className,
}: {
  scenario: HighlightedScenarioDefinition;
  variant?: string;
  autoplay?: boolean;
  className?: string;
}) {
  const rootRef = useRef<HTMLElement>(null);
  const autoplayStarted = useRef(false);
  const prefersReducedMotion = useReducedMotion();
  const initialVariant = scenario.variants?.find((item) => item.id === variant)?.id
    ?? scenario.variants?.[0]?.id;
  const initialSteps = scenario.variants?.find((item) => item.id === initialVariant)?.steps
    ?? scenario.steps;
  const [state, dispatch] = useReducer(
    playerReducer,
    createInitialPlayerState(initialSteps.length - 1, initialVariant),
  );

  const activeVariant = scenario.variants?.find((item) => item.id === state.selectedVariant);
  const steps = activeVariant?.steps ?? scenario.steps;
  const lastStep = steps.length - 1;
  const safeStepIndex = Math.min(state.stepIndex, lastStep);
  const activeStep = steps[safeStepIndex];
  const activeTabId = state.manualTabId ?? activeStep.activeTab;
  const activeTab = scenario.tabs.find((tab) => tab.id === activeTabId) ?? scenario.tabs[0];
  const activeHighlights = (activeStep.highlightedLines ?? []).filter((item) => item.tabId === activeTab.id);
  const activeEvidence = useMemo(
    () => activeStep.evidenceIds.flatMap((id) => {
      const item = scenario.evidence.find((candidate) => candidate.id === id);
      return item ? [item] : [];
    }),
    [activeStep, scenario.evidence],
  );
  const outcome = scenario.outcomes.find((item) => item.id === activeStep.outcomeId);
  const connectorTone = outcome?.kind === 'block' || outcome?.kind === 'quarantine' || outcome?.kind === 'disable'
    ? 'danger'
    : activeHighlights.at(-1)?.tone ?? activeEvidence.at(-1)?.tone ?? 'info';

  useEffect(() => {
    if (!autoplay || prefersReducedMotion || autoplayStarted.current) return;
    const node = rootRef.current;
    if (!node) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !autoplayStarted.current) {
          autoplayStarted.current = true;
          dispatch({ type: 'AUTOPLAY_START' });
          observer.disconnect();
        }
      },
      { threshold: 0.3 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [autoplay, prefersReducedMotion]);

  useEffect(() => {
    if (!state.isPlaying || prefersReducedMotion) return;
    if (safeStepIndex >= lastStep) {
      dispatch({ type: 'SHOW_FINAL', lastStep });
      return;
    }
    const timer = window.setTimeout(() => {
      dispatch({ type: 'GO_TO', stepIndex: safeStepIndex + 1, lastStep });
      if (safeStepIndex + 1 < lastStep) {
        window.setTimeout(() => dispatch({ type: 'PLAY', lastStep }), 0);
      }
    }, activeStep.dwellMs);
    return () => window.clearTimeout(timer);
  }, [activeStep.dwellMs, lastStep, prefersReducedMotion, safeStepIndex, state.isPlaying]);

  useEffect(() => {
    const onVisibilityChange = () => {
      if (document.hidden) dispatch({ type: 'PAUSE' });
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, []);

  return (
    <section ref={rootRef} className={`feature-demo${className ? ` ${className}` : ''}`} aria-labelledby={`${scenario.id}-title`}>
      <header className="scenario-header">
        <div>
          <p className="scenario-eyebrow"><ShieldCheck aria-hidden />{scenario.syntheticDataNotice}</p>
          <h2 id={`${scenario.id}-title`}>{scenario.title}</h2>
          <p>{scenario.summary}</p>
        </div>
        <div className="scenario-status"><span aria-hidden />Deterministic</div>
      </header>

      {scenario.variants?.length ? (
        <div className="scenario-variants" aria-label="Scenario outcome">
          <span>Outcome</span>
          <div role="group">
            {scenario.variants.map((item) => (
              <button
                type="button"
                key={item.id}
                aria-pressed={state.selectedVariant === item.id}
                title={item.description}
                onClick={() => dispatch({ type: 'SELECT_VARIANT', variantId: item.id, lastStep: item.steps.length - 1 })}
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>
      ) : null}

      <div className="scenario-frame">
        <ScenarioTabs tabs={scenario.tabs} activeTabId={activeTab.id} onSelect={(tabId) => dispatch({ type: 'SELECT_TAB', tabId })} />
        <div className="scenario-stage">
          <ScenarioCode tab={activeTab} highlights={activeHighlights} evidenceCount={activeEvidence.length} />
          <EvidenceRail items={activeEvidence} stepId={activeStep.id} />
          <ScenarioAnnotations tone={connectorTone} annotationCount={activeEvidence.length} stepId={activeStep.id} />
        </div>
        <OutcomeStrip outcome={outcome} step={activeStep} />
        <footer className="scenario-footer">
          <div className="scenario-step-copy">
            <span>{String(safeStepIndex + 1).padStart(2, '0')}</span>
            <p><strong>{activeStep.label}</strong>{activeStep.description}</p>
          </div>
          <ScenarioControls
            isPlaying={state.isPlaying}
            stepIndex={safeStepIndex}
            stepCount={steps.length}
            onPrevious={() => dispatch({ type: 'PREVIOUS' })}
            onTogglePlayback={() => dispatch(state.isPlaying ? { type: 'PAUSE' } : { type: 'PLAY', lastStep })}
            onNext={() => dispatch({ type: 'NEXT', lastStep })}
            onRestart={() => dispatch({ type: 'RESTART', play: !prefersReducedMotion })}
          />
        </footer>
      </div>
      <ScenarioBoundary did={scenario.boundaries.did} didNot={scenario.boundaries.didNot} />
    </section>
  );
}

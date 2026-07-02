'use client';

import { motion, useReducedMotion } from 'motion/react';
import { useCallback, useId, useLayoutEffect, useRef, useState } from 'react';
import { evidenceHighlightIndex, type ScenarioTone } from './types';

interface ConnectorGeometry {
  id: string;
  path: string;
  sourceX: number;
  sourceY: number;
  tone: ScenarioTone;
}

interface GeometryState {
  width: number;
  height: number;
  connectors: ConnectorGeometry[];
}

export function ScenarioAnnotations({
  tones,
  highlightCount,
  stepId,
}: {
  tones: ScenarioTone[];
  highlightCount: number;
  stepId: string;
}) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const markerId = useId().replaceAll(':', '');
  const prefersReducedMotion = useReducedMotion();
  const [geometry, setGeometry] = useState<GeometryState>({
    width: 0,
    height: 0,
    connectors: [],
  });

  const measure = useCallback(() => {
    const svg = svgRef.current;
    const stage = svg?.closest<HTMLElement>('.scenario-stage');
    if (!svg || !stage || highlightCount === 0 || tones.length === 0) {
      setGeometry({ width: 0, height: 0, connectors: [] });
      return;
    }

    const stageRect = stage.getBoundingClientRect();
    const codeRect = stage.querySelector<HTMLElement>('.scenario-code-scroll')?.getBoundingClientRect();
    if (!codeRect) {
      setGeometry({ width: 0, height: 0, connectors: [] });
      return;
    }

    const highlights = Array.from(
      stage.querySelectorAll<HTMLElement>('[data-scenario-highlight-index]'),
    ).filter((line) => line.getBoundingClientRect().height > 0);
    const evidence = Array.from(
      stage.querySelectorAll<HTMLElement>('[data-scenario-evidence-index]'),
    );

    const connectors = evidence.flatMap((item, evidenceIndex): ConnectorGeometry[] => {
      const resolvedEvidenceIndex = Number(item.dataset.scenarioEvidenceIndex ?? evidenceIndex);
      const highlightIndex = evidenceHighlightIndex(resolvedEvidenceIndex, highlightCount);
      const lines = highlights.filter(
        (line) => Number(line.dataset.scenarioHighlightIndex) === highlightIndex,
      );
      if (lines.length === 0) return [];

      const firstLine = lines[0].getBoundingClientRect();
      const lastLine = lines.at(-1)?.getBoundingClientRect() ?? firstLine;
      const contentRects = lines
        .map((line) => line.querySelector<HTMLElement>('.scenario-line-content')?.getBoundingClientRect())
        .filter((rect): rect is DOMRect => Boolean(rect));
      const itemRect = item.getBoundingClientRect();
      const visibleCodeRight = Math.min(codeRect.right - 18, stageRect.right);
      const contentRight = Math.max(...contentRects.map((rect) => rect.right), codeRect.left + 72);
      const sourceX = Math.min(contentRight + 10, visibleCodeRight) - stageRect.left;
      const sourceY = (firstLine.top + lastLine.bottom) / 2 - stageRect.top;
      const targetX = itemRect.left - stageRect.left + 4;
      const targetY = itemRect.top - stageRect.top + Math.min(34, itemRect.height / 2);
      const bend = Math.max(28, Math.abs(targetX - sourceX) * 0.42);

      return [{
        id: `${stepId}-${evidenceIndex}`,
        path: `M ${targetX} ${targetY} C ${targetX - bend} ${targetY}, ${sourceX + bend} ${sourceY}, ${sourceX} ${sourceY}`,
        sourceX,
        sourceY,
        tone: tones[evidenceIndex] ?? tones.at(-1) ?? 'info',
      }];
    });

    setGeometry({
      width: stageRect.width,
      height: stageRect.height,
      connectors,
    });
  }, [highlightCount, stepId, tones]);

  useLayoutEffect(() => {
    const svg = svgRef.current;
    const stage = svg?.closest<HTMLElement>('.scenario-stage');
    if (!stage) return;

    const frame = window.requestAnimationFrame(measure);
    const settledFrame = window.setTimeout(measure, 260);
    const observer = new ResizeObserver(measure);
    observer.observe(stage);
    const codeScroller = stage.querySelector<HTMLElement>('.scenario-code-scroll');
    let scrollFrame: number | null = null;
    const onScroll = () => {
      if (scrollFrame !== null) return;
      scrollFrame = window.requestAnimationFrame(() => {
        scrollFrame = null;
        measure();
      });
    };
    codeScroller?.addEventListener('scroll', onScroll, { passive: true });

    return () => {
      window.cancelAnimationFrame(frame);
      window.clearTimeout(settledFrame);
      observer.disconnect();
      codeScroller?.removeEventListener('scroll', onScroll);
      if (scrollFrame !== null) window.cancelAnimationFrame(scrollFrame);
    };
  }, [measure]);

  return (
    <svg
      ref={svgRef}
      className="scenario-connectors"
      viewBox={`0 0 ${geometry.width || 1} ${geometry.height || 1}`}
      preserveAspectRatio="none"
      aria-hidden
    >
      <defs>
        {geometry.connectors.map((connector) => (
          <marker
            key={`marker-${connector.id}`}
            id={`${markerId}-${connector.id}`}
            markerWidth="8"
            markerHeight="8"
            refX="6"
            refY="4"
            orient="auto"
            markerUnits="strokeWidth"
          >
            <path d="M 0 0 L 8 4 L 0 8 z" className={`scenario-connector-arrow scenario-tone-${connector.tone}`} />
          </marker>
        ))}
      </defs>
      {geometry.connectors.map((connector) => (
        <g key={connector.id}>
          <motion.path
            className={`scenario-connector scenario-tone-${connector.tone}`}
            d={connector.path}
            markerEnd={`url(#${markerId}-${connector.id})`}
            initial={prefersReducedMotion ? false : { pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 1 }}
            transition={{ duration: prefersReducedMotion ? 0 : 0.5, ease: 'easeInOut' }}
          />
          <circle
            className={`scenario-connector-dot scenario-tone-${connector.tone}`}
            cx={connector.sourceX}
            cy={connector.sourceY}
            r="3"
          />
        </g>
      ))}
    </svg>
  );
}

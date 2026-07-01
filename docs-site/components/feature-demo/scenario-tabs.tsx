'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { motion } from 'motion/react';
import type { HighlightedScenarioTab } from './types';

export function ScenarioTabs({
  tabs,
  activeTabId,
  onSelect,
}: {
  tabs: HighlightedScenarioTab[];
  activeTabId: string;
  onSelect: (id: string) => void;
}) {
  const railRef = useRef<HTMLDivElement | null>(null);
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);

  const updateScrollState = useCallback(() => {
    const rail = railRef.current;
    if (!rail) return;
    setCanScrollLeft(rail.scrollLeft > 1);
    setCanScrollRight(rail.scrollLeft + rail.clientWidth < rail.scrollWidth - 1);
  }, []);

  useEffect(() => {
    const rail = railRef.current;
    if (!rail) return;
    updateScrollState();
    const observer = new ResizeObserver(updateScrollState);
    observer.observe(rail);
    return () => observer.disconnect();
  }, [updateScrollState]);

  useEffect(() => {
    const rail = railRef.current;
    const activeTab = rail?.querySelector<HTMLElement>(`#scenario-tab-${activeTabId}`);
    if (!rail || !activeTab) return;
    const leftEdge = activeTab.offsetLeft;
    const rightEdge = leftEdge + activeTab.offsetWidth;
    const visibleLeft = rail.scrollLeft;
    const visibleRight = visibleLeft + rail.clientWidth;
    const nextLeft = leftEdge < visibleLeft
      ? leftEdge
      : rightEdge > visibleRight
        ? rightEdge - rail.clientWidth
        : visibleLeft;
    rail.scrollTo({
      left: nextLeft,
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
    });
    const frame = window.requestAnimationFrame(updateScrollState);
    return () => window.cancelAnimationFrame(frame);
  }, [activeTabId, updateScrollState]);

  function scrollRail(direction: -1 | 1) {
    const rail = railRef.current;
    if (!rail) return;
    rail.scrollBy({
      left: direction * Math.max(180, rail.clientWidth * 0.7),
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
    });
  }

  function moveFocus(currentIndex: number, offset: number) {
    const next = (currentIndex + offset + tabs.length) % tabs.length;
    onSelect(tabs[next].id);
    document.getElementById(`scenario-tab-${tabs[next].id}`)?.focus();
  }

  return (
    <div className="scenario-tabs-shell">
      <div
        ref={railRef}
        className="scenario-tabs"
        role="tablist"
        aria-label="Scenario artifacts"
        onScroll={updateScrollState}
      >
        {tabs.map((tab, index) => {
          const active = activeTabId === tab.id;
          return (
            <button
              key={tab.id}
              id={`scenario-tab-${tab.id}`}
              type="button"
              role="tab"
              aria-selected={active}
              aria-controls={`scenario-panel-${tab.id}`}
              tabIndex={active ? 0 : -1}
              onClick={() => onSelect(tab.id)}
              onKeyDown={(event) => {
                if (event.key === 'ArrowRight') {
                  event.preventDefault();
                  moveFocus(index, 1);
                }
                if (event.key === 'ArrowLeft') {
                  event.preventDefault();
                  moveFocus(index, -1);
                }
                if (event.key === 'Home') {
                  event.preventDefault();
                  moveFocus(0, 0);
                }
                if (event.key === 'End') {
                  event.preventDefault();
                  moveFocus(tabs.length - 1, 0);
                }
              }}
            >
              {tab.label}
              {active ? (
                <motion.span
                  layoutId="scenario-active-tab"
                  className="scenario-tab-underline"
                  transition={{ duration: 0.18, ease: 'easeOut' }}
                />
              ) : null}
            </button>
          );
        })}
      </div>
      {canScrollLeft ? (
        <button
          type="button"
          className="scenario-tabs-scroll scenario-tabs-scroll-left"
          aria-label="Scroll artifacts left"
          onClick={() => scrollRail(-1)}
        >
          <ChevronLeft aria-hidden />
        </button>
      ) : null}
      {canScrollRight ? (
        <button
          type="button"
          className="scenario-tabs-scroll scenario-tabs-scroll-right"
          aria-label="Scroll artifacts right"
          onClick={() => scrollRail(1)}
        >
          <ChevronRight aria-hidden />
        </button>
      ) : null}
    </div>
  );
}

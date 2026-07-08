'use client';

import { ChevronLeft, ChevronRight, Pause, Play, RotateCcw } from 'lucide-react';

export function ScenarioControls({
  isPlaying,
  stepIndex,
  stepCount,
  onPrevious,
  onTogglePlayback,
  onNext,
  onRestart,
}: {
  isPlaying: boolean;
  stepIndex: number;
  stepCount: number;
  onPrevious: () => void;
  onTogglePlayback: () => void;
  onNext: () => void;
  onRestart: () => void;
}) {
  return (
    <div className="scenario-controls" aria-label="Guided example playback controls">
      <button type="button" onClick={onPrevious} disabled={stepIndex === 0} aria-label="Previous step">
        <ChevronLeft aria-hidden />
      </button>
      <button type="button" className="scenario-control-primary" onClick={onTogglePlayback} aria-label={isPlaying ? 'Pause guided example' : 'Play guided example'}>
        {isPlaying ? <Pause aria-hidden /> : <Play aria-hidden />}
      </button>
      <button type="button" onClick={onNext} disabled={stepIndex === stepCount - 1} aria-label="Next step">
        <ChevronRight aria-hidden />
      </button>
      <button type="button" onClick={onRestart} aria-label="Restart guided example">
        <RotateCcw aria-hidden />
      </button>
      <span className="scenario-step-count" aria-live="polite">
        Step {stepIndex + 1} / {stepCount}
      </span>
    </div>
  );
}

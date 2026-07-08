'use client';

import { useReducedMotion } from 'motion/react';
import {
  MotionGrid,
  MotionGridCells,
  type Frames,
} from '@/components/animate-ui/primitives/animate/motion-grid';

const FRAMES: Frames = [
  [[0, 2], [1, 2], [2, 2], [2, 3], [3, 3]],
  [[1, 2], [2, 2], [3, 2], [3, 3], [4, 3]],
  [[2, 2], [3, 2], [4, 2], [4, 3], [5, 3]],
  [[3, 2], [4, 2], [5, 2], [5, 3], [6, 3]],
  [[4, 2], [5, 2], [6, 2], [6, 3], [7, 3]],
  [[3, 2], [4, 2], [5, 2], [5, 3], [6, 3]],
  [[2, 2], [3, 2], [4, 2], [4, 3], [5, 3]],
  [[1, 2], [2, 2], [3, 2], [3, 3], [4, 3]],
];

export function EditorialMotionGrid() {
  const reducedMotion = useReducedMotion();

  return (
    <MotionGrid
      aria-hidden
      className="editorial-motion-grid"
      gridSize={[12, 8]}
      frames={FRAMES}
      duration={900}
      animate={!reducedMotion}
    >
      <MotionGridCells
        className="editorial-motion-grid-cell"
        activeProps={{ className: 'is-active' }}
      />
    </MotionGrid>
  );
}

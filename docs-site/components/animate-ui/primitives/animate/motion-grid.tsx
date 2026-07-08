'use client';

import * as React from 'react';
import { motion, type HTMLMotionProps } from 'motion/react';

import { cn } from '@/lib/utils';
import { getStrictContext } from '@/lib/get-strict-context';
import { Slot, type WithAsChild } from '@/components/animate-ui/primitives/animate/slot';

type FrameDot = [number, number];
type Frame = FrameDot[];
type Frames = Frame[];

type MotionGridContextType = {
  index: number;
  cols: number;
  rows: number;
  frames: Frames;
  duration: number;
  animate: boolean;
};

const [MotionGridProvider, useMotionGrid] =
  getStrictContext<MotionGridContextType>('MotionGridContext');

type MotionGridProps = WithAsChild<
  {
    gridSize: [number, number];
    frames: Frames;
    duration?: number;
    animate?: boolean;
  } & HTMLMotionProps<'div'>
>;

const MotionGrid = ({
  gridSize,
  frames,
  duration = 200,
  animate = true,
  asChild = false,
  'aria-hidden': ariaHidden = true,
  style,
  ...props
}: MotionGridProps) => {
  const [index, setIndex] = React.useState(0);
  const [pageVisible, setPageVisible] = React.useState(true);
  const intervalRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  React.useEffect(() => {
    const updateVisibility = () => setPageVisible(document.visibilityState === 'visible');
    updateVisibility();
    document.addEventListener('visibilitychange', updateVisibility);
    return () => document.removeEventListener('visibilitychange', updateVisibility);
  }, []);

  React.useEffect(() => {
    if (!animate || !pageVisible || frames.length === 0) return;
    intervalRef.current = setInterval(
      () => setIndex((i) => (i + 1) % frames.length),
      duration,
    );
    return () => clearInterval(intervalRef.current!);
  }, [frames.length, duration, animate, pageVisible]);

  const [cols, rows] = gridSize;

  const Component: React.ElementType = asChild ? Slot : motion.div;

  return (
    <MotionGridProvider
      value={{ animate: animate && pageVisible, index, cols, rows, frames, duration }}
    >
      <Component
        aria-hidden={ariaHidden}
        data-animate={animate && pageVisible}
        style={{
          display: 'grid',
          gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))`,
          gridAutoRows: '1fr',
          ...style,
        }}
        {...props}
      />
    </MotionGridProvider>
  );
};

type MotionGridCellsProps = HTMLMotionProps<'div'> & {
  activeProps?: HTMLMotionProps<'div'>;
  inactiveProps?: HTMLMotionProps<'div'>;
};

function MotionGridCells({
  activeProps,
  inactiveProps,
  ...props
}: MotionGridCellsProps) {
  const { animate, index, cols, rows, frames, duration } = useMotionGrid();

  const active = new Set<number>(
    frames[index]?.map(([x, y]) => y * cols + x) ?? [],
  );

  return Array.from({ length: cols * rows }).map((_, i) => {
    const isActive = active.has(i);
    const componentProps: HTMLMotionProps<'div'> = {
      ...(isActive ? activeProps : inactiveProps),
    };
    componentProps.className = cn(
      props?.className,
      isActive ? activeProps?.className : inactiveProps?.className,
    );
    componentProps.style = {
      ...props?.style,
      ...(isActive ? activeProps?.style : inactiveProps?.style),
    };

    return (
      <motion.div
        key={i}
        data-active={isActive}
        data-animate={animate}
        // The registry API expresses `duration` in milliseconds for the
        // frame timer, while Motion expects seconds. Keep both clocks in
        // sync instead of accidentally asking Motion for a 200-second fade.
        transition={{ duration: duration / 1000, ease: 'easeInOut' }}
        {...props}
        {...componentProps}
      />
    );
  });
}

export {
  MotionGrid,
  MotionGridCells,
  type MotionGridProps,
  type MotionGridCellsProps,
  type FrameDot,
  type Frame,
  type Frames,
};

import * as React from 'react';
import { type MotionValue } from 'motion/react';

function useMotionValueState(
  motionValue: MotionValue,
  enabled = true,
): number {
  return React.useSyncExternalStore(
    enabled
      ? (callback) => {
      const unsub = motionValue.on('change', callback);
      return unsub;
        }
      : () => () => undefined,
    enabled ? () => motionValue.get() : () => 0,
    enabled ? () => motionValue.get() : () => 0,
  );
}

export { useMotionValueState };

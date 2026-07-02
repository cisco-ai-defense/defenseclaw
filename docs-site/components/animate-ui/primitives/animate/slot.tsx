'use client';

import * as React from 'react';
import { motion, isMotionComponent, type HTMLMotionProps } from 'motion/react';
import { cn } from '@/lib/utils';

type AnyProps = Record<string, unknown>;

type DOMMotionProps<T extends HTMLElement = HTMLElement> = Omit<
  HTMLMotionProps<keyof HTMLElementTagNameMap>,
  'ref'
> & { ref?: React.Ref<T> };

type WithAsChild<Base extends object> =
  | (Base & { asChild: true; children: React.ReactElement })
  | (Base & { asChild?: false | undefined });

type SlotProps<T extends HTMLElement = HTMLElement> = {
  children?: React.ReactElement;
} & DOMMotionProps<T>;

function mergeRefs<T>(
  ...refs: (React.Ref<T> | undefined)[]
): React.RefCallback<T> {
  return (node) => {
    refs.forEach((ref) => {
      if (!ref) return;
      if (typeof ref === 'function') {
        ref(node);
      } else {
        (ref as React.RefObject<T | null>).current = node;
      }
    });
  };
}

function mergeProps<T extends HTMLElement>(
  childProps: AnyProps,
  slotProps: DOMMotionProps<T>,
): AnyProps {
  const merged: AnyProps = { ...childProps, ...slotProps };

  if (childProps.className || slotProps.className) {
    merged.className = cn(
      childProps.className as string,
      slotProps.className as string,
    );
  }

  if (childProps.style || slotProps.style) {
    merged.style = {
      ...(childProps.style as React.CSSProperties),
      ...(slotProps.style as React.CSSProperties),
    };
  }

  for (const key of Object.keys(childProps)) {
    if (!/^on[A-Z]/.test(key)) continue;
    const childHandler = childProps[key];
    const slotHandler = (slotProps as AnyProps)[key];
    if (typeof childHandler !== 'function' || typeof slotHandler !== 'function') continue;
    merged[key] = (...args: unknown[]) => {
      childHandler(...args);
      const event = args[0] as { defaultPrevented?: boolean } | undefined;
      if (!event?.defaultPrevented) slotHandler(...args);
    };
  }

  return merged;
}

function ValidSlot<T extends HTMLElement = HTMLElement>({
  children,
  ref,
  ...props
}: SlotProps<T> & { children: React.ReactElement }) {
  const childType = children.type;
  const isAlreadyMotion =
    typeof childType === 'object' &&
    childType !== null &&
    isMotionComponent(childType);

  const Base = React.useMemo(
    () => {
      return isAlreadyMotion
        ? (childType as React.ElementType)
        : motion.create(childType as React.ElementType);
    },
    [childType, isAlreadyMotion],
  );

  const { ref: childRef, ...childProps } = children.props as AnyProps;

  const mergedProps = mergeProps(childProps, props);

  return (
    <Base {...mergedProps} ref={mergeRefs(childRef as React.Ref<T>, ref)} />
  );
}

function Slot<T extends HTMLElement = HTMLElement>(props: SlotProps<T>) {
  if (!React.isValidElement(props.children)) return null;
  return <ValidSlot {...props} children={props.children} />;
}

export {
  Slot,
  type SlotProps,
  type WithAsChild,
  type DOMMotionProps,
  type AnyProps,
};

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
  const merged: AnyProps = { ...slotProps, ...childProps };

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

  const { ref: propsRef, ...childProps } = children.props as AnyProps;
  const legacyRef = Number.parseInt(React.version, 10) < 19
    ? (children as unknown as { ref?: React.Ref<T> }).ref
    : undefined;
  const childRef = (propsRef ?? legacyRef) as React.Ref<T> | undefined;

  const mergedProps = mergeProps(childProps, props);

  return (
    <Base {...mergedProps} ref={mergeRefs(childRef, ref)} />
  );
}

function Slot<T extends HTMLElement = HTMLElement>(props: SlotProps<T>) {
  if (!React.isValidElement(props.children)) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('Animate UI Slot expects exactly one React element child.');
    }
    return null;
  }
  if (props.children.type === React.Fragment) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('Animate UI Slot cannot forward motion props or refs to a Fragment.');
    }
    return props.children;
  }
  return <ValidSlot {...props} children={props.children} />;
}

export {
  Slot,
  type SlotProps,
  type WithAsChild,
  type DOMMotionProps,
  type AnyProps,
};

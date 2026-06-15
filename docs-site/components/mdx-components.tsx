import defaultMdxComponents from 'fumadocs-ui/mdx';
import { Tab, Tabs } from 'fumadocs-ui/components/tabs';
import { Step, Steps } from 'fumadocs-ui/components/steps';
import { Accordion, Accordions } from 'fumadocs-ui/components/accordion';
import { Callout } from 'fumadocs-ui/components/callout';
import { File, Folder, Files } from 'fumadocs-ui/components/files';
import { Card, Cards } from 'fumadocs-ui/components/card';
import { Banner } from 'fumadocs-ui/components/banner';
import { TypeTable } from 'fumadocs-ui/components/type-table';
import type { MDXComponents } from 'mdx/types';
import { Flow, Node, Edge, Sequence, Message } from '@/components/diagram';
import { CapabilityMatrix, HookEventsList } from '@/components/capability-matrix';
import { CommandGenerator } from '@/components/command-generator';
import PolicyCreator from '@/components/policy-creator';
import { RecipeCatalog } from '@/components/policy-creator/recipe-catalog';
import { Video } from '@/components/video';
import { TerminalAnimation } from '@/components/terminal-animation';

// Single registry for the components that MDX pages can reference
// without a per-file import. Keeping this list short and curated
// keeps the docs surface coherent — every page reaches for the same
// vocabulary (Steps, Tabs, Files, Callouts, Cards, Accordions,
// TypeTables, Flow/Sequence diagrams, the CapabilityMatrix).
export const mdxComponents: MDXComponents = {
  ...defaultMdxComponents,
  Tab,
  Tabs,
  Step,
  Steps,
  Accordion,
  Accordions,
  Callout,
  File,
  Folder,
  Files,
  Card,
  Cards,
  Banner,
  TypeTable,
  Flow,
  Node,
  Edge,
  Sequence,
  Message,
  CapabilityMatrix,
  HookEventsList,
  CommandGenerator,
  PolicyCreator,
  RecipeCatalog,
  Video,
  TerminalAnimation,
};

import * as React from 'react';
import {
  type DiagramKind,
  type MessageKind,
  KIND_TO_STYLE,
  CHAR_WIDTH,
  DiagramDefs,
  ForeignDiv,
  nextDiagramId,
} from './shared';
import { type DiagramFit } from './flow';
import { DiagramLightbox } from './lightbox';

const MESSAGE_MARKER = Symbol.for('defenseclaw.diagram.Message');

export interface ParticipantSpec {
  id: string;
  label: string;
  kind?: DiagramKind;
  emphasis?: boolean;
}

export interface MessageProps {
  from: string;
  to: string;
  label?: string;
  kind?: MessageKind;
  // A "note" message renders as a self-contained banner across the
  // active span instead of an arrow — useful for "Sinks fan-out" or
  // similar grouping callouts.
  note?: boolean;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function Message(_props: MessageProps): React.ReactElement | null {
  return null;
}
(Message as unknown as { __diagramKind: symbol }).__diagramKind = MESSAGE_MARKER;

interface SequenceProps {
  caption?: string;
  participants: ParticipantSpec[];
  // See <Flow>'s `fit` for the full discussion. 'auto' (default) is
  // the right choice almost always — the SVG scales down to fit the
  // article column with no upscaling beyond natural.
  fit?: DiagramFit;
  // Marks the diagram as one we know is wider than the article
  // column. Suppresses the build-time width gate's hard-fail.
  oversize?: boolean;
  children?: React.ReactNode;
}

interface ResolvedParticipant extends ParticipantSpec {
  // X coordinate of the lifeline center.
  x: number;
  // Width of the participant pill at the top of the diagram.
  pillW: number;
  pillH: number;
}

interface ResolvedMessage extends MessageProps {
  fromIdx: number;
  toIdx: number;
}

const PILL_PAD_X = 18;
const PILL_HEIGHT = 44;
const COL_MIN_GAP = 160;
// Cap how wide any single column gap can grow. Without this, one
// 60-char message label can push every other column outward and
// blow the whole diagram past the article column. When a label
// exceeds this, the chip ellipses inside its foreignObject — the
// authoring guide tells writers to alias overlong labels into the
// surrounding prose anyway.
const COL_MAX_GAP = 360;
const TOP_MARGIN = 20;
const PILL_MARGIN_BOTTOM = 18;
const MESSAGE_GAP = 56;
const BOTTOM_MARGIN = 28;
const SIDE_MARGIN = 24;
// Same chip-width estimator used inside the renderer (see
// SequenceLabelChip below). Hoisted so the layout stage can reserve
// the right amount of space per column without rendering yet.
function estimateChipWidth(label: string): number {
  return Math.min(280, Math.max(40, label.length * 6.6 + 20));
}

// Filter Message children out of the JSX tree, ignoring whitespace
// and any stray <p>s the MDX renderer might inject.
function readMessages(children: React.ReactNode, idIndex: Map<string, number>): ResolvedMessage[] {
  const out: ResolvedMessage[] = [];
  React.Children.forEach(children, (child) => {
    if (!React.isValidElement(child)) return;
    const marker = (child.type as unknown as { __diagramKind?: symbol }).__diagramKind;
    if (marker !== MESSAGE_MARKER) return;
    const props = child.props as MessageProps;
    const fromIdx = idIndex.get(props.from);
    const toIdx = idIndex.get(props.to);
    if (fromIdx === undefined || toIdx === undefined) return;
    out.push({
      ...props,
      fromIdx,
      toIdx,
    });
  });
  return out;
}

export function Sequence({
  caption,
  participants,
  fit = 'auto',
  oversize = false,
  children,
}: SequenceProps) {
  if (participants.length === 0) {
    return (
      <SequenceContainer caption={caption}>
        <p style={{ color: 'var(--color-fd-muted-foreground)', fontSize: 14 }}>
          (Empty Sequence — add at least one participant.)
        </p>
      </SequenceContainer>
    );
  }

  // Resolve pill widths from the label characters.
  const pillWidths = participants.map((p) =>
    Math.max(96, p.label.length * CHAR_WIDTH + PILL_PAD_X * 2),
  );

  const idIndex = new Map(participants.map((p, i) => [p.id, i]));
  const messages = readMessages(children, idIndex);

  // Per-column gaps. Each gap is sized to the widest label that
  // actually spans that column pair — clamped to keep absurdly long
  // labels from ballooning the whole layout. This replaces the old
  // global `colGap = max(MIN, widestPill + 32)`, where one verbose
  // participant label inflated every column. Now a long label only
  // pushes its own columns outward.
  const colGaps: number[] = [];
  for (let i = 0; i < participants.length - 1; i++) {
    // Each column needs room for both pills' overhang past their
    // lifelines and any message label whose chip spans this gap.
    const pillContribution = (pillWidths[i] + pillWidths[i + 1]) / 2 + 24;
    let widestSpanningLabel = 0;
    for (const m of messages) {
      const a = Math.min(m.fromIdx, m.toIdx);
      const b = Math.max(m.fromIdx, m.toIdx);
      // A note's banner spans every column between its endpoints.
      // An arrow's chip floats centered between its endpoints, so
      // it only contributes if the chip would visually overlap this
      // column boundary — but for layout purposes treating it the
      // same way is conservatively correct.
      if (m.label && i >= a && i < b) {
        widestSpanningLabel = Math.max(
          widestSpanningLabel,
          estimateChipWidth(m.label) / Math.max(1, b - a),
        );
      }
    }
    const desired = Math.max(
      COL_MIN_GAP,
      Math.max(pillContribution, widestSpanningLabel + 24),
    );
    colGaps.push(Math.min(COL_MAX_GAP, desired));
  }

  // Cumulative x positions: each lifeline sits at the running sum of
  // the previous column gaps, offset by the leading pill's half
  // width and the side margin.
  const lifelineXs: number[] = [];
  for (let i = 0; i < participants.length; i++) {
    if (i === 0) {
      lifelineXs.push(SIDE_MARGIN + pillWidths[0] / 2);
    } else {
      lifelineXs.push(lifelineXs[i - 1] + colGaps[i - 1]);
    }
  }

  const resolved: ResolvedParticipant[] = participants.map((p, i) => ({
    ...p,
    // Gateway lifelines are always emphasized — same convention as <Flow>.
    emphasis: Boolean(p.emphasis) || p.kind === 'gateway',
    x: lifelineXs[i],
    pillW: pillWidths[i],
    pillH: PILL_HEIGHT,
  }));

  // Total width: last lifeline x + half its pill + side margin.
  // Round up so the natural width is a whole pixel — the build-time
  // width gate, the data-* attrs, and downstream max-width: ${w}px
  // CSS all read better as integers.
  const lastIdx = participants.length - 1;
  const totalWidth = Math.ceil(
    lifelineXs[lastIdx] + pillWidths[lastIdx] / 2 + SIDE_MARGIN,
  );
  const lifelineTop = TOP_MARGIN + PILL_HEIGHT + PILL_MARGIN_BOTTOM;
  const totalHeight =
    lifelineTop +
    Math.max(40, messages.length * MESSAGE_GAP) +
    BOTTOM_MARGIN;

  const id = nextDiagramId('fd-seq');
  const ariaLabel = caption ?? 'Sequence diagram';

  // Same three-mode contract as <Flow>. 'native' keeps natural
  // pixels (parent figure scrolls); 'scale'/'auto' use viewBox plus
  // a max-width cap so the SVG shrinks-to-fit but never upscales.
  const sizeStyle: React.CSSProperties =
    fit === 'native'
      ? {
          display: 'block',
          margin: '0 auto',
          maxWidth: 'none',
          width: totalWidth,
          height: totalHeight,
        }
      : {
          display: 'block',
          margin: '0 auto',
          width: '100%',
          height: 'auto',
          maxWidth: totalWidth,
        };
  const svgAttrs =
    fit === 'native'
      ? { width: totalWidth, height: totalHeight }
      : ({} as { width?: number; height?: number });

  const svg = (
    <svg
      viewBox={`0 0 ${totalWidth} ${totalHeight}`}
      {...svgAttrs}
      style={sizeStyle}
      role="img"
      aria-label={ariaLabel}
      preserveAspectRatio="xMidYMid meet"
      // Hidden on phones — the timeline list below renders the same
      // information stacked vertically. Both renders ship in the
      // same SSR HTML; no JS for the swap.
      className="hidden sm:block"
    >
      <DiagramDefs id={id} />

      {/* Lifelines first so messages render on top. */}
      {resolved.map((p) => (
        <line
          key={`lifeline-${p.id}`}
          x1={p.x}
          x2={p.x}
          y1={lifelineTop}
          y2={totalHeight - BOTTOM_MARGIN + 8}
          style={{
            stroke: p.emphasis
              ? 'var(--brand-cisco)'
              : 'var(--color-fd-border)',
            strokeWidth: p.emphasis ? 1.5 : 1,
            strokeDasharray: p.emphasis ? undefined : '4 5',
            opacity: p.emphasis ? 0.7 : 0.9,
          }}
        />
      ))}

      {/* Participant pills */}
      {resolved.map((p) => (
        <ParticipantPill key={`pill-${p.id}`} p={p} gradientId={id} filterId={id} />
      ))}

      {/* Messages */}
      {messages.map((m, i) => {
        const y = lifelineTop + 28 + i * MESSAGE_GAP;
        if (m.note) {
          return (
            <SequenceNote
              key={`m-${i}`}
              y={y}
              x1={Math.min(resolved[m.fromIdx].x, resolved[m.toIdx].x)}
              x2={Math.max(resolved[m.fromIdx].x, resolved[m.toIdx].x)}
              label={m.label ?? ''}
            />
          );
        }
        return (
          <SequenceArrow
            key={`m-${i}`}
            y={y}
            from={resolved[m.fromIdx]}
            to={resolved[m.toIdx]}
            label={m.label}
            kind={m.kind ?? 'sync'}
            markerId={id}
          />
        );
      })}
    </svg>
  );

  return (
    <DiagramLightbox
      caption={caption}
      naturalWidth={totalWidth}
      naturalHeight={totalHeight}
      ariaLabel={ariaLabel}
      oversize={oversize}
    >
      {svg}
      <SequenceTimelineList
        participants={resolved}
        messages={messages}
        ariaLabel={ariaLabel}
      />
    </DiagramLightbox>
  );
}

// Mobile-only render: the same sequence rendered as a vertical
// timeline of cards, one per message. Hidden on `sm:` breakpoints
// and above; visible below 640px. Since both renders ship in the
// same SSR HTML, the swap is pure CSS — no JS, no layout shift, no
// hydration cost.
function SequenceTimelineList({
  participants,
  messages,
  ariaLabel,
}: {
  participants: ResolvedParticipant[];
  messages: ResolvedMessage[];
  ariaLabel: string;
}) {
  if (messages.length === 0) {
    return null;
  }
  return (
    <ol
      role="list"
      aria-label={`${ariaLabel} (timeline view)`}
      className="not-prose flex flex-col gap-3 sm:hidden"
    >
      {messages.map((m, i) => {
        const from = participants[m.fromIdx];
        const to = participants[m.toIdx];
        const isNote = Boolean(m.note);
        const isReturn = m.kind === 'return';
        const isAsync = m.kind === 'async';
        const arrow = isReturn ? '←' : isAsync ? '⇢' : '→';
        return (
          <li
            key={`tl-${i}`}
            className={
              isNote
                ? 'rounded-lg border border-(--brand-warn)/50 bg-(--brand-warn)/10 px-3 py-2.5 text-sm'
                : 'rounded-lg border border-fd-border bg-fd-card px-3 py-2.5 text-sm'
            }
          >
            <div className="flex items-baseline gap-2 text-xs text-fd-muted-foreground">
              <span className="font-mono tabular-nums">
                {String(i + 1).padStart(2, '0')}
              </span>
              {isNote ? (
                <span className="font-medium text-fd-foreground">
                  Note · {from.label}
                  {from.id !== to.id ? ` → ${to.label}` : ''}
                </span>
              ) : (
                <span className="font-medium text-fd-foreground">
                  {from.label}{' '}
                  <span aria-hidden className="text-fd-muted-foreground">
                    {arrow}
                  </span>{' '}
                  {to.label}
                </span>
              )}
            </div>
            {m.label && (
              <p className="mt-1 text-fd-foreground">{m.label}</p>
            )}
          </li>
        );
      })}
    </ol>
  );
}

function SequenceContainer({
  caption,
  children,
}: {
  caption?: string;
  children: React.ReactNode;
}) {
  return (
    <figure className="my-6 not-prose">
      <div className="overflow-x-auto rounded-xl border border-fd-border bg-fd-card/60 p-5">
        {children}
      </div>
      {caption && (
        <figcaption className="mt-2 text-center text-sm text-fd-muted-foreground">
          {caption}
        </figcaption>
      )}
    </figure>
  );
}

function ParticipantPill({
  p,
  gradientId,
  filterId,
}: {
  p: ResolvedParticipant;
  gradientId: string;
  filterId: string;
}) {
  const kind: DiagramKind = p.kind ?? 'generic';
  const style = KIND_TO_STYLE[kind];
  const x = p.x - p.pillW / 2;
  const y = TOP_MARGIN;
  const stroke = p.emphasis
    ? `url(#${gradientId}-emphasis)`
    : 'var(--color-fd-border)';
  return (
    <g>
      <rect
        x={x}
        y={y}
        width={p.pillW}
        height={p.pillH}
        rx={p.pillH / 2}
        ry={p.pillH / 2}
        style={{
          fill: 'var(--color-fd-card)',
          stroke,
          strokeWidth: p.emphasis ? 1.75 : 1,
        }}
        filter={`url(#${filterId}-shadow)`}
      />
      {/* Top accent stripe — communicates the kind without overwhelming
          the pill silhouette. We place it inside the rounded ends with
          a small inset so the radius stays clean. */}
      {style.accent && !p.emphasis && (
        <rect
          x={x + 12}
          y={y + 4}
          width={p.pillW - 24}
          height={2}
          rx={1}
          ry={1}
          style={{ fill: style.accent, opacity: 0.85 }}
        />
      )}
      <foreignObject x={x} y={y} width={p.pillW} height={p.pillH}>
        <ForeignDiv
          style={{
            width: '100%',
            height: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '0 16px',
            boxSizing: 'border-box',
            fontFamily: 'var(--font-sans), system-ui, sans-serif',
            fontSize: '13px',
            fontWeight: p.emphasis ? 600 : 500,
            color: 'var(--color-fd-foreground)',
            letterSpacing: '-0.005em',
            textAlign: 'center',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {p.label}
        </ForeignDiv>
      </foreignObject>
    </g>
  );
}

function SequenceArrow({
  y,
  from,
  to,
  label,
  kind,
  markerId,
}: {
  y: number;
  from: ResolvedParticipant;
  to: ResolvedParticipant;
  label?: string;
  kind: MessageKind;
  markerId: string;
}) {
  const isReturn = kind === 'return';
  const isAsync = kind === 'async';
  const stroke = from.emphasis || to.emphasis
    ? 'var(--brand-cisco)'
    : 'var(--color-fd-foreground)';
  const arrow =
    from.emphasis || to.emphasis
      ? `${markerId}-arrow-emphasis`
      : `${markerId}-arrow`;
  const dasharray = isReturn ? '5 4' : isAsync ? '2 4' : undefined;
  const opacity = isReturn ? 0.75 : 1;

  // Self-message: render a small loop on the right side of the lifeline.
  if (from.id === to.id) {
    const cx = from.x;
    const r = 14;
    return (
      <g style={{ opacity }}>
        <path
          d={`M ${cx} ${y} h ${r} a ${r} ${r} 0 0 1 0 ${r * 2} h -${r}`}
          style={{
            fill: 'none',
            stroke,
            strokeWidth: 1.25,
            strokeDasharray: dasharray,
            strokeLinecap: 'round',
          }}
          markerEnd={`url(#${arrow})`}
        />
        {label && (
          <SequenceLabelChip
            x={cx + r * 2 + 6}
            y={y + r}
            label={label}
            anchor="start"
          />
        )}
      </g>
    );
  }

  // Pull arrow endpoints in slightly so they don't kiss the lifeline.
  const dir = to.x > from.x ? 1 : -1;
  const x1 = from.x + dir * 4;
  const x2 = to.x - dir * 4;

  return (
    <g style={{ opacity }}>
      <line
        x1={x1}
        y1={y}
        x2={x2}
        y2={y}
        style={{
          stroke,
          strokeWidth: 1.25,
          strokeDasharray: dasharray,
          strokeLinecap: 'round',
        }}
        markerEnd={`url(#${arrow})`}
      />
      {label && (
        <SequenceLabelChip
          x={(x1 + x2) / 2}
          y={y - 18}
          label={label}
          anchor="middle"
        />
      )}
    </g>
  );
}

function SequenceLabelChip({
  x,
  y,
  label,
  anchor,
}: {
  x: number;
  y: number;
  label: string;
  anchor: 'start' | 'middle' | 'end';
}) {
  const w = Math.min(280, Math.max(40, label.length * 6.6 + 20));
  const h = 22;
  const offsetX = anchor === 'middle' ? -w / 2 : anchor === 'end' ? -w : 0;
  return (
    <foreignObject x={x + offsetX} y={y - h / 2} width={w} height={h}>
      <ForeignDiv
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '0 9px',
          boxSizing: 'border-box',
          fontFamily: 'var(--font-mono), ui-monospace, SFMono-Regular, Menlo, monospace',
          fontSize: '11.5px',
          color: 'var(--color-fd-muted-foreground)',
          background: 'var(--color-fd-card)',
          border: '1px solid var(--color-fd-border)',
          borderRadius: '6px',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {label}
      </ForeignDiv>
    </foreignObject>
  );
}

function SequenceNote({
  y,
  x1,
  x2,
  label,
}: {
  y: number;
  x1: number;
  x2: number;
  label: string;
}) {
  const padding = 14;
  // When the note spans a single participant (x1 === x2), give the
  // banner a sensible width based on the label rather than collapsing
  // it to zero. Empty-rect notes are how mermaid renders a no-op and
  // we want our equivalent to read clearly.
  const minWidth = Math.max(120, Math.min(280, label.length * 6.6 + padding * 2));
  const naturalWidth = x2 - x1 + padding * 2;
  const width = Math.max(naturalWidth, minWidth);
  const left = (x1 + x2) / 2 - width / 2;
  const height = 30;
  return (
    <g>
      <rect
        x={left}
        y={y - height / 2}
        width={width}
        height={height}
        rx={6}
        ry={6}
        style={{
          fill: 'color-mix(in oklab, var(--brand-warn) 12%, var(--color-fd-card))',
          stroke: 'var(--brand-warn)',
          strokeWidth: 1,
          opacity: 0.95,
        }}
      />
      <foreignObject x={left} y={y - height / 2} width={width} height={height}>
        <ForeignDiv
          style={{
            width: '100%',
            height: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '0 12px',
            boxSizing: 'border-box',
            fontFamily: 'var(--font-sans), system-ui, sans-serif',
            fontSize: '12px',
            fontWeight: 500,
            color: 'var(--color-fd-foreground)',
            textAlign: 'center',
          }}
        >
          {label}
        </ForeignDiv>
      </foreignObject>
    </g>
  );
}

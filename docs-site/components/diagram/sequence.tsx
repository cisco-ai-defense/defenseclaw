import * as React from 'react';
import {
  type DiagramKind,
  type MessageKind,
  KIND_TO_STYLE,
  CHAR_WIDTH,
  DiagramDefs,
  DiagramKindIcon,
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

const PILL_PAD_X = 20;
const PILL_HEIGHT = 58;
const COL_MIN_GAP = 150;
// Cap how wide any single column gap can grow. Without this, one
// 60-char message label can push every other column outward and
// blow the whole diagram past the article column. When a label
// exceeds this, the chip ellipses inside its foreignObject — the
// authoring guide tells writers to alias overlong labels into the
// surrounding prose anyway.
const COL_MAX_GAP = 164;
const TOP_MARGIN = 24;
const PILL_MARGIN_BOTTOM = 24;
const MESSAGE_GAP = 54;
const BOTTOM_MARGIN = 30;
const SIDE_MARGIN = 24;
// Same chip-width estimator used inside the renderer (see
// SequenceLabelChip below). Hoisted so the layout stage can reserve
// the right amount of space per column without rendering yet.
function estimateChipWidth(label: string): number {
  return Math.min(300, Math.max(40, label.length * 6.6 + 20));
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
    Math.max(128, p.label.length * CHAR_WIDTH + PILL_PAD_X * 2 + 22),
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
    const pillContribution = (pillWidths[i] + pillWidths[i + 1]) / 2 + 14;
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
      Math.max(pillContribution, widestSpanningLabel + 12),
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
          margin: '0 auto',
          maxWidth: 'none',
          width: totalWidth,
          height: totalHeight,
        }
      : {
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
      className="fd-seq-svg hidden sm:block"
    >
      <DiagramDefs id={id} />

      {/* Alternating swimlane bands make participant ownership readable at
          a glance without the graph-paper texture used by the old system. */}
      {resolved.map((participant, index) => {
        const previousX = resolved[index - 1]?.x;
        const nextX = resolved[index + 1]?.x;
        const left = index === 0
          ? 8
          : (previousX! + participant.x) / 2;
        const right = index === resolved.length - 1
          ? totalWidth - 8
          : (participant.x + nextX!) / 2;
        return (
          <rect
            key={`lane-${participant.id}`}
            className="fd-seq-lane"
            x={left}
            y={lifelineTop - 8}
            width={right - left}
            height={totalHeight - lifelineTop - BOTTOM_MARGIN + 16}
            style={{
              fill: index % 2 === 0
                ? 'var(--diagram-lane-bg)'
                : 'transparent',
            }}
          />
        );
      })}

      {/*
        Animation cadence (gated on the parent figure's
        `data-animate="entered"`, so SSR paints the final state until
        JS hydrates and the diagram scrolls into view):
          1. Pills fade-down in column order:    i  * 50ms
          2. Lifelines scaleY together once pills are settled:
                                                  participants.length * 50 + 80ms
          3. Messages slide-in row-by-row:       lifelinesEnd + i * 90ms
          4. Each message's label fades in 200ms after the message.
      */}
      {/* Lifelines first so messages render on top. All lifelines
          scaleY downward simultaneously once every pill has landed. */}
      {resolved.map((p) => (
        <line
          key={`lifeline-${p.id}`}
          className="fd-seq-lifeline"
          x1={p.x}
          x2={p.x}
          y1={lifelineTop}
          y2={totalHeight - BOTTOM_MARGIN + 8}
          style={{
            stroke: p.emphasis
              ? 'var(--diagram-accent-blue)'
              : 'var(--diagram-border-strong)',
            strokeWidth: p.emphasis ? 1.5 : 1,
            strokeDasharray: p.emphasis ? undefined : '3 5',
            opacity: p.emphasis ? 0.72 : 1,
            animationDelay: `${participants.length * 50 + 80}ms`,
          }}
        />
      ))}

      {/* Participant pills */}
      {resolved.map((p, i) => (
        <ParticipantPill
          key={`pill-${p.id}`}
          p={p}
          animationDelay={`${i * 50}ms`}
        />
      ))}

      {/* Numbered message rows create an audit-trace reading rhythm. */}
      {messages.map((_, index) => {
        const y = lifelineTop + 28 + index * MESSAGE_GAP;
        return (
          <g key={`row-${index}`} className="fd-seq-row-guide">
            <line
              x1={12}
              x2={totalWidth - 12}
              y1={y + 23}
              y2={y + 23}
              style={{ stroke: 'var(--diagram-row-rule)', strokeWidth: 1 }}
            />
            <text
              x={14}
              y={y + 4}
              style={{
                fill: 'var(--diagram-row-number)',
                fontFamily: 'var(--font-mono), ui-monospace, monospace',
                fontSize: '9px',
                fontWeight: 700,
                letterSpacing: '0.08em',
              }}
            >
              {String(index + 1).padStart(2, '0')}
            </text>
          </g>
        );
      })}

      {/* Messages */}
      {messages.map((m, i) => {
        const y = lifelineTop + 28 + i * MESSAGE_GAP;
        // Messages animate after every lifeline has finished drawing
        // (participants.length * 50 + 80ms breather + 240ms scaleY
        // duration), then stagger one per row at 90ms.
        const messagesStartMs = participants.length * 50 + 80 + 240;
        const messageDelay = `${messagesStartMs + i * 90}ms`;
        const labelDelay = `${messagesStartMs + i * 90 + 200}ms`;
        if (m.note) {
          return (
            <SequenceNote
              key={`m-${i}`}
              y={y}
              x1={Math.min(resolved[m.fromIdx].x, resolved[m.toIdx].x)}
              x2={Math.max(resolved[m.fromIdx].x, resolved[m.toIdx].x)}
              label={m.label ?? ''}
              animationDelay={messageDelay}
              labelAnimationDelay={labelDelay}
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
            animationDelay={messageDelay}
            labelAnimationDelay={labelDelay}
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
      className="diagram-timeline not-prose sm:hidden"
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
            className={`diagram-timeline-row${isNote ? ' is-note' : ''}`}
          >
            <div className="diagram-timeline-meta">
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
              <p className="diagram-timeline-copy">{m.label}</p>
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
    <figure className="diagram-figure my-8 not-prose">
      <div className="diagram-canvas overflow-x-auto">
        {children}
      </div>
      {caption && (
        <figcaption className="diagram-caption">
          {caption}
        </figcaption>
      )}
    </figure>
  );
}

function ParticipantPill({
  p,
  animationDelay,
}: {
  p: ResolvedParticipant;
  // Per-participant entrance delay; gated on the parent figure's
  // `data-animate="entered"`, so SSR paints the pill in its final
  // state until JS hydrates and the diagram scrolls into view.
  animationDelay?: string;
}) {
  const kind: DiagramKind = p.kind ?? 'generic';
  const style = KIND_TO_STYLE[kind];
  const x = p.x - p.pillW / 2;
  const y = TOP_MARGIN;
  const stroke = p.emphasis
    ? 'var(--diagram-accent-blue)'
    : 'var(--diagram-node-border)';
  return (
    <g
      className="fd-seq-pill"
      style={animationDelay ? { animationDelay } : undefined}
    >
      <rect
        x={x}
        y={y}
        width={p.pillW}
        height={p.pillH}
        rx={6}
        ry={6}
        style={{
          fill: p.emphasis
            ? 'var(--diagram-node-emphasis-bg)'
            : 'var(--diagram-node-bg)',
          stroke,
          strokeWidth: p.emphasis ? 1.6 : 1,
        }}
      />
      {style.accent && (
        <rect
          x={x}
          y={y}
          width={4}
          height={p.pillH}
          rx={3}
          ry={3}
          style={{ fill: p.emphasis ? 'var(--diagram-accent-blue)' : style.accent }}
        />
      )}
      <foreignObject x={x} y={y} width={p.pillW} height={p.pillH}>
        <ForeignDiv
          style={{
            width: '100%',
            height: '100%',
            display: 'flex',
            flexDirection: 'row',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '10px',
            padding: '8px 12px 8px 14px',
            boxSizing: 'border-box',
            fontFamily: 'var(--font-sans), system-ui, sans-serif',
            fontSize: '12.5px',
            fontWeight: p.emphasis ? 680 : 620,
            color: 'var(--diagram-text)',
            letterSpacing: '-0.01em',
            textAlign: 'left',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          <span
            style={{
              display: 'inline-flex',
              flex: '0 0 auto',
              alignItems: 'center',
              justifyContent: 'center',
              width: '28px',
              height: '28px',
              border: `1px solid color-mix(in oklab, ${style.accent} 28%, var(--diagram-border))`,
              borderRadius: '5px',
              background: `color-mix(in oklab, ${style.accent} 8%, var(--diagram-node-bg))`,
              color: style.accent,
            }}
            aria-hidden
          >
            <DiagramKindIcon kind={kind} />
          </span>
          <span
            style={{
              display: 'flex',
              minWidth: 0,
              flex: '1 1 auto',
              flexDirection: 'column',
            }}
          >
            <span style={{
              color: style.accent,
              fontFamily: 'var(--font-mono), ui-monospace, monospace',
              fontSize: '8px',
              fontWeight: 750,
              letterSpacing: '0.09em',
              lineHeight: 1,
              textTransform: 'uppercase',
            }}>{style.label}</span>
            <span style={{ marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', width: '100%' }}>
              {p.label}
            </span>
          </span>
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
  animationDelay,
  labelAnimationDelay,
}: {
  y: number;
  from: ResolvedParticipant;
  to: ResolvedParticipant;
  label?: string;
  kind: MessageKind;
  markerId: string;
  // Row-staggered entrance delay; gated on the parent figure's
  // `data-animate="entered"`. The arrow slides in from the left
  // (transform-origin set in global.css), the label fades in 200ms
  // later so it never lands before the line it sits on.
  animationDelay?: string;
  labelAnimationDelay?: string;
}) {
  const isReturn = kind === 'return';
  const isAsync = kind === 'async';
  const stroke = from.emphasis || to.emphasis
    ? 'var(--diagram-accent-blue)'
    : 'var(--diagram-edge-strong)';
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
      <g
        className="fd-seq-message"
        style={animationDelay ? { animationDelay } : undefined}
      >
        <path
          d={`M ${cx} ${y} h ${r} a ${r} ${r} 0 0 1 0 ${r * 2} h -${r}`}
          style={{
            fill: 'none',
            stroke,
            strokeWidth: 1.4,
            strokeOpacity: opacity,
            strokeDasharray: dasharray,
            strokeLinecap: 'round',
            strokeLinejoin: 'round',
          }}
          markerEnd={`url(#${arrow})`}
        />
        {label && (
          <SequenceLabelChip
            x={cx + r * 2 + 6}
            y={y + r}
            label={label}
            anchor="start"
            animationDelay={labelAnimationDelay}
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
    <g
      className="fd-seq-message"
      style={animationDelay ? { animationDelay } : undefined}
    >
      <line
        x1={x1}
        y1={y}
        x2={x2}
        y2={y}
        style={{
          stroke,
          strokeWidth: 1.4,
          strokeOpacity: opacity,
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
          animationDelay={labelAnimationDelay}
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
  animationDelay,
}: {
  x: number;
  y: number;
  label: string;
  anchor: 'start' | 'middle' | 'end';
  animationDelay?: string;
}) {
  const w = Math.min(300, Math.max(40, label.length * 6.5 + 20));
  const h = 22;
  const offsetX = anchor === 'middle' ? -w / 2 : anchor === 'end' ? -w : 0;
  return (
    <foreignObject
      className="fd-seq-message-label"
      x={x + offsetX}
      y={y - h / 2}
      width={w}
      height={h}
      style={animationDelay ? { animationDelay } : undefined}
    >
      <ForeignDiv
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '0 6px',
          boxSizing: 'border-box',
          fontFamily: 'var(--font-mono), ui-monospace, SFMono-Regular, Menlo, monospace',
          fontSize: '11px',
          fontWeight: 620,
          lineHeight: 1.15,
          color: 'var(--diagram-edge-label)',
          background: 'var(--diagram-canvas)',
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
  animationDelay,
  labelAnimationDelay,
}: {
  y: number;
  x1: number;
  x2: number;
  label: string;
  animationDelay?: string;
  labelAnimationDelay?: string;
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
  const height = 32;
  return (
    <g
      className="fd-seq-message"
      style={animationDelay ? { animationDelay } : undefined}
    >
      <rect
        x={left}
        y={y - height / 2}
        width={width}
        height={height}
        rx={4}
        ry={4}
        style={{
          fill: 'var(--diagram-note-bg)',
          stroke: 'var(--diagram-accent-amber)',
          strokeWidth: 1.2,
        }}
      />
      <foreignObject
        className="fd-seq-message-label"
        x={left}
        y={y - height / 2}
        width={width}
        height={height}
        style={labelAnimationDelay ? { animationDelay: labelAnimationDelay } : undefined}
      >
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
            color: 'var(--diagram-text)',
            textAlign: 'center',
          }}
        >
          {label}
        </ForeignDiv>
      </foreignObject>
    </g>
  );
}

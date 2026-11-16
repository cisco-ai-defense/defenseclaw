// Embeds a hosted demo video (Vidcast) in a frame that matches <Video>.
// Only Vidcast share embeds are accepted, so a page cannot frame an
// arbitrary site. The frame loads lazily, so pages with several demos
// stay light until the reader scrolls to them.
const ALLOWED_PREFIX = 'https://app.vidcast.io/share/embed/';

export interface VideoEmbedProps {
  /** Vidcast embed URL: https://app.vidcast.io/share/embed/<id> */
  src: string;
  /** Accessible name of the frame. */
  title: string;
  /** Short caption rendered below the player. */
  caption?: string;
}

export function VideoEmbed({ src, title, caption }: VideoEmbedProps) {
  if (!src.startsWith(ALLOWED_PREFIX)) {
    throw new Error(`VideoEmbed only accepts Vidcast embeds (${ALLOWED_PREFIX}...), got ${src}`);
  }
  return (
    <figure className="my-6 overflow-hidden rounded-xl border border-fd-border bg-black/60">
      <div className="relative aspect-video w-full">
        <iframe
          src={src}
          title={title}
          loading="lazy"
          allow="fullscreen *; autoplay *; clipboard-write *"
          allowFullScreen
          referrerPolicy="strict-origin-when-cross-origin"
          className="absolute inset-0 h-full w-full border-0"
        />
      </div>
      {caption ? (
        <figcaption className="border-t border-fd-border bg-fd-card px-4 py-2 text-xs text-fd-muted-foreground">
          {caption}
        </figcaption>
      ) : null}
    </figure>
  );
}

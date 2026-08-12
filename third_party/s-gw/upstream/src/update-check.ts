import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { getSgwHome } from "./paths.js";
import { CURRENT_VERSION } from "./version.js";

export const UPDATE_REPOSITORY = "sgateway/s-gw";
export const UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

export interface UpdateCheckResult {
  checked: boolean;
  currentVersion: string;
  latestVersion: string | null;
  available: boolean;
  installerReady: boolean;
  releaseUrl: string | null;
  prerelease: boolean;
  publishedAt: string | null;
  checkedAt: string | null;
  error?: string;
}

interface GitHubRelease {
  tag_name: string;
  html_url: string;
  draft: boolean;
  prerelease: boolean;
  published_at?: string | null;
  assets?: GitHubReleaseAsset[];
}

interface GitHubReleaseAsset {
  name: string;
  state?: string;
}

interface UpdateCache {
  result: UpdateCheckResult;
}

interface SemanticVersion {
  core: [string, string, string];
  prerelease: string[];
}

interface ReleaseCheckerOptions {
  cachePath?: string;
  currentVersion?: string;
  endpoint?: string;
  feedEndpoint?: string | null;
  enabled?: boolean;
  fetcher?: typeof fetch;
  now?: () => number;
}

export function isNewerVersion(candidate: string, current: string): boolean {
  const left = parseSemanticVersion(candidate);
  const right = parseSemanticVersion(current);
  if (!left || !right) return false;
  return compareSemanticVersions(left, right) > 0;
}

export class ReleaseChecker {
  private readonly cachePath: string;
  private readonly currentVersion: string;
  private readonly endpoint: string;
  private readonly feedEndpoint: string | null;
  private readonly enabled: boolean;
  private readonly fetcher: typeof fetch;
  private readonly now: () => number;
  private latest: UpdateCheckResult | null = null;
  private inFlight: Promise<UpdateCheckResult> | null = null;

  constructor(options: ReleaseCheckerOptions = {}) {
    this.cachePath = options.cachePath ?? path.join(getSgwHome(), "update-check.json");
    this.currentVersion = options.currentVersion ?? CURRENT_VERSION;
    this.endpoint = options.endpoint ?? `https://api.github.com/repos/${UPDATE_REPOSITORY}/releases?per_page=20`;
    this.feedEndpoint = options.feedEndpoint === undefined
      ? `https://github.com/${UPDATE_REPOSITORY}/releases.atom`
      : options.feedEndpoint;
    this.enabled = options.enabled ?? process.env.SGW_DISABLE_UPDATE_CHECK !== "1";
    this.fetcher = options.fetcher ?? fetch;
    this.now = options.now ?? Date.now;
  }

  current(): UpdateCheckResult | null {
    return this.latest;
  }

  async check(force = false): Promise<UpdateCheckResult> {
    if (!this.enabled) {
      const result = emptyResult(this.currentVersion);
      this.latest = result;
      return result;
    }

    if (this.inFlight) return this.inFlight;
    this.inFlight = this.performCheck(force).finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  private async performCheck(force: boolean): Promise<UpdateCheckResult> {
    const cached = await this.readCache();
    if (!force && cached && cacheIsFresh(cached, this.now())) {
      this.latest = cached;
      return cached;
    }

    try {
      const release = await this.fetchLatestRelease();
      const checkedAt = new Date(this.now()).toISOString();
      const result: UpdateCheckResult = release ? {
        checked: true,
        currentVersion: this.currentVersion,
        latestVersion: cleanVersion(release.tag_name),
        available: isNewerVersion(release.tag_name, this.currentVersion) && releaseHasVerifiedInstaller(release),
        installerReady: releaseHasVerifiedInstaller(release),
        releaseUrl: release.html_url,
        prerelease: release.prerelease,
        publishedAt: release.published_at ?? null,
        checkedAt
      } : {
        ...emptyResult(this.currentVersion),
        checked: true,
        checkedAt
      };

      this.latest = result;
      await this.writeCache(result);
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const result = cached ? { ...cached, checked: false, error: message } : {
        ...emptyResult(this.currentVersion),
        error: message
      };
      this.latest = result;
      return result;
    }
  }

  private async fetchLatestRelease(): Promise<GitHubRelease | null> {
    try {
      const response = await this.fetcher(this.endpoint, {
        headers: {
          Accept: "application/vnd.github+json",
          "User-Agent": "s-gw-updater"
        },
        signal: AbortSignal.timeout(5_000)
      });
      if (!response.ok) throw new Error(`GitHub release check returned HTTP ${response.status}.`);
      const payload = await response.json();
      if (!Array.isArray(payload)) throw new Error("GitHub release check returned an invalid response.");
      return newestRelease(payload as GitHubRelease[]);
    } catch (apiError) {
      if (!this.feedEndpoint) throw apiError;
      try {
        const response = await this.fetcher(this.feedEndpoint, {
          headers: {
            Accept: "application/atom+xml",
            "User-Agent": "s-gw-updater"
          },
          signal: AbortSignal.timeout(5_000)
        });
        if (!response.ok) throw new Error(`GitHub release feed returned HTTP ${response.status}.`);
        const release = releaseFromAtom(await response.text());
        if (!release) return null;
        const assets = await atomReleaseAssets(release, this.fetcher);
        return assets ? { ...release, assets } : null;
      } catch (feedError) {
        const apiMessage = apiError instanceof Error ? apiError.message : String(apiError);
        const feedMessage = feedError instanceof Error ? feedError.message : String(feedError);
        throw new Error(`${apiMessage} Atom fallback failed: ${feedMessage}`);
      }
    }
  }

  private async readCache(): Promise<UpdateCheckResult | null> {
    try {
      const parsed = JSON.parse(await readFile(this.cachePath, "utf8")) as UpdateCache;
      if (!validResult(parsed.result) || parsed.result.currentVersion !== this.currentVersion) {
        return null;
      }
      return parsed.result;
    } catch {
      return null;
    }
  }

  private async writeCache(result: UpdateCheckResult): Promise<void> {
    try {
      await mkdir(path.dirname(this.cachePath), { recursive: true, mode: 0o700 });
      await writeFile(this.cachePath, `${JSON.stringify({ result }, null, 2)}\n`, { mode: 0o600 });
      await chmod(this.cachePath, 0o600);
    } catch {
      // A read-only home should not turn an optional update check into a product failure.
    }
  }
}

export const releaseChecker = new ReleaseChecker();

function newestRelease(releases: GitHubRelease[]): GitHubRelease | null {
  const candidates = releases
    .filter((release) => !release.draft && !release.prerelease && Boolean(parseSemanticVersion(release.tag_name)))
    .sort((left, right) => {
      if (isNewerVersion(left.tag_name, right.tag_name)) return -1;
      if (isNewerVersion(right.tag_name, left.tag_name)) return 1;
      return 0;
    });

  for (const release of candidates) {
    if (releaseHasVerifiedInstaller(release)) return release;
  }
  return null;
}

function releaseFromAtom(xml: string): GitHubRelease | null {
  const entry = xml.match(/<entry>([\s\S]*?)<\/entry>/i)?.[1];
  if (!entry) return null;

  const link = entry.match(/<link\b[^>]*\brel="alternate"[^>]*\bhref="([^"]+)"/i)?.[1];
  const id = entry.match(/<id>([^<]+)<\/id>/i)?.[1];
  const tagFromLink = link?.match(/\/releases\/tag\/([^/?#"]+)/i)?.[1];
  const tagFromId = id?.split("/").at(-1);
  const tag = decodeXml(tagFromLink || tagFromId || "").trim();
  const parsed = parseSemanticVersion(tag);
  if (!parsed) return null;

  return {
    tag_name: tag,
    html_url: decodeXml(link || `https://github.com/${UPDATE_REPOSITORY}/releases/tag/${tag}`),
    draft: false,
    prerelease: parsed.prerelease.length > 0,
    published_at: entry.match(/<updated>([^<]+)<\/updated>/i)?.[1] || null
  };
}

async function atomReleaseAssets(
  release: GitHubRelease,
  fetcher: typeof fetch
): Promise<GitHubReleaseAsset[] | null> {
  const version = cleanVersion(release.tag_name);
  const installer = expectedInstallerName(version);
  const prefix = `https://github.com/${UPDATE_REPOSITORY}/releases/download/${release.tag_name}`;
  const installerUrl = `${prefix}/${installer}`;
  const checksumUrl = `${installerUrl}.sha256`;
  const manifestUrl = `${prefix}/SHA256SUMS.txt`;

  const installerResponse = await fetcher(installerUrl, {
    method: "HEAD",
    headers: { "User-Agent": "s-gw-updater" },
    signal: AbortSignal.timeout(5_000)
  });
  if (!installerResponse.ok) return null;

  const checksumResponse = await fetcher(checksumUrl, {
    method: "HEAD",
    headers: { "User-Agent": "s-gw-updater" },
    signal: AbortSignal.timeout(5_000)
  });
  if (checksumResponse.ok) {
    return [
      { name: installer, state: "uploaded" },
      { name: `${installer}.sha256`, state: "uploaded" }
    ];
  }

  const manifestResponse = await fetcher(manifestUrl, {
    method: "HEAD",
    headers: { "User-Agent": "s-gw-updater" },
    signal: AbortSignal.timeout(5_000)
  });
  return manifestResponse.ok
    ? [{ name: installer, state: "uploaded" }, { name: "SHA256SUMS.txt", state: "uploaded" }]
    : null;
}

function decodeXml(value: string): string {
  return value
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
}

function emptyResult(currentVersion: string): UpdateCheckResult {
  return {
    checked: false,
    currentVersion,
    latestVersion: null,
    available: false,
    installerReady: false,
    releaseUrl: null,
    prerelease: false,
    publishedAt: null,
    checkedAt: null
  };
}

function cleanVersion(version: string): string {
  return version.trim().replace(/^v/i, "");
}

function parseSemanticVersion(version: string): SemanticVersion | null {
  const match = cleanVersion(version).match(
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/
  );
  if (!match) return null;

  const prerelease = match[4]?.split(".") ?? [];
  if (prerelease.some((identifier) => /^\d+$/.test(identifier) && identifier.length > 1 && identifier.startsWith("0"))) {
    return null;
  }

  return {
    core: [match[1], match[2], match[3]],
    prerelease
  };
}

function compareSemanticVersions(left: SemanticVersion, right: SemanticVersion): number {
  for (let index = 0; index < left.core.length; index += 1) {
    const compared = compareNumericIdentifier(left.core[index], right.core[index]);
    if (compared !== 0) return compared;
  }

  if (left.prerelease.length === 0 || right.prerelease.length === 0) {
    if (left.prerelease.length === right.prerelease.length) return 0;
    return left.prerelease.length === 0 ? 1 : -1;
  }

  const count = Math.max(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < count; index += 1) {
    const a = left.prerelease[index];
    const b = right.prerelease[index];
    if (a === undefined || b === undefined) {
      if (a === b) return 0;
      return a === undefined ? -1 : 1;
    }

    const aNumeric = /^\d+$/.test(a);
    const bNumeric = /^\d+$/.test(b);
    if (aNumeric && bNumeric) {
      const compared = compareNumericIdentifier(a, b);
      if (compared !== 0) return compared;
      continue;
    }
    if (aNumeric !== bNumeric) return aNumeric ? -1 : 1;
    if (a !== b) return a < b ? -1 : 1;
  }
  return 0;
}

function compareNumericIdentifier(left: string, right: string): number {
  if (left.length !== right.length) return left.length < right.length ? -1 : 1;
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function cacheIsFresh(result: UpdateCheckResult, now: number): boolean {
  if (!result.checkedAt) return false;
  const checkedAt = Date.parse(result.checkedAt);
  if (!Number.isFinite(checkedAt)) return false;

  return now - checkedAt < UPDATE_CHECK_INTERVAL_MS;
}

function validResult(value: unknown): value is UpdateCheckResult {
  if (!value || typeof value !== "object") return false;
  const result = value as Partial<UpdateCheckResult>;
  return typeof result.currentVersion === "string" &&
    typeof result.available === "boolean" &&
    typeof result.installerReady === "boolean" &&
    (result.latestVersion === null || typeof result.latestVersion === "string") &&
    (result.releaseUrl === null || typeof result.releaseUrl === "string") &&
    (result.checkedAt === null || typeof result.checkedAt === "string");
}

function releaseHasVerifiedInstaller(release: GitHubRelease): boolean {
  const expected = expectedInstallerName(release.tag_name);
  const uploaded = (release.assets || []).filter((asset) => asset.state?.toLowerCase() === "uploaded");
  const installer = uploaded.find((asset) => asset.name.toLowerCase() === expected.toLowerCase());
  if (!installer) return false;

  const lower = installer.name.toLowerCase();
  const base = lower.replace(/\.[^.]+$/, "");
  return uploaded.some((asset) => {
    const name = asset.name.toLowerCase();
    return name === `${lower}.sha256` || name === `${base}.sha256` || name === "sha256sums.txt" || name === "sha256sums";
  });
}

function expectedInstallerName(version: string): string {
  const clean = cleanVersion(version);
  if (process.platform === "darwin") return `s-gw-${clean}-macos.dmg`;
  if (process.platform === "win32") return `s-gw-${clean}-windows.zip`;
  return `s-gw-${clean}.tgz`;
}

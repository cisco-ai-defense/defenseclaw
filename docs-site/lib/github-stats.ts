import { site } from '@/lib/site';

// Shape returned by GitHub's /repos/:owner/:repo endpoint that we
// actually care about. Keeping it minimal so we never accidentally
// surface fields that aren't documented to be stable.
interface GitHubRepoResponse {
  stargazers_count: number;
  forks_count: number;
}

export interface RepoStats {
  stars: number;
  forks: number;
}

// Endpoint and key are derived once so anything that needs to refresh
// from the client (see components/repo-stats-client.tsx) stays in sync
// with what we asked for at build time.
export const githubApiUrl = `https://api.github.com/repos/${site.repo.owner}/${site.repo.name}`;

// Fetch repo stats at build time. Returns `null` when the API is
// unreachable or rate-limits us so the layout can render the banner
// without numbers rather than throwing the build. We always opt out of
// Next's data cache (`cache: 'no-store'`) — `output: 'export'` only
// runs the fetch once per build anyway, and the client-side refresh in
// the browser is what keeps the number current between deploys.
export async function getRepoStats(): Promise<RepoStats | null> {
  // Never hardcode credentials. We accept a token from the build
  // environment (e.g. GITHUB_TOKEN injected by Actions) for higher
  // build-time rate limits, but anonymous calls also work for the
  // ~60/hr quota since each deploy only makes one request.
  const token = process.env.GITHUB_TOKEN;

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': `${site.repo.owner}-${site.repo.name}-docs`,
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  try {
    const res = await fetch(githubApiUrl, {
      headers,
      // `output: 'export'` rejects `cache: 'no-store'` because it
      // marks the route dynamic. Let Next's default cache hold the
      // response — a clean build re-fetches, and the client-side
      // refresh in repo-stats-client.tsx covers freshness for
      // visitors between deploys.
      next: { revalidate: false },
      // Bound the build-time request so a slow GitHub API doesn't
      // stall a deploy — 5s is well above p99 for unauth /repos.
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      return null;
    }
    const json = (await res.json()) as GitHubRepoResponse;
    return {
      stars: json.stargazers_count,
      forks: json.forks_count,
    };
  } catch {
    return null;
  }
}

// Compact "1.2k" / "12k" / "12.3k" formatter — keeps the banner pill
// narrow while still distinguishing 1.2k from 1.5k. Falls back to the
// raw count under 1000.
export function formatCount(n: number): string {
  if (n < 1000) {
    return n.toLocaleString('en-US');
  }
  if (n < 10_000) {
    return `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k`;
  }
  if (n < 1_000_000) {
    return `${Math.round(n / 1000)}k`;
  }
  return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}m`;
}

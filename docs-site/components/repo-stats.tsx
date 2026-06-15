import { getRepoStats } from '@/lib/github-stats';
import RepoStatsClient, { type RepoStatsVariant } from '@/components/repo-stats-client';

interface RepoStatsProps {
  variant?: RepoStatsVariant;
}

// Server wrapper: runs the GitHub API call once at build time so the
// banner / navbar render correct numbers in the static HTML (no FOUC,
// works without JS), then hands the values to the client component
// which refreshes them on mount. Multiple instances on the same page
// are de-duplicated by Next's fetch cache (see lib/github-stats.ts).
export default async function RepoStats({ variant }: RepoStatsProps = {}) {
  const initial = await getRepoStats();
  return <RepoStatsClient initial={initial} variant={variant} />;
}

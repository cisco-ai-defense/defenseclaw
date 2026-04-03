import { useState, useEffect } from 'react';
import { sidecarClient } from '@/services/sidecar-client';
import type { HealthSnapshot } from '@/types';

export interface UseSidecarResult {
  health: HealthSnapshot | null;
  isLoading: boolean;
  error: Error | null;
  refresh: () => Promise<void>;
}

export function useSidecar(): UseSidecarResult {
  const [health, setHealth] = useState<HealthSnapshot | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchHealth = async () => {
    try {
      setError(null);
      const snapshot = await sidecarClient.getHealth();
      setHealth(snapshot);
      setIsLoading(false);
    } catch (err) {
      console.error('Failed to fetch health:', err);
      setError(err as Error);
      setIsLoading(false);
    }
  };

  useEffect(() => {
    // Initial fetch
    fetchHealth();

    // Poll every 5 seconds
    const interval = setInterval(fetchHealth, 5000);

    return () => clearInterval(interval);
  }, []);

  return {
    health,
    isLoading,
    error,
    refresh: fetchHealth,
  };
}

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  getVulnerabilities, 
  getVulnerability, 
  getVulnerabilityStats,
  startValidation 
} from '../utils/api';

export function useVulnerabilities(filters: {
  limit?: number;
  offset?: number;
  severity?: string;
  category?: string;
  exploitable?: boolean;
  validated?: boolean;
} = {}) {
  return useQuery({
    queryKey: ['vulnerabilities', filters],
    queryFn: () => getVulnerabilities(filters),
    staleTime: 30000, // 30 seconds
  });
}

export function useVulnerability(id: string) {
  return useQuery({
    queryKey: ['vulnerability', id],
    queryFn: () => getVulnerability(id),
    enabled: !!id,
    staleTime: 60000, // 1 minute
  });
}

export function useVulnerabilityStats() {
  return useQuery({
    queryKey: ['vulnerability-stats'],
    queryFn: getVulnerabilityStats,
    staleTime: 30000, // 30 seconds
    refetchInterval: 60000, // Auto-refresh every minute
  });
}

export function useStartValidation() {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: startValidation,
    onSuccess: (data, findingId) => {
      // Invalidate queries to refresh data
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      queryClient.invalidateQueries({ queryKey: ['vulnerability', findingId] });
      queryClient.invalidateQueries({ queryKey: ['validation-workflows'] });
    },
  });
} 
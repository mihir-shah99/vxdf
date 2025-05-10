import { apiGet } from './client';

export interface Stats {
  total: number;
  exploitable: number;
  validated: number;
  pending: number;
}

function isErrorResponse(data: unknown): data is { error: string } {
  return typeof data === 'object' && data !== null && 'error' in data;
}

export const getStats = async (): Promise<Stats> => {
  const data = await apiGet<unknown>('/stats');
  if (isErrorResponse(data)) {
    throw new Error(data.error);
  }
  return data as Stats;
}; 
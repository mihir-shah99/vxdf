import { apiGet } from './client';

export interface Stats {
  total: number;
  exploitable: number;
  validated: number;
  pending: number;
}

export const getStats = async (): Promise<Stats> => {
  return apiGet<Stats>('/stats');
}; 
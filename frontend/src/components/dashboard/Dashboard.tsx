import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { getStats } from '../../api/stats';
import toast from 'react-hot-toast';
import LoadingSpinner from '../LoadingSpinner';
import Button from '../Button';
import Card from '../Card';

const Dashboard: React.FC = () => {
  const { data: stats, isLoading, error, refetch } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
  });

  if (error) {
    toast.error('Failed to load dashboard data');
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Dashboard</h2>
        <Button
          variant="primary"
          size="md"
          onClick={() => refetch()}
          isLoading={isLoading}
        >
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <h3 className="text-lg font-semibold text-gray-300">Total Findings</h3>
          <div className="h-12 flex items-center">
            {isLoading ? (
              <LoadingSpinner size="sm" />
            ) : (
              <p className="text-3xl font-bold text-white mt-2">
                {stats?.total || 0}
              </p>
            )}
          </div>
        </Card>
        
        <Card>
          <h3 className="text-lg font-semibold text-gray-300">Exploitable</h3>
          <div className="h-12 flex items-center">
            {isLoading ? (
              <LoadingSpinner size="sm" />
            ) : (
              <p className="text-3xl font-bold text-danger-400 mt-2">
                {stats?.exploitable || 0}
              </p>
            )}
          </div>
        </Card>
        
        <Card>
          <h3 className="text-lg font-semibold text-gray-300">Validated</h3>
          <div className="h-12 flex items-center">
            {isLoading ? (
              <LoadingSpinner size="sm" />
            ) : (
              <p className="text-3xl font-bold text-success-400 mt-2">
                {stats?.validated || 0}
              </p>
            )}
          </div>
        </Card>
        
        <Card>
          <h3 className="text-lg font-semibold text-gray-300">Pending</h3>
          <div className="h-12 flex items-center">
            {isLoading ? (
              <LoadingSpinner size="sm" />
            ) : (
              <p className="text-3xl font-bold text-warning-400 mt-2">
                {stats?.pending || 0}
              </p>
            )}
          </div>
        </Card>
      </div>

      <Card
        title="Recent Activity"
        subtitle="Latest findings and updates"
      >
        <div className="text-gray-400 text-center py-8">
          {isLoading ? (
            <LoadingSpinner size="md" />
          ) : (
            'No recent activity'
          )}
        </div>
      </Card>
    </div>
  );
};

export default Dashboard; 
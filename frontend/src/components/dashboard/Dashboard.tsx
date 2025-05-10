import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { getStats } from '../../api/stats';
import { getVulnerabilities } from '../../api/validateVulnerability';
import toast from 'react-hot-toast';
import LoadingSpinner from '../LoadingSpinner';
import Button from '../Button';
import Card from '../Card';
import { Pie, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  Title as ChartTitle,
  defaults as chartDefaults,
  Plugin,
} from 'chart.js';
import { FaBug, FaFileAlt, FaChartBar, FaFolderOpen, FaServer, FaDatabase, FaCog, FaShieldAlt, FaCheckCircle, FaHourglassHalf, FaPlus } from 'react-icons/fa';
import { useEffect, useRef, useState } from 'react';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, ChartTitle);

// Gradient plugin for Chart.js
const gradientPlugin: Plugin = {
  id: 'custom-gradient',
  beforeDatasetsDraw: (chart) => {
    const ctx = chart.ctx;
    chart.data.datasets.forEach((dataset: any, i: number) => {
      if (dataset.useGradient && chart.getDatasetMeta(i).type === 'pie') {
        const gradient = ctx.createRadialGradient(
          chart.width / 2,
          chart.height / 2,
          0,
          chart.width / 2,
          chart.height / 2,
          chart.width / 2
        );
        gradient.addColorStop(0, 'rgba(34,193,195,0.8)');
        gradient.addColorStop(1, 'rgba(44,62,80,0.8)');
        dataset.backgroundColor = gradient;
      }
      if (dataset.useGradient && chart.getDatasetMeta(i).type === 'bar') {
        const gradient = ctx.createLinearGradient(0, 0, 0, chart.height);
        gradient.addColorStop(0, 'rgba(56,189,248,0.9)');
        gradient.addColorStop(1, 'rgba(30,41,59,0.7)');
        dataset.backgroundColor = gradient;
      }
    });
  },
};
ChartJS.register(gradientPlugin);

// Modern, blended color palette for dark UI
const severityColors = [
  'rgba(239,68,68,0.85)',   // CRITICAL - red
  'rgba(245,158,66,0.85)',  // HIGH - orange
  'rgba(251,191,36,0.85)',  // MEDIUM - yellow
  'rgba(34,197,94,0.85)',   // LOW - green
  'rgba(99,102,241,0.85)',  // UNKNOWN/other - indigo
];
const typeColors = [
  'rgba(56,189,248,0.85)',  // cyan
  'rgba(99,102,241,0.85)',  // indigo
  'rgba(139,92,246,0.85)',  // purple
  'rgba(16,185,129,0.85)',  // teal
  'rgba(251,191,36,0.85)',  // yellow
  'rgba(245,158,66,0.85)',  // orange
  'rgba(239,68,68,0.85)',   // red
  'rgba(30,64,175,0.85)',   // blue
  'rgba(59,130,246,0.85)',  // blue
  'rgba(236,72,153,0.85)',  // pink
];

const Dashboard: React.FC = () => {
  const { data: stats, isLoading, error, refetch } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
  });

  // Fetch recent validated vulnerabilities
  const { data: recentVulns, isLoading: isLoadingVulns } = useQuery({
    queryKey: ['recentVulns'],
    queryFn: () => getVulnerabilities({ limit: 5, offset: 0, validated: true }),
  });

  // Prepare chart data
  const severityLabels = stats && stats.bySeverity ? Object.keys(stats.bySeverity) : [];
  const severityData = stats && stats.bySeverity ? Object.values(stats.bySeverity) : [];

  const typeLabels = stats && stats.byType ? Object.keys(stats.byType) : [];
  const typeData = stats && stats.byType ? Object.values(stats.byType) : [];

  if (error) {
    toast.error('Failed to load dashboard data');
  }

  // Animated stat numbers
  function AnimatedNumber({ value }: { value: number }) {
    const [display, setDisplay] = useState(0);
    useEffect(() => {
      let start = 0;
      const duration = 800;
      const step = Math.ceil(value / (duration / 16));
      const interval = setInterval(() => {
        start += step;
        if (start >= value) {
          setDisplay(value);
          clearInterval(interval);
        } else {
          setDisplay(start);
        }
      }, 16);
      return () => clearInterval(interval);
    }, [value]);
    return <span>{display}</span>;
  }

  const pieOptions = {
    plugins: {
      legend: {
        position: 'top' as const,
        labels: { color: '#fff', font: { weight: 'bold' as const } },
      },
      tooltip: {
        enabled: true,
        callbacks: {
          label: (ctx: any) => `${ctx.label}: ${ctx.parsed}`,
        },
      },
    },
  };
  const barOptions = {
    plugins: {
      legend: { display: false },
      tooltip: { enabled: true },
    },
    scales: {
      x: {
        ticks: { color: '#fff', font: { weight: 'bold' as const } },
        grid: { color: 'rgba(255,255,255,0.1)' },
      },
      y: {
        beginAtZero: true,
        ticks: { color: '#fff' },
        grid: { color: 'rgba(255,255,255,0.1)' },
      },
    },
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Dashboard</h2>
        <button
          className="flex items-center gap-2 px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold shadow transition-colors"
        >
          <FaPlus /> New
        </button>
      </div>

      {/* Navigation Buttons */}
      <div className="flex flex-wrap gap-3 mb-2">
        <button className="flex items-center gap-2 px-4 py-2 rounded-md bg-gray-800 text-white hover:bg-blue-600 transition-colors font-medium shadow">
          <FaBug /> Findings
        </button>
        <button className="flex items-center gap-2 px-4 py-2 rounded-md bg-gray-800 text-white hover:bg-blue-600 transition-colors font-medium shadow">
          <FaChartBar /> Analysis
        </button>
        <button className="flex items-center gap-2 px-4 py-2 rounded-md bg-gray-800 text-white hover:bg-blue-600 transition-colors font-medium shadow">
          <FaFileAlt /> Reports
        </button>
        <button className="flex items-center gap-2 px-4 py-2 rounded-md bg-gray-800 text-white hover:bg-blue-600 transition-colors font-medium shadow">
          <FaFolderOpen /> Documents
        </button>
        <button className="flex items-center gap-2 px-4 py-2 rounded-md bg-gray-800 text-white hover:bg-blue-600 transition-colors font-medium shadow">
          <FaServer /> Environments
        </button>
        <button className="flex items-center gap-2 px-4 py-2 rounded-md bg-gray-800 text-white hover:bg-blue-600 transition-colors font-medium shadow">
          <FaDatabase /> Database
        </button>
        <button className="flex items-center gap-2 px-4 py-2 rounded-md bg-gray-800 text-white hover:bg-blue-600 transition-colors font-medium shadow">
          <FaCog /> Settings
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <h3 className="text-lg font-semibold text-gray-300">Total Findings</h3>
          <div className="h-12 flex items-center">
            {isLoading ? (
              <LoadingSpinner size="sm" />
            ) : (
              <p className="text-3xl font-bold text-white mt-2">
                <AnimatedNumber value={stats?.total || 0} />
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
                <AnimatedNumber value={stats?.exploitable || 0} />
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
                <AnimatedNumber value={stats?.validated || 0} />
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
                <AnimatedNumber value={stats?.pending || 0} />
              </p>
            )}
          </div>
        </Card>
      </div>

      {/* Dashboard Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card title="Findings by Severity">
          <div className="flex justify-center items-center h-64">
            {isLoading ? (
              <LoadingSpinner size="md" />
            ) : (
              <Pie
                data={{
                  labels: severityLabels,
                  datasets: [
                    {
                      data: severityData,
                      backgroundColor: severityColors.slice(0, severityLabels.length),
                      borderWidth: 1,
                    } as any,
                  ].map((ds, i) => i === 0 ? { ...ds, useGradient: true } : ds),
                }}
                options={pieOptions}
              />
            )}
          </div>
        </Card>
        <Card title="Findings by Type">
          <div className="flex justify-center items-center h-64">
            {isLoading ? (
              <LoadingSpinner size="md" />
            ) : (
              <Bar
                data={{
                  labels: typeLabels,
                  datasets: [
                    {
                      label: 'Findings',
                      data: typeData,
                      backgroundColor: typeColors.slice(0, typeLabels.length),
                    } as any,
                  ].map((ds, i) => i === 0 ? { ...ds, useGradient: true } : ds),
                }}
                options={barOptions}
              />
            )}
          </div>
        </Card>
      </div>

      {/* Recently Validated Vulnerabilities Table */}
      <Card title="Recently Validated Vulnerabilities">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-600 bg-gray-700 text-white">
            <thead className="bg-gray-800">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Title</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Category</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-600">
              {isLoadingVulns ? (
                <tr>
                  <td colSpan={6} className="px-6 py-4 text-center text-sm text-gray-400">Loading...</td>
                </tr>
              ) : recentVulns && recentVulns.vulnerabilities.length > 0 ? (
                recentVulns.vulnerabilities.map((vuln: any) => (
                  <tr key={vuln.id} className="hover:bg-gray-600">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{vuln.id}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">{vuln.name}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        vuln.severity === 'CRITICAL' ? 'bg-red-900 text-red-200' :
                        vuln.severity === 'HIGH' ? 'bg-orange-900 text-orange-200' :
                        vuln.severity === 'MEDIUM' ? 'bg-yellow-900 text-yellow-200' :
                        'bg-green-900 text-green-200'
                      }`}>
                        {vuln.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">{vuln.type}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        vuln.isExploitable ? 'bg-red-900 text-red-200' : 'bg-green-900 text-green-200'
                      }`}>
                        {vuln.isExploitable ? 'Exploitable' : 'Not Exploitable'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-blue-400 hover:text-blue-200 font-medium cursor-pointer">View Details</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="px-6 py-4 text-center text-sm text-gray-400">No vulnerabilities have been validated yet. Upload scan results to begin.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

export default Dashboard; 
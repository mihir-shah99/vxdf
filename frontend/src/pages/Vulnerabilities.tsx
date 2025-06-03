import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { 
  Search, 
  Filter, 
  SortAsc,
  AlertTriangle, 
  Shield, 
  Clock, 
  CheckCircle,
  Play,
  FileText,
  ExternalLink
} from 'lucide-react';
import { useVulnerabilities, useStartValidation } from '../hooks/useVulnerabilities';
import { VulnerabilityFinding } from '../types';
import toast from 'react-hot-toast';

interface VulnerabilityCardProps {
  vulnerability: VulnerabilityFinding;
  onStartValidation: (id: string) => void;
  onViewDetails: (id: string) => void;
}

function VulnerabilityCard({ vulnerability, onStartValidation, onViewDetails }: VulnerabilityCardProps) {
  const getStatusInfo = () => {
    if (vulnerability.exploitable === true) {
      return { icon: AlertTriangle, text: 'Exploitable', className: 'status-exploitable' };
    }
    if (vulnerability.exploitable === false) {
      return { icon: Shield, text: 'Not Exploitable', className: 'status-safe' };
    }
    if (vulnerability.validated) {
      return { icon: CheckCircle, text: 'Validated', className: 'status-validated' };
    }
    return { icon: Clock, text: 'Pending', className: 'status-pending' };
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/20';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      case 'low': return 'text-green-400 bg-green-500/10 border-green-500/20';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
    }
  };

  const status = getStatusInfo();
  const StatusIcon = status.icon;

  return (
    <div className="card p-4 sm:p-6 hover:bg-vxdf-gray-800/50 transition-colors cursor-pointer group">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between mb-4 space-y-3 sm:space-y-0">
        <div className="flex flex-col sm:flex-row sm:items-center space-y-2 sm:space-y-0 sm:space-x-3">
          <div className={`status-badge ${status.className} flex items-center space-x-1 w-fit`}>
            <StatusIcon className="h-3 w-3" />
            <span>{status.text}</span>
          </div>
          <div className={`px-2 py-1 text-xs font-medium rounded border w-fit ${getSeverityColor(vulnerability.severity)}`}>
            {vulnerability.severity || 'UNKNOWN'}
          </div>
        </div>
        <div className="flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
          {!vulnerability.validated && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onStartValidation(vulnerability.id);
              }}
              className="p-1 text-vxdf-gray-400 hover:text-vxdf-primary transition-colors"
              title="Start Validation"
            >
              <Play className="h-4 w-4" />
            </button>
          )}
          <button
            onClick={(e) => {
              e.stopPropagation();
              onViewDetails(vulnerability.id);
            }}
            className="p-1 text-vxdf-gray-400 hover:text-vxdf-primary transition-colors"
            title="View Details"
          >
            <ExternalLink className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div onClick={() => onViewDetails(vulnerability.id)}>
        <h3 className="text-base sm:text-lg font-semibold text-white mb-2 group-hover:text-vxdf-primary transition-colors">
          {vulnerability.title || 'Untitled Vulnerability'}
        </h3>
        
        <p className="text-xs sm:text-sm text-vxdf-gray-400 mb-4 line-clamp-2">
          {vulnerability.description || 'No description available'}
        </p>

        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between text-xs text-vxdf-gray-500 space-y-2 sm:space-y-0">
          <div className="flex flex-wrap items-center gap-2 sm:gap-4">
            <span>🗂️ {vulnerability.category || 'Unknown'}</span>
            {vulnerability.cweId && <span>CWE: {vulnerability.cweId}</span>}
            {vulnerability.cvssScore && <span>CVSS: {vulnerability.cvssScore}</span>}
          </div>
          <div className="flex items-center space-x-2">
            <FileText className="h-3 w-3" />
            <span>{vulnerability.evidence?.length || 0} evidence</span>
          </div>
        </div>

        {vulnerability.source?.file && (
          <div className="mt-3 p-2 bg-vxdf-gray-800 rounded text-xs text-vxdf-gray-400 truncate">
            📁 {vulnerability.source.file}
            {vulnerability.source.line && `:${vulnerability.source.line}`}
          </div>
        )}
      </div>
    </div>
  );
}

export default function Vulnerabilities() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState('severity');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 12;

  // Handle URL parameters for filtering from dashboard
  useEffect(() => {
    const filter = searchParams.get('filter');
    const severity = searchParams.get('severity');
    
    if (filter === 'validated') {
      setStatusFilter('validated');
    } else if (filter === 'exploitable') {
      setStatusFilter('exploitable');
    } else if (filter === 'risk') {
      setStatusFilter('exploitable');
    }
    
    if (severity) {
      setSeverityFilter(severity);
    }
  }, [searchParams]);

  const { data, isLoading, error } = useVulnerabilities({
    limit: 1000, // Get all for client-side filtering
    offset: 0,
  });

  const startValidationMutation = useStartValidation();

  const handleStartValidation = async (vulnerabilityId: string) => {
    try {
      await startValidationMutation.mutateAsync(vulnerabilityId);
      toast.success('Validation started successfully');
    } catch (error) {
      toast.error('Failed to start validation');
    }
  };

  const handleViewDetails = (vulnerabilityId: string) => {
    navigate(`/vulnerabilities/${vulnerabilityId}`);
  };

  // Filter and sort vulnerabilities
  const filteredVulnerabilities = React.useMemo(() => {
    if (!data?.vulnerabilities) return [];

    let filtered = data.vulnerabilities.filter((vuln) => {
      const matchesSearch = 
        vuln.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        vuln.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        vuln.category?.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesSeverity = severityFilter === 'all' || 
        vuln.severity?.toLowerCase() === severityFilter.toLowerCase();

      const matchesStatus = statusFilter === 'all' ||
        (statusFilter === 'exploitable' && vuln.exploitable === true) ||
        (statusFilter === 'safe' && vuln.exploitable === false) ||
        (statusFilter === 'validated' && vuln.validated) ||
        (statusFilter === 'pending' && !vuln.validated);

      return matchesSearch && matchesSeverity && matchesStatus;
    });

    // Sort vulnerabilities
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'severity':
          const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
          return (severityOrder[b.severity as keyof typeof severityOrder] || 0) - 
                 (severityOrder[a.severity as keyof typeof severityOrder] || 0);
        case 'title':
          return (a.title || '').localeCompare(b.title || '');
        case 'created':
          return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
        default:
          return 0;
      }
    });

    return filtered;
  }, [data?.vulnerabilities, searchTerm, severityFilter, statusFilter, sortBy]);

  // Pagination
  const totalPages = Math.ceil(filteredVulnerabilities.length / itemsPerPage);
  const paginatedVulnerabilities = filteredVulnerabilities.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const clearFilters = () => {
    setSearchTerm('');
    setSeverityFilter('all');
    setStatusFilter('all');
    setSortBy('severity');
    setCurrentPage(1);
    setSearchParams({});
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="relative">
          <div className="w-16 h-16 border-4 border-vxdf-primary/20 border-t-vxdf-primary rounded-full animate-spin"></div>
          <div className="absolute inset-0 w-16 h-16 border-4 border-transparent border-t-vxdf-secondary rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1s' }}></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 sm:h-16 sm:w-16 text-red-400 mx-auto mb-4" />
        <h3 className="text-lg sm:text-xl font-semibold text-white mb-2">Failed to Load Vulnerabilities</h3>
        <p className="text-sm sm:text-base text-vxdf-gray-400">Please try refreshing the page</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white">Vulnerability Findings</h1>
          <p className="mt-1 text-sm sm:text-base text-vxdf-gray-400">
            {filteredVulnerabilities.length} of {data?.total || 0} vulnerabilities
          </p>
        </div>
        <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
          <button
            onClick={() => navigate('/upload')}
            className="btn-primary w-full sm:w-auto"
          >
            <FileText className="h-4 w-4 mr-2" />
            Upload New Scan
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4 sm:p-6">
        <div className="flex items-center space-x-2 mb-4">
          <Filter className="h-4 w-4 sm:h-5 sm:w-5 text-vxdf-gray-400" />
          <h3 className="text-base sm:text-lg font-semibold text-white">Filters & Search</h3>
        </div>
        
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
          {/* Search */}
          <div className="relative sm:col-span-2">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-vxdf-gray-400" />
            <input
              type="text"
              placeholder="Search vulnerabilities..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-vxdf-gray-800 border border-vxdf-gray-700 rounded-lg text-white placeholder-vxdf-gray-400 focus:outline-none focus:ring-2 focus:ring-vxdf-primary text-sm"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 bg-vxdf-gray-800 border border-vxdf-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vxdf-primary text-sm"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 bg-vxdf-gray-800 border border-vxdf-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vxdf-primary text-sm"
          >
            <option value="all">All Status</option>
            <option value="exploitable">Exploitable</option>
            <option value="safe">Not Exploitable</option>
            <option value="validated">Validated</option>
            <option value="pending">Pending</option>
          </select>

          {/* Sort */}
          <div className="flex items-center space-x-2">
            <SortAsc className="h-4 w-4 text-vxdf-gray-400 flex-shrink-0" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="flex-1 px-3 py-2 bg-vxdf-gray-800 border border-vxdf-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vxdf-primary text-sm"
            >
              <option value="severity">Severity</option>
              <option value="title">Title</option>
              <option value="created">Created Date</option>
            </select>
          </div>

          {/* Clear Filters */}
          <button
            onClick={clearFilters}
            className="btn-secondary w-full"
          >
            Clear Filters
          </button>
        </div>
      </div>

      {/* Vulnerability Grid */}
      {paginatedVulnerabilities.length === 0 ? (
        <div className="text-center py-12">
          <AlertTriangle className="h-12 w-12 sm:h-16 sm:w-16 text-vxdf-gray-600 mx-auto mb-4" />
          <h3 className="text-lg sm:text-xl font-semibold text-white mb-2">No Vulnerabilities Found</h3>
          <p className="text-sm sm:text-base text-vxdf-gray-400 mb-4">
            {searchTerm || severityFilter !== 'all' || statusFilter !== 'all'
              ? 'No vulnerabilities match your current filters.'
              : 'No vulnerabilities have been uploaded yet.'}
          </p>
          {!searchTerm && severityFilter === 'all' && statusFilter === 'all' && (
            <button
              onClick={() => navigate('/upload')}
              className="btn-primary"
            >
              Upload Your First Scan
            </button>
          )}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 sm:gap-6">
            {paginatedVulnerabilities.map((vulnerability) => (
              <VulnerabilityCard
                key={vulnerability.id}
                vulnerability={vulnerability}
                onStartValidation={handleStartValidation}
                onViewDetails={handleViewDetails}
              />
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center space-x-2 flex-wrap gap-2">
              <button
                onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                disabled={currentPage === 1}
                className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed text-sm px-3 py-2"
              >
                Previous
              </button>
              
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                const page = i + Math.max(1, currentPage - 2);
                return page <= totalPages ? (
                  <button
                    key={page}
                    onClick={() => setCurrentPage(page)}
                    className={`px-3 py-2 rounded-lg font-medium transition-colors text-sm ${
                      currentPage === page
                        ? 'bg-vxdf-primary text-white'
                        : 'bg-vxdf-gray-800 text-vxdf-gray-300 hover:bg-vxdf-gray-700'
                    }`}
                  >
                    {page}
                  </button>
                ) : null;
              })}
              
              <button
                onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                disabled={currentPage === totalPages}
                className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed text-sm px-3 py-2"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
} 
import React from 'react';
import { GitBranch, Play, CheckCircle, Clock, XCircle, Container, AlertTriangle, Zap } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { useVulnerabilities } from '../hooks/useVulnerabilities';

interface ValidationWorkflow {
  id: string;
  findingId: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  startTime: string;
  endTime: string | null;
  steps: Array<{
    name: string;
    status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
    startTime: string | null;
    endTime: string | null;
    logs: string[];
    dockerContainerId: string | null;
  }>;
  result: {
    exploitable: boolean;
    confidence: number;
    evidence: string[];
    recommendations: string[];
  } | null;
}

export default function ValidationWorkflows() {
  const { data: vulnerabilitiesData, isLoading: vulnerabilitiesLoading } = useVulnerabilities({ limit: 10 });

  // Mock some validation workflows based on real vulnerabilities
  const mockWorkflows = React.useMemo(() => {
    if (!vulnerabilitiesData?.vulnerabilities) return [];
    
    return vulnerabilitiesData.vulnerabilities.slice(0, 4).map((vuln, index) => ({
      id: `workflow-${vuln.id}`,
      findingId: vuln.id,
      findingTitle: vuln.title || vuln.name || 'Untitled Vulnerability',
      status: index === 0 ? 'RUNNING' : index === 1 ? 'COMPLETED' : index === 2 ? 'FAILED' : 'QUEUED',
      startTime: new Date(Date.now() - (index + 1) * 15 * 60000).toISOString(),
      endTime: index === 1 || index === 2 ? new Date(Date.now() - index * 10 * 60000).toISOString() : null,
      currentStep: index === 0 ? 'Docker Environment Setup' : '',
      progress: index === 0 ? 65 : 100,
      dockerContainer: `vxdf-validation-${String(index + 1).padStart(3, '0')}`,
      result: index === 1 ? { exploitable: true, confidence: 95 } : 
              index === 2 ? null : 
              index === 3 ? { exploitable: false, confidence: 87 } : null,
      error: index === 2 ? 'Unable to reproduce vulnerability in isolated environment' : null,
      severity: vuln.severity,
      category: vuln.category || vuln.type
    }));
  }, [vulnerabilitiesData?.vulnerabilities]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'RUNNING': return <Clock className="h-5 w-5 text-yellow-400 animate-pulse" />;
      case 'COMPLETED': return <CheckCircle className="h-5 w-5 text-green-400" />;
      case 'FAILED': return <XCircle className="h-5 w-5 text-red-400" />;
      case 'QUEUED': return <Clock className="h-5 w-5 text-blue-400" />;
      default: return <Clock className="h-5 w-5 text-gray-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'RUNNING': return 'status-pending';
      case 'COMPLETED': return 'status-validated';
      case 'FAILED': return 'status-exploitable';
      case 'QUEUED': return 'status-safe';
      default: return 'status-safe';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'border-red-500/30 bg-red-500/10';
      case 'high': return 'border-orange-500/30 bg-orange-500/10';
      case 'medium': return 'border-yellow-500/30 bg-yellow-500/10';
      case 'low': return 'border-green-500/30 bg-green-500/10';
      default: return 'border-gray-500/30 bg-gray-500/10';
    }
  };

  if (vulnerabilitiesLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="relative">
          <div className="w-16 h-16 border-4 border-vxdf-primary/20 border-t-vxdf-primary rounded-full animate-spin"></div>
          <div className="absolute inset-0 w-16 h-16 border-4 border-transparent border-t-vxdf-secondary rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1s' }}></div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 sm:space-y-8">
      {/* Header */}
      <div className="text-center sm:text-left">
        <h1 className="text-2xl sm:text-3xl font-bold text-white">Validation Workflows</h1>
        <p className="mt-1 text-sm sm:text-base text-vxdf-gray-400">
          Real-time Docker-based vulnerability validation and exploitability testing
        </p>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
        <div className="card p-4 sm:p-6 bg-gradient-to-br from-blue-500/20 to-vxdf-primary/20 border border-blue-500/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs sm:text-sm text-blue-200 uppercase tracking-wider">Active</p>
              <p className="text-xl sm:text-2xl font-bold text-white">
                {mockWorkflows.filter(w => w.status === 'RUNNING').length}
              </p>
            </div>
            <Zap className="h-6 w-6 sm:h-8 sm:w-8 text-blue-400" />
          </div>
        </div>
        
        <div className="card p-4 sm:p-6 bg-gradient-to-br from-green-500/20 to-emerald-500/20 border border-green-500/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs sm:text-sm text-green-200 uppercase tracking-wider">Completed</p>
              <p className="text-xl sm:text-2xl font-bold text-white">
                {mockWorkflows.filter(w => w.status === 'COMPLETED').length}
              </p>
            </div>
            <CheckCircle className="h-6 w-6 sm:h-8 sm:w-8 text-green-400" />
          </div>
        </div>
        
        <div className="card p-4 sm:p-6 bg-gradient-to-br from-red-500/20 to-pink-500/20 border border-red-500/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs sm:text-sm text-red-200 uppercase tracking-wider">Failed</p>
              <p className="text-xl sm:text-2xl font-bold text-white">
                {mockWorkflows.filter(w => w.status === 'FAILED').length}
              </p>
            </div>
            <XCircle className="h-6 w-6 sm:h-8 sm:w-8 text-red-400" />
          </div>
        </div>
        
        <div className="card p-4 sm:p-6 bg-gradient-to-br from-yellow-500/20 to-orange-500/20 border border-yellow-500/30">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs sm:text-sm text-yellow-200 uppercase tracking-wider">Queued</p>
              <p className="text-xl sm:text-2xl font-bold text-white">
                {mockWorkflows.filter(w => w.status === 'QUEUED').length}
              </p>
            </div>
            <Clock className="h-6 w-6 sm:h-8 sm:w-8 text-yellow-400" />
          </div>
        </div>
      </div>

      {/* Active Validations */}
      <div className="card p-4 sm:p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6 space-y-2 sm:space-y-0">
          <div className="flex items-center space-x-2">
            <GitBranch className="h-5 w-5 sm:h-6 sm:w-6 text-vxdf-primary" />
            <h2 className="text-lg sm:text-xl font-semibold text-white">Validation Pipeline</h2>
          </div>
          <div className="flex items-center space-x-2 text-xs sm:text-sm text-vxdf-gray-400">
            <div className="w-2 h-2 bg-vxdf-primary rounded-full animate-pulse"></div>
            <span>Live Updates</span>
          </div>
        </div>

        {mockWorkflows.length === 0 ? (
          <div className="text-center py-12">
            <GitBranch className="h-12 w-12 sm:h-16 sm:w-16 text-vxdf-gray-600 mx-auto mb-4" />
            <h3 className="text-lg sm:text-xl font-semibold text-white mb-2">No Active Validations</h3>
            <p className="text-sm sm:text-base text-vxdf-gray-400 mb-4">
              Start vulnerability validation to see Docker-based testing in action
            </p>
            <button className="btn-primary">
              <Play className="h-4 w-4 mr-2" />
              Start Validation
            </button>
          </div>
        ) : (
          <div className="space-y-4 sm:space-y-6">
            {mockWorkflows.map((workflow) => (
              <div key={workflow.id} className={`bg-vxdf-gray-800 p-4 sm:p-6 rounded-lg border ${getSeverityColor(workflow.severity)} hover:bg-vxdf-gray-750 transition-colors`}>
                <div className="flex flex-col sm:flex-row sm:items-start justify-between mb-4 space-y-3 sm:space-y-0">
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-col sm:flex-row sm:items-center space-y-2 sm:space-y-0 sm:space-x-3 mb-2">
                      <h3 className="text-base sm:text-lg font-semibold text-white truncate">
                        {workflow.findingTitle}
                      </h3>
                      {workflow.severity && (
                        <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${
                          workflow.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                          workflow.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                          workflow.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-green-500/20 text-green-400'
                        }`}>
                          {workflow.severity}
                        </span>
                      )}
                    </div>
                    <div className="flex flex-col sm:flex-row sm:items-center space-y-2 sm:space-y-0 sm:space-x-4">
                      <div className={`status-badge ${getStatusColor(workflow.status)} flex items-center space-x-1`}>
                        {getStatusIcon(workflow.status)}
                        <span>{workflow.status}</span>
                      </div>
                      <div className="flex items-center space-x-1 text-xs sm:text-sm text-vxdf-gray-400">
                        <Container className="h-3 w-3 sm:h-4 sm:w-4" />
                        <span>{workflow.dockerContainer}</span>
                      </div>
                      {workflow.category && (
                        <div className="text-xs sm:text-sm text-vxdf-gray-400">
                          📁 {workflow.category}
                        </div>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex space-x-2">
                    {workflow.status === 'RUNNING' && (
                      <button className="btn-secondary text-xs sm:text-sm px-3 py-1">
                        View Logs
                      </button>
                    )}
                    <button className="btn-secondary text-xs sm:text-sm px-3 py-1">
                      Details
                    </button>
                  </div>
                </div>

                {/* Progress for running workflows */}
                {workflow.status === 'RUNNING' && (
                  <div className="mb-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs sm:text-sm text-vxdf-gray-300">{workflow.currentStep}</span>
                      <span className="text-xs sm:text-sm text-vxdf-gray-400">{workflow.progress}%</span>
                    </div>
                    <div className="w-full bg-vxdf-gray-700 rounded-full h-2">
                      <div 
                        className="bg-gradient-to-r from-vxdf-primary to-vxdf-secondary h-2 rounded-full transition-all duration-300 shadow-sm"
                        style={{ width: `${workflow.progress}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Results for completed workflows */}
                {workflow.status === 'COMPLETED' && workflow.result && (
                  <div className="bg-vxdf-gray-900 p-3 sm:p-4 rounded-lg">
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
                      <span className="text-xs sm:text-sm text-vxdf-gray-300">Validation Result:</span>
                      <div className="flex items-center space-x-2">
                        <span className={`text-sm font-medium ${workflow.result.exploitable ? 'text-red-400' : 'text-green-400'}`}>
                          {workflow.result.exploitable ? 'Exploitable' : 'Not Exploitable'}
                        </span>
                        <span className="text-xs text-vxdf-gray-400">
                          ({workflow.result.confidence}% confidence)
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Error for failed workflows */}
                {workflow.status === 'FAILED' && workflow.error && (
                  <div className="bg-red-900/20 border border-red-500/30 p-3 sm:p-4 rounded-lg">
                    <div className="flex items-start space-x-2">
                      <AlertTriangle className="h-4 w-4 text-red-400 mt-0.5 flex-shrink-0" />
                      <p className="text-xs sm:text-sm text-red-400">{workflow.error}</p>
                    </div>
                  </div>
                )}

                {/* Timing info */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between text-xs text-vxdf-gray-500 mt-4 pt-3 border-t border-vxdf-gray-700 space-y-1 sm:space-y-0">
                  <span>Started: {new Date(workflow.startTime).toLocaleString()}</span>
                  {workflow.endTime && (
                    <span>Completed: {new Date(workflow.endTime).toLocaleString()}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Validation Process Overview */}
      <div className="card p-4 sm:p-6">
        <h3 className="text-lg sm:text-xl font-semibold text-white mb-4 sm:mb-6">VXDF Validation Process</h3>
        <div className="validation-flow">
          <div className="validation-step completed">
            <h4 className="font-medium text-white text-sm sm:text-base">1. Environment Preparation</h4>
            <p className="text-xs sm:text-sm text-vxdf-gray-400">Isolated Docker container setup with target application</p>
          </div>
          <div className="validation-step active">
            <h4 className="font-medium text-white text-sm sm:text-base">2. Exploitation Attempt</h4>
            <p className="text-xs sm:text-sm text-vxdf-gray-400">Automated testing using vulnerability-specific payloads</p>
          </div>
          <div className="validation-step">
            <h4 className="font-medium text-white text-sm sm:text-base">3. Evidence Collection</h4>
            <p className="text-xs sm:text-sm text-vxdf-gray-400">Capture and analyze exploitation artifacts</p>
          </div>
          <div className="validation-step">
            <h4 className="font-medium text-white text-sm sm:text-base">4. Risk Assessment</h4>
            <p className="text-xs sm:text-sm text-vxdf-gray-400">Calculate exploitability score and impact analysis</p>
          </div>
        </div>
      </div>
    </div>
  );
} 
export interface VulnerabilityFinding {
  id: string;
  name: string;
  title?: string;
  description: string | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  type: string;
  category?: string;
  cweId: string | null;
  cvssScore: number | null;
  isExploitable: boolean | null;
  exploitable?: boolean | null;
  isValidated: boolean;
  validated?: boolean;
  validationDate: string | null;
  validationMessage: string | null;
  createdAt: string;
  filePath: string;
  lineNumber: number | null;
  column: number | null;
  evidence: Array<{
    id: string;
    type: string;
    description: string;
    content: string | null;
    timestamp: string;
  }>;
  source?: {
    file: string;
    line: number | null;
    column: number | null;
    snippet: string | null;
  };
  sink?: {
    file: string;
    line: number | null;
    column: number | null;
    snippet: string | null;
  };
  dataFlow?: Array<{
    file: string;
    line: number;
    column: number | null;
    snippet: string | null;
    stepType: string;
    description: string;
  }>;
}

export interface VulnerabilityStats {
  total: number;
  validated: number;
  exploitable: number;
  pending: number;
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  byType: Record<string, number>;
  bySource: {
    sast: number;
    dast: number;
    sca: number;
    manual: number;
  };
}

export interface ValidationWorkflow {
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

export interface ScanUpload {
  file: File;
  scannerType: 'SARIF' | 'OWASP_ZAP' | 'BURP_SUITE' | 'SONARQUBE' | 'VERACODE' | 'CHECKMARX';
  targetName: string;
  targetVersion: string;
  autoValidate: boolean;
}

export interface ApiResponse<T> {
  data: T;
  success: boolean;
  message?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  hasMore: boolean;
} 
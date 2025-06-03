import { VulnerabilityFinding, VulnerabilityStats, ValidationWorkflow } from '../types';

const API_BASE = '/api';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

// Transform backend vulnerability data to frontend format
function transformVulnerability(backendVuln: any): VulnerabilityFinding {
  // Generate human-readable title from name and description
  const generateTitle = (name: string, description: string | null): string => {
    if (!name) return 'Untitled Vulnerability';
    
    // If the name is already descriptive, use it
    if (name.includes(' ') && name.length > 10) {
      return name;
    }
    
    // Transform technical names to readable titles
    const nameTransforms: Record<string, string> = {
      'SQL_INJECTION': 'SQL Injection Vulnerability',
      'ENTERPRISE_SQL': 'Enterprise SQL Injection',
      'ECOMMERCE_SQL': 'E-commerce SQL Injection',
      'XSS_STORED': 'Stored Cross-Site Scripting',
      'XSS_REFLECTED': 'Reflected Cross-Site Scripting',
      'PATH_TRAVERSAL': 'Path Traversal Vulnerability',
      'CSRF': 'Cross-Site Request Forgery',
      'COMMAND_INJECTION': 'Command Injection Vulnerability',
      'FILE_UPLOAD': 'File Upload Vulnerability'
    };
    
    // Try to match patterns
    for (const [pattern, title] of Object.entries(nameTransforms)) {
      if (name.toUpperCase().includes(pattern)) {
        return title;
      }
    }
    
    // If we have a description, use it to create a title
    if (description) {
      // Capitalize and clean up description
      const cleanDesc = description.replace(/[_-]/g, ' ').toLowerCase();
      return cleanDesc.charAt(0).toUpperCase() + cleanDesc.slice(1);
    }
    
    // Fall back to formatting the technical name
    return name
      .replace(/[_-]/g, ' ')
      .replace(/\b\w/g, l => l.toUpperCase())
      .replace(/\d+$/, match => ` ${match}`);
  };

  const title = generateTitle(backendVuln.name, backendVuln.description);

  return {
    id: backendVuln.id,
    name: backendVuln.name,
    title: title, // Computed human-readable title
    description: backendVuln.description,
    severity: backendVuln.severity,
    type: backendVuln.type || 'unknown',
    category: backendVuln.type || 'unknown', // Backward compatibility
    cweId: backendVuln.cweId,
    cvssScore: backendVuln.cvssScore,
    isExploitable: backendVuln.isExploitable,
    exploitable: backendVuln.isExploitable, // Backward compatibility
    isValidated: backendVuln.isValidated,
    validated: backendVuln.isValidated, // Backward compatibility
    validationDate: backendVuln.validationDate,
    validationMessage: backendVuln.validationMessage,
    createdAt: backendVuln.createdAt,
    filePath: backendVuln.filePath,
    lineNumber: backendVuln.lineNumber,
    column: backendVuln.column,
    evidence: backendVuln.evidence || [],
    // Create source info from backend data
    source: {
      file: backendVuln.filePath || 'Unknown',
      line: backendVuln.lineNumber,
      column: backendVuln.column,
      snippet: null
    },
    // For now, sink is same as source (can be enhanced later)
    sink: {
      file: backendVuln.filePath || 'Unknown',
      line: backendVuln.lineNumber,
      column: backendVuln.column,
      snippet: null
    },
    dataFlow: []
  };
}

async function apiRequest<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new ApiError(response.status, errorText || 'Request failed');
  }

  return response.json();
}

// Vulnerability Findings API
export async function getVulnerabilities(params: {
  limit?: number;
  offset?: number;
  severity?: string;
  category?: string;
  exploitable?: boolean;
  validated?: boolean;
} = {}) {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined) {
      searchParams.append(key, String(value));
    }
  });

  const response = await apiRequest<{
    vulnerabilities: any[];
    total: number;
    limit: number;
    offset: number;
  }>(`/vulnerabilities?${searchParams.toString()}`);

  return {
    ...response,
    vulnerabilities: response.vulnerabilities.map(transformVulnerability)
  };
}

export async function getVulnerability(id: string) {
  const vulnerability = await apiRequest<any>(`/vulnerabilities/${id}`);
  return transformVulnerability(vulnerability);
}

export async function getVulnerabilityStats() {
  return apiRequest<VulnerabilityStats>('/stats');
}

// Validation Workflow API
export async function getValidationWorkflows() {
  return apiRequest<ValidationWorkflow[]>('/validation/workflows');
}

export async function getValidationWorkflow(id: string) {
  return apiRequest<ValidationWorkflow>(`/validation/workflows/${id}`);
}

export async function startValidation(findingId: string) {
  return apiRequest<{ workflowId: string }>('/validation/start', {
    method: 'POST',
    body: JSON.stringify({ findingId }),
  });
}

// Upload API
export async function uploadScanFile(
  file: File,
  options: {
    parserType?: string;
    validate?: boolean;
    targetName?: string;
    targetVersion?: string;
    minSeverity?: string;
  } = {}
) {
  const formData = new FormData();
  formData.append('file', file);
  
  Object.entries(options).forEach(([key, value]) => {
    if (value !== undefined) {
      const fieldName = key === 'parserType' ? 'parser_type' : 
                       key === 'targetName' ? 'target_name' :
                       key === 'targetVersion' ? 'target_version' :
                       key === 'minSeverity' ? 'min_severity' : key;
      formData.append(fieldName, String(value));
    }
  });

  const response = await fetch(`${API_BASE}/upload`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new ApiError(response.status, errorText || 'Upload failed');
  }

  return response.json();
}

// Real-time updates
export function createEventSource(endpoint: string) {
  return new EventSource(`${API_BASE}${endpoint}`);
} 
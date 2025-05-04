/**
 * Core type definitions for the AppSec Validator platform
 */

// Supported input file types
export enum ScanFileType {
  SARIF = 'sarif',
  CYCLONEDX = 'cyclonedx',
  DAST = 'dast'
}

// Vulnerability severity levels
export enum Severity {
  CRITICAL = 'Critical',
  HIGH = 'High',
  MEDIUM = 'Medium',
  LOW = 'Low',
  INFO = 'Informational'
}

// Vulnerability status
export enum ValidationStatus {
  EXPLOITABLE = 'Exploitable',
  NOT_EXPLOITABLE = 'Not Exploitable',
  NEEDS_REVIEW = 'Needs Review',
  FALSE_POSITIVE = 'False Positive',
  IN_PROGRESS = 'Validating'
}

// Core vulnerability interface
export interface Vulnerability {
  id: string;
  title: string;
  description?: string;
  severity: Severity;
  category: string;
  cwe?: string;
  source: CodeLocation;
  sink: CodeLocation;
  steps?: DataFlowStep[];
  evidence?: Evidence[];
  status: ValidationStatus;
  remediationGuidance?: string;
}

// Code location
export interface CodeLocation {
  file: string;
  line: number;
  column?: number;
  function?: string;
  snippet?: string;
}

// Data flow step
export interface DataFlowStep {
  location: CodeLocation;
  type: 'source' | 'propagation' | 'sink';
  note?: string;
}

// Evidence of vulnerability exploitation
export interface Evidence {
  description: string;
  method?: string;
  timestamp?: string;
  payload?: string;
  responseData?: string;
  screenshot?: string;
}

// VXDF (Validated Exploitable Data Flow) report
export interface VXDFReport {
  vxdfVersion: string;
  metadata: {
    generator: string;
    timestamp: string;
    target?: string;
  };
  flows: VXDFFlow[];
}

// VXDF Flow
export interface VXDFFlow {
  id: string;
  title: string;
  description?: string;
  severity: Severity;
  category: string;
  cwe?: string;
  source: {
    file: string;
    line: number;
    function?: string;
    snippet?: string;
  };
  sink: {
    file: string;
    line: number;
    function?: string;
    snippet?: string;
  };
  steps?: Array<{
    file: string;
    line: number;
    function?: string;
    snippet?: string;
    note?: string;
  }>;
  evidence: Array<{
    description: string;
    method?: string;
    timestamp?: string;
  }>;
}

// Input parsers
export interface ScanParser {
  parse(fileContent: string): Vulnerability[];
  supports(fileType: string): boolean;
}

// Validation engine
export interface ValidationEngine {
  validate(vulnerability: Vulnerability): Promise<Vulnerability>;
  validateBatch(vulnerabilities: Vulnerability[]): Promise<Vulnerability[]>;
}
/**
 * Core type definitions for the VXDF v1.0.0 platform
 */

// Supported input file types
export enum ScanFileType {
  SARIF = 'sarif',
  CYCLONEDX = 'cyclonedx',
  DAST = 'dast'
}

// VXDF v1.0.0 Severity levels (matching SeverityLevelEnum)
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFORMATIONAL = 'INFORMATIONAL',
  NONE = 'NONE'
}

// VXDF v1.0.0 Status enum (matching StatusEnum)
export enum ValidationStatus {
  OPEN = 'OPEN',
  UNDER_INVESTIGATION = 'UNDER_INVESTIGATION',
  REMEDIATION_IN_PROGRESS = 'REMEDIATION_IN_PROGRESS',
  REMEDIATED = 'REMEDIATED',
  REMEDIATION_VERIFIED = 'REMEDIATION_VERIFIED',
  FALSE_POSITIVE_AFTER_REVALIDATION = 'FALSE_POSITIVE_AFTER_REVALIDATION',
  ACCEPTED_RISK = 'ACCEPTED_RISK',
  DEFERRED = 'DEFERRED',
  OTHER = 'OTHER'
}

// VXDF v1.0.0 Location Type enum
export enum LocationType {
  SOURCE_CODE_UNIT = 'SOURCE_CODE_UNIT',
  WEB_ENDPOINT_PARAMETER = 'WEB_ENDPOINT_PARAMETER',
  WEB_HTTP_HEADER = 'WEB_HTTP_HEADER',
  WEB_COOKIE = 'WEB_COOKIE',
  SOFTWARE_COMPONENT_LIBRARY = 'SOFTWARE_COMPONENT_LIBRARY',
  CONFIGURATION_FILE_SETTING = 'CONFIGURATION_FILE_SETTING',
  FILE_SYSTEM_ARTIFACT = 'FILE_SYSTEM_ARTIFACT',
  NETWORK_SERVICE_ENDPOINT = 'NETWORK_SERVICE_ENDPOINT',
  DATABASE_SCHEMA_OBJECT = 'DATABASE_SCHEMA_OBJECT',
  ENVIRONMENT_VARIABLE = 'ENVIRONMENT_VARIABLE',
  OPERATING_SYSTEM_REGISTRY_KEY = 'OPERATING_SYSTEM_REGISTRY_KEY',
  CLOUD_PLATFORM_RESOURCE = 'CLOUD_PLATFORM_RESOURCE',
  EXECUTABLE_BINARY_FUNCTION = 'EXECUTABLE_BINARY_FUNCTION',
  PROCESS_MEMORY_REGION = 'PROCESS_MEMORY_REGION',
  USER_INTERFACE_ELEMENT = 'USER_INTERFACE_ELEMENT',
  GENERIC_RESOURCE_IDENTIFIER = 'GENERIC_RESOURCE_IDENTIFIER'
}

// VXDF v1.0.0 Evidence Type enum
export enum EvidenceType {
  HTTP_REQUEST_LOG = 'HTTP_REQUEST_LOG',
  HTTP_RESPONSE_LOG = 'HTTP_RESPONSE_LOG',
  CODE_SNIPPET_SOURCE = 'CODE_SNIPPET_SOURCE',
  CODE_SNIPPET_SINK = 'CODE_SNIPPET_SINK',
  CODE_SNIPPET_CONTEXT = 'CODE_SNIPPET_CONTEXT',
  POC_SCRIPT = 'POC_SCRIPT',
  RUNTIME_APPLICATION_LOG_ENTRY = 'RUNTIME_APPLICATION_LOG_ENTRY',
  RUNTIME_SYSTEM_LOG_ENTRY = 'RUNTIME_SYSTEM_LOG_ENTRY',
  RUNTIME_WEB_SERVER_LOG_ENTRY = 'RUNTIME_WEB_SERVER_LOG_ENTRY',
  RUNTIME_DATABASE_LOG_ENTRY = 'RUNTIME_DATABASE_LOG_ENTRY',
  RUNTIME_DEBUGGER_OUTPUT = 'RUNTIME_DEBUGGER_OUTPUT',
  RUNTIME_EXCEPTION_TRACE = 'RUNTIME_EXCEPTION_TRACE',
  SCREENSHOT_URL = 'SCREENSHOT_URL',
  SCREENSHOT_EMBEDDED_BASE64 = 'SCREENSHOT_EMBEDDED_BASE64',
  MANUAL_VERIFICATION_NOTES = 'MANUAL_VERIFICATION_NOTES',
  TEST_PAYLOAD_USED = 'TEST_PAYLOAD_USED',
  ENVIRONMENT_CONFIGURATION_DETAILS = 'ENVIRONMENT_CONFIGURATION_DETAILS',
  NETWORK_TRAFFIC_CAPTURE_SUMMARY = 'NETWORK_TRAFFIC_CAPTURE_SUMMARY',
  STATIC_ANALYSIS_DATA_FLOW_PATH = 'STATIC_ANALYSIS_DATA_FLOW_PATH',
  STATIC_ANALYSIS_CONTROL_FLOW_GRAPH = 'STATIC_ANALYSIS_CONTROL_FLOW_GRAPH',
  CONFIGURATION_FILE_SNIPPET = 'CONFIGURATION_FILE_SNIPPET',
  VULNERABLE_COMPONENT_SCAN_OUTPUT = 'VULNERABLE_COMPONENT_SCAN_OUTPUT',
  MISSING_ARTIFACT_VERIFICATION = 'MISSING_ARTIFACT_VERIFICATION',
  OBSERVED_BEHAVIORAL_CHANGE = 'OBSERVED_BEHAVIORAL_CHANGE',
  DATABASE_STATE_CHANGE_PROOF = 'DATABASE_STATE_CHANGE_PROOF',
  FILE_SYSTEM_CHANGE_PROOF = 'FILE_SYSTEM_CHANGE_PROOF',
  COMMAND_EXECUTION_OUTPUT = 'COMMAND_EXECUTION_OUTPUT',
  EXFILTRATED_DATA_SAMPLE = 'EXFILTRATED_DATA_SAMPLE',
  SESSION_INFORMATION_LEAK = 'SESSION_INFORMATION_LEAK',
  EXTERNAL_INTERACTION_PROOF = 'EXTERNAL_INTERACTION_PROOF',
  DIFFERENTIAL_ANALYSIS_RESULT = 'DIFFERENTIAL_ANALYSIS_RESULT',
  TOOL_SPECIFIC_OUTPUT_LOG = 'TOOL_SPECIFIC_OUTPUT_LOG',
  OTHER_EVIDENCE = 'OTHER_EVIDENCE'
}

// VXDF v1.0.0 Location interface
export interface Location {
  locationType: LocationType;
  description?: string;
  uri?: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  snippet?: string;
  fullyQualifiedName?: string;
  symbol?: string;
  url?: string;
  customProperties?: Record<string, any>;
}

// VXDF v1.0.0 Evidence interface
export interface Evidence {
  evidenceType: EvidenceType;
  description: string;
  data: any; // Structure depends on evidenceType
  id: string;
  validationMethod?: string;
  timestamp?: string;
  customProperties?: Record<string, any>;
}

// VXDF v1.0.0 Trace Step interface
export interface TraceStep {
  order: number;
  location: Location;
  description: string;
  stepType?: string;
  evidenceRefs?: string[];
  customProperties?: Record<string, any>;
}

// VXDF v1.0.0 Exploit Flow interface
export interface ExploitFlow {
  flowId?: string;
  description: string;
  trace: TraceStep[];
  status: ValidationStatus;
  exploitabilityAssessment?: {
    level?: string;
    description?: string;
    cvssExploitabilitySubscore?: number;
  };
  validationHistory?: any[];
  affectedComponents?: any[];
  remediationRecommendations?: string;
  primaryExploitScenario?: boolean;
  customProperties?: Record<string, any>;
}

// VXDF v1.0.0 Severity Model interface
export interface SeverityModel {
  level: Severity;
  cvssV3_1?: any;
  cvssV4_0?: any;
  customScore?: any;
  justification?: string;
}

// VXDF v1.0.0 Vulnerability Details interface
export interface VulnerabilityDetails {
  vulnerabilityId: string;
  alternateIds?: string[];
  title: string;
  description: string;
  discoveryDate: string;
  disclosureDate?: string;
  discoverySource?: string;
  severity: SeverityModel;
  exploitFlows: ExploitFlow[];
  affectedApplications?: any[];
  tags?: string[];
  cwes?: number[];
  owaspTopTenCategories?: string[];
  references?: string[];
  remediationInfo?: any;
  customProperties?: Record<string, any>;
}

// VXDF v1.0.0 Document interface
export interface VXDFDocument {
  vxdfVersion: '1.0.0';
  documentId: string;
  generatedAt: string;
  generatorToolInfo?: {
    name: string;
    version?: string;
  };
  vulnerability: VulnerabilityDetails;
  evidencePool?: Evidence[];
  customProperties?: Record<string, any>;
}

// Legacy interfaces for backward compatibility
export interface Vulnerability {
  id: string;
  title: string;
  description?: string;
  severity: Severity;
  category: string;
  cwe?: string;
  source: Location;
  sink: Location;
  steps?: TraceStep[];
  evidence?: Evidence[];
  status: ValidationStatus;
  remediationGuidance?: string;
}

// Legacy aliases
export interface CodeLocation extends Location {}
export interface DataFlowStep extends TraceStep {}
export interface VXDFReport extends VXDFDocument {}
export interface VXDFFlow extends ExploitFlow {}

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
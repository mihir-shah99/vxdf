// VXDF Generator - Converts validation results to VXDF format

export interface VXDFDocument {
  vxdfVersion: string;
  metadata: {
    generator: string;
    timestamp: string;
    target?: string;
  };
  flows: Array<{
    id: string;
    title: string;
    description?: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
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
  }>;
}

/**
 * Generate a VXDF document from validation results
 */
export function generateVXDF(validationResults: any[]): VXDFDocument {
  return {
    vxdfVersion: "1.0",
    metadata: {
      generator: "AppSec Validator v0.1.0",
      timestamp: new Date().toISOString(),
      target: "Target Application"
    },
    flows: validationResults.map((result, index) => ({
      id: result.vulnerability.id || `F-${index + 1}`,
      title: result.vulnerability.title,
      description: result.vulnerability.description,
      severity: result.vulnerability.severity,
      category: result.vulnerability.category,
      cwe: getCWEForCategory(result.vulnerability.category),
      source: {
        file: result.vulnerability.source.file,
        line: result.vulnerability.source.line,
        snippet: result.vulnerability.source.snippet
      },
      sink: {
        file: result.vulnerability.sink.file,
        line: result.vulnerability.sink.line,
        snippet: result.vulnerability.sink.snippet
      },
      steps: result.vulnerability.steps,
      evidence: result.evidence || [{
        description: "Validation evidence not available",
        timestamp: new Date().toISOString()
      }]
    }))
  };
}

/**
 * Maps vulnerability categories to CWE IDs
 */
function getCWEForCategory(category: string): string | undefined {
  const cweMap: Record<string, string> = {
    "Injection": "CWE-89",
    "XSS": "CWE-79",
    "SQL Injection": "CWE-89",
    "Path Traversal": "CWE-22",
    "Command Injection": "CWE-78",
    "SSRF": "CWE-918",
    "Deserialization": "CWE-502",
    "Authentication": "CWE-287",
    "Authorization": "CWE-863"
  };
  
  return cweMap[category];
}

/**
 * Exports VXDF to a JSON file (in a browser environment)
 */
export function exportVXDFFile(vxdf: VXDFDocument): void {
  const dataStr = JSON.stringify(vxdf, null, 2);
  const dataUri = `data:application/json;charset=utf-8,${encodeURIComponent(dataStr)}`;
  
  const exportName = `vxdf-report-${new Date().toISOString().slice(0, 10)}.json`;
  
  const linkElement = document.createElement('a');
  linkElement.setAttribute('href', dataUri);
  linkElement.setAttribute('download', exportName);
  linkElement.click();
  linkElement.remove();
}
/**
 * SARIF Parser
 * 
 * Parses SARIF (Static Analysis Results Interchange Format) files
 */

import { Vulnerability, ScanParser, Severity, ValidationStatus, CodeLocation } from '../types/core';

interface SARIFLocation {
  physicalLocation?: {
    artifactLocation?: {
      uri?: string;
    };
    region?: {
      startLine?: number;
      startColumn?: number;
      snippet?: {
        text?: string;
      };
    };
  };
}

interface SARIFResult {
  ruleId?: string;
  message: {
    text: string;
  };
  level?: string;
  locations?: SARIFLocation[];
  codeFlows?: Array<{
    threadFlows: Array<{
      locations: Array<{
        location: SARIFLocation;
        importance?: string;
      }>;
    }>;
  }>;
}

interface SARIFRun {
  tool: {
    driver: {
      name: string;
      rules?: Array<{
        id: string;
        shortDescription?: {
          text: string;
        };
        fullDescription?: {
          text: string;
        };
        properties?: {
          tags?: string[];
          precision?: string;
          security-severity?: string;
        };
      }>;
    };
  };
  results: SARIFResult[];
}

interface SARIFFile {
  version: string;
  $schema?: string;
  runs: SARIFRun[];
}

export class SARIFParser implements ScanParser {
  /**
   * Determines if this parser can handle the given file type
   */
  public supports(fileType: string): boolean {
    return fileType.toLowerCase().endsWith('.sarif.json') || 
           fileType.toLowerCase().endsWith('.sarif');
  }
  
  /**
   * Parses a SARIF file and extracts vulnerabilities
   */
  public parse(fileContent: string): Vulnerability[] {
    try {
      const sarif: SARIFFile = JSON.parse(fileContent);
      
      if (!sarif.runs || !Array.isArray(sarif.runs)) {
        throw new Error('Invalid SARIF format: missing runs array');
      }
      
      const vulnerabilities: Vulnerability[] = [];
      
      // Process each run in the SARIF file
      for (const run of sarif.runs) {
        if (!run.results || !Array.isArray(run.results)) {
          continue;
        }
        
        // Create a map of rule IDs to rule metadata
        const rulesMap = new Map();
        if (run.tool?.driver?.rules) {
          for (const rule of run.tool.driver.rules) {
            if (rule.id) {
              rulesMap.set(rule.id, rule);
            }
          }
        }
        
        // Process each result in the run
        for (const result of run.results) {
          // Skip if no locations (we need at least a sink)
          if (!result.locations || result.locations.length === 0) {
            continue;
          }
          
          // Get rule metadata if available
          const rule = result.ruleId ? rulesMap.get(result.ruleId) : null;
          
          // Extract the primary location (sink)
          const primaryLocation = result.locations[0];
          const sinkLocation = this.extractLocationInfo(primaryLocation);
          
          // If there's no sink information, skip this result
          if (!sinkLocation) {
            continue;
          }
          
          // Determine severity from the level or rule properties
          let severity = this.determineSeverity(result.level, rule);
          
          // Extract or generate a title
          const title = rule?.shortDescription?.text || result.message.text;
          
          // Extract or generate a description
          const description = rule?.fullDescription?.text || result.message.text;
          
          // Extract category/type from rule tags if available
          const category = this.determineCategory(rule);
          
          // Extract CWE if available in tags
          const cwe = this.extractCWE(rule);
          
          // Extract source and data flow if codeFlows is available
          let source: CodeLocation | undefined;
          const steps = [];
          
          if (result.codeFlows && result.codeFlows.length > 0) {
            const threadFlow = result.codeFlows[0].threadFlows[0];
            if (threadFlow && threadFlow.locations && threadFlow.locations.length > 0) {
              // First location is often the source
              const sourceLocationInfo = this.extractLocationInfo(threadFlow.locations[0].location);
              if (sourceLocationInfo) {
                source = sourceLocationInfo;
              }
              
              // Extract all steps
              for (const flowLocation of threadFlow.locations) {
                const stepLocation = this.extractLocationInfo(flowLocation.location);
                if (stepLocation) {
                  steps.push({
                    location: stepLocation,
                    type: flowLocation === threadFlow.locations[0] ? 'source' :
                          flowLocation === threadFlow.locations[threadFlow.locations.length - 1] ? 'sink' :
                          'propagation',
                    note: flowLocation.importance || undefined
                  });
                }
              }
            }
          }
          
          // If no source was found in codeFlows, use the sink as the source
          if (!source) {
            source = { ...sinkLocation };
          }
          
          // Create the vulnerability object
          const vulnerability: Vulnerability = {
            id: `SARIF-${result.ruleId || `RULE-${vulnerabilities.length + 1}`}`,
            title,
            description,
            severity,
            category,
            cwe,
            source,
            sink: sinkLocation,
            steps: steps.length > 0 ? steps : undefined,
            status: ValidationStatus.NEEDS_REVIEW
          };
          
          vulnerabilities.push(vulnerability);
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      console.error('Error parsing SARIF file:', error);
      throw new Error(`Failed to parse SARIF file: ${error.message}`);
    }
  }
  
  /**
   * Extracts location information from a SARIF location
   */
  private extractLocationInfo(location: SARIFLocation): CodeLocation | null {
    if (!location.physicalLocation?.artifactLocation?.uri) {
      return null;
    }
    
    return {
      file: location.physicalLocation.artifactLocation.uri,
      line: location.physicalLocation.region?.startLine || 0,
      column: location.physicalLocation.region?.startColumn,
      snippet: location.physicalLocation.region?.snippet?.text
    };
  }
  
  /**
   * Determines severity from result level or rule properties
   */
  private determineSeverity(level?: string, rule?: any): Severity {
    // Try to get severity from security-severity property
    if (rule?.properties?.['security-severity']) {
      const securitySeverity = parseFloat(rule.properties['security-severity']);
      if (!isNaN(securitySeverity)) {
        if (securitySeverity >= 9.0) return Severity.CRITICAL;
        if (securitySeverity >= 7.0) return Severity.HIGH;
        if (securitySeverity >= 4.0) return Severity.MEDIUM;
        if (securitySeverity > 0.0) return Severity.LOW;
        return Severity.INFO;
      }
    }
    
    // Use the level if provided
    if (level) {
      switch (level.toLowerCase()) {
        case 'error': return Severity.HIGH;
        case 'warning': return Severity.MEDIUM;
        case 'note': return Severity.LOW;
        case 'none': return Severity.INFO;
      }
    }
    
    // Default severity
    return Severity.MEDIUM;
  }
  
  /**
   * Determines category from rule tags
   */
  private determineCategory(rule?: any): string {
    if (rule?.properties?.tags && Array.isArray(rule.properties.tags)) {
      // Look for common security categories in tags
      const securityTags = [
        'injection', 'sql-injection', 'xss', 'cross-site-scripting',
        'path-traversal', 'command-injection', 'ssrf', 'xxe', 'access-control',
        'open-redirect', 'insecure-deserialization'
      ];
      
      for (const tag of rule.properties.tags) {
        const normalizedTag = tag.toLowerCase();
        
        if (normalizedTag.includes('injection')) {
          if (normalizedTag.includes('sql')) return 'SQL Injection';
          if (normalizedTag.includes('command')) return 'Command Injection';
          if (normalizedTag.includes('os')) return 'OS Command Injection';
          return 'Injection';
        }
        
        if (normalizedTag.includes('xss') || normalizedTag.includes('cross-site-script')) {
          return 'XSS';
        }
        
        if (normalizedTag.includes('path-traversal') || normalizedTag.includes('directory-traversal')) {
          return 'Path Traversal';
        }
        
        if (normalizedTag.includes('ssrf')) {
          return 'SSRF';
        }
        
        // Check other categories...
      }
    }
    
    // If no specific security category found, use a generic one
    return 'Security Vulnerability';
  }
  
  /**
   * Extracts CWE ID from rule tags
   */
  private extractCWE(rule?: any): string | undefined {
    if (rule?.properties?.tags && Array.isArray(rule.properties.tags)) {
      for (const tag of rule.properties.tags) {
        // Look for tags like "cwe-79" or "CWE-352"
        const match = tag.match(/cwe-(\d+)/i);
        if (match) {
          return `CWE-${match[1]}`;
        }
      }
    }
    
    return undefined;
  }
}
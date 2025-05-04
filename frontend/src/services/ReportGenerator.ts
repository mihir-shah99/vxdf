/**
 * Report Generator
 * 
 * Creates VXDF reports from validation results.
 */

import { ValidationResult } from '../engines/ExploitValidationEngine';
import { DataFlowPath } from '../engines/DataFlowEngine';

export interface VXDFFlow {
  id: string;
  title: string;
  description: string;
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
  steps: Array<{
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

export interface VXDFReport {
  vxdfVersion: string;
  metadata: {
    generator: string;
    timestamp: string;
    target?: string;
  };
  flows: VXDFFlow[];
}

export class VXDFReportGenerator {
  /**
   * Generates a VXDF report from validation results
   */
  public generateReport(
    validationResults: ValidationResult[],
    dataFlowPaths: Record<string, DataFlowPath>,
    target: string
  ): VXDFReport {
    const flows: VXDFFlow[] = validationResults
      .filter(result => result.exploitable)
      .map(result => {
        const dataFlow = dataFlowPaths[result.vulnerabilityId];
        
        return {
          id: result.vulnerabilityId,
          title: this.generateTitle(result),
          description: this.generateDescription(result),
          severity: this.determineSeverity(result),
          category: this.determineCategory(result),
          cwe: this.determineCWE(result),
          source: {
            file: dataFlow.source.file,
            line: dataFlow.source.line,
            function: dataFlow.source.function,
            snippet: dataFlow.source.snippet
          },
          sink: {
            file: dataFlow.sink.file,
            line: dataFlow.sink.line,
            function: dataFlow.sink.function,
            snippet: dataFlow.sink.snippet
          },
          steps: dataFlow.steps.map(step => ({
            file: step.location.file,
            line: step.location.line,
            function: step.location.function,
            snippet: step.location.snippet,
            note: step.note
          })),
          evidence: result.evidence.map(evidence => ({
            description: evidence.description,
            method: evidence.method,
            timestamp: evidence.timestamp
          }))
        };
      });
    
    return {
      vxdfVersion: "1.0",
      metadata: {
        generator: "AppSec Validator v0.1.0",
        timestamp: new Date().toISOString(),
        target
      },
      flows
    };
  }
  
  /**
   * Generates a title for the vulnerability flow
   */
  private generateTitle(result: ValidationResult): string {
    const category = this.determineCategory(result);
    return `${category} in ${this.getComponentFromId(result.vulnerabilityId)}`;
  }
  
  /**
   * Generates a detailed description of the vulnerability
   */
  private generateDescription(result: ValidationResult): string {
    const category = this.determineCategory(result);
    const component = this.getComponentFromId(result.vulnerabilityId);
    
    return `A validated ${category} vulnerability was found in ${component}. 
    The vulnerability allows an attacker to ${this.getAttackImpact(category)}.`;
  }
  
  /**
   * Extracts a component name from the vulnerability ID
   */
  private getComponentFromId(id: string): string {
    // In a real implementation, this would extract meaningful component info
    // For demo, we'll use mock components
    const components = [
      'login form',
      'user profile',
      'admin panel',
      'file upload',
      'payment processing',
      'authentication module'
    ];
    
    // Use a hash of the ID to pick a consistent component
    const hash = Array.from(id).reduce((sum, char) => sum + char.charCodeAt(0), 0);
    return components[hash % components.length];
  }
  
  /**
   * Determines the severity based on the validation result
   */
  private determineSeverity(result: ValidationResult): 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' {
    // In a real implementation, this would use CVSS or similar metrics
    // For demo, we'll use basic logic
    
    if (!result.exploitable) return 'Informational';
    
    const category = this.determineCategory(result);
    const criticalCategories = ['SQL Injection', 'Command Injection', 'Remote Code Execution'];
    const highCategories = ['XSS', 'SSRF', 'XXE', 'Deserialization'];
    
    if (criticalCategories.includes(category)) return 'Critical';
    if (highCategories.includes(category)) return 'High';
    
    return result.confidence === 'high' ? 'Medium' : 'Low';
  }
  
  /**
   * Determines the vulnerability category
   */
  private determineCategory(result: ValidationResult): string {
    // In a real implementation, this would parse the validation result
    // For demo, we'll use the vulnerability ID to infer a category
    
    const categoryMap: Record<string, string> = {
      'SQL': 'SQL Injection',
      'XSS': 'Cross-Site Scripting',
      'CMD': 'Command Injection',
      'PATH': 'Path Traversal',
      'SSRF': 'Server-Side Request Forgery',
      'DESER': 'Deserialization',
      'XXE': 'XML External Entity'
    };
    
    // Check if the ID contains any category keywords
    for (const [key, value] of Object.entries(categoryMap)) {
      if (result.vulnerabilityId.includes(key)) {
        return value;
      }
    }
    
    return 'Unknown Vulnerability';
  }
  
  /**
   * Maps a vulnerability category to a CWE ID
   */
  private determineCWE(result: ValidationResult): string | undefined {
    const category = this.determineCategory(result);
    
    const cweMap: Record<string, string> = {
      'SQL Injection': 'CWE-89',
      'Cross-Site Scripting': 'CWE-79',
      'Command Injection': 'CWE-78',
      'Path Traversal': 'CWE-22',
      'Server-Side Request Forgery': 'CWE-918',
      'Deserialization': 'CWE-502',
      'XML External Entity': 'CWE-611'
    };
    
    return cweMap[category];
  }
  
  /**
   * Describes the impact of exploiting this vulnerability type
   */
  private getAttackImpact(category: string): string {
    const impactMap: Record<string, string> = {
      'SQL Injection': 'execute arbitrary SQL commands and potentially access, modify, or delete database content',
      'Cross-Site Scripting': 'execute malicious JavaScript in the context of other users' browsers',
      'Command Injection': 'execute arbitrary system commands on the host operating system',
      'Path Traversal': 'access files and directories outside of the intended directory',
      'Server-Side Request Forgery': 'make the server perform requests to internal resources',
      'Deserialization': 'execute arbitrary code during object deserialization',
      'XML External Entity': 'access local files or perform server-side request forgery via XML parsing'
    };
    
    return impactMap[category] || 'exploit the system in an unexpected way';
  }
}
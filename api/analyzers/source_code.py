"""
Real Source Code Analyzer for VXDF
Provides actual analysis of vulnerable source code, not fictional endpoints.
"""
import ast
import os
import re
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityContext:
    """
    Rich context about a vulnerability extracted from actual source code analysis.
    """
    file_path: str
    function_name: str
    vulnerable_line: int
    user_input_sources: List[str]
    dangerous_sinks: List[str]
    data_flow_path: List[str]
    technology_stack: List[str]
    frameworks_detected: List[str]
    database_operations: List[str]
    authentication_context: Optional[str]

class SourceCodeAnalyzer:
    """
    Analyzes actual source code to understand vulnerability context.
    This replaces the fraudulent fictional endpoint testing.
    """
    
    def __init__(self):
        self.supported_languages = {
            '.py': self._analyze_python,
            '.java': self._analyze_java,
            '.js': self._analyze_javascript,
            '.jsx': self._analyze_javascript,
            '.ts': self._analyze_typescript,
            '.tsx': self._analyze_typescript,
            '.php': self._analyze_php,
            '.cs': self._analyze_csharp,
            '.cpp': self._analyze_cpp,
            '.c': self._analyze_c
        }
        
    def analyze_vulnerability(self, finding) -> Optional[VulnerabilityContext]:
        """
        Perform REAL analysis of the vulnerable source code.
        This is what makes VXDF valuable vs fraudulent fictional testing.
        """
        try:
            if not finding.file_path:
                logger.warning(f"No file path in finding {finding.id}")
                return None
                
            # Check if file exists (could be relative to project root)
            file_path = self._resolve_file_path(finding.file_path)
            if not file_path or not os.path.exists(file_path):
                logger.warning(f"Source file not found: {finding.file_path}")
                return None
            
            file_ext = os.path.splitext(file_path)[1].lower()
            analyzer = self.supported_languages.get(file_ext)
            
            if not analyzer:
                logger.warning(f"Unsupported file type: {file_ext}")
                return None
            
            logger.info(f"Analyzing {file_ext} source code: {file_path}")
            return analyzer(finding, file_path)
            
        except Exception as e:
            logger.error(f"Error analyzing source code for finding {finding.id}: {e}")
            return None
    
    def _resolve_file_path(self, file_path: str) -> Optional[str]:
        """
        Resolve relative file paths to absolute paths.
        """
        if os.path.isabs(file_path) and os.path.exists(file_path):
            return file_path
        
        # Try relative to current working directory
        if os.path.exists(file_path):
            return os.path.abspath(file_path)
        
        # Try relative to common project roots
        possible_roots = [
            os.getcwd(),
            os.path.join(os.getcwd(), 'src'),
            os.path.join(os.getcwd(), 'app'),
            os.path.join(os.getcwd(), '..'),
        ]
        
        for root in possible_roots:
            full_path = os.path.join(root, file_path)
            if os.path.exists(full_path):
                return os.path.abspath(full_path)
        
        return None
    
    def _analyze_python(self, finding, file_path: str) -> VulnerabilityContext:
        """
        Analyze Python source code for REAL vulnerability context.
        """
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        try:
            # Parse Python AST
            tree = ast.parse(source_code)
        except SyntaxError as e:
            logger.warning(f"Syntax error parsing {file_path}: {e}")
            return self._create_basic_context(finding, file_path, source_code)
        
        # Find the vulnerable function
        vulnerable_function = self._find_function_at_line(tree, finding.line_number)
        
        # Extract vulnerability context
        user_inputs = self._find_user_input_sources(tree, vulnerable_function, source_code)
        dangerous_sinks = self._find_dangerous_sinks(tree, vulnerable_function, finding.vulnerability_type, source_code)
        
        # Detect frameworks and technology stack
        frameworks = self._detect_python_frameworks(source_code)
        tech_stack = self._detect_python_tech_stack(source_code)
        
        # Find database operations
        db_operations = self._find_database_operations(tree, source_code)
        
        # Find authentication context
        auth_context = self._find_authentication_context(tree, source_code)
        
        return VulnerabilityContext(
            file_path=file_path,
            function_name=vulnerable_function.name if vulnerable_function else self._extract_function_from_line(source_code, finding.line_number),
            vulnerable_line=finding.line_number,
            user_input_sources=user_inputs,
            dangerous_sinks=dangerous_sinks,
            data_flow_path=self._trace_data_flow(tree, user_inputs, dangerous_sinks),
            technology_stack=tech_stack,
            frameworks_detected=frameworks,
            database_operations=db_operations,
            authentication_context=auth_context
        )
    
    def _find_function_at_line(self, tree, line_number: int):
        """
        Find the function containing the vulnerable line.
        """
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    if node.lineno <= line_number <= (node.end_lineno or node.lineno):
                        return node
        return None
    
    def _find_user_input_sources(self, tree, function, source_code: str) -> List[str]:
        """
        Find REAL sources of user input in the vulnerable function.
        """
        user_input_patterns = [
            # Flask patterns
            r'request\.args\.get',
            r'request\.form\.get',
            r'request\.json\.get',
            r'request\.data',
            r'request\.get_json',
            # Django patterns
            r'request\.GET\.get',
            r'request\.POST\.get',
            r'request\.body',
            # FastAPI patterns
            r'Query\(',
            r'Path\(',
            r'Body\(',
            # General patterns
            r'input\(',
            r'sys\.argv',
            r'os\.environ',
            r'getenv\('
        ]
        
        sources = []
        if function:
            function_source = ast.get_source_segment(source_code, function) or ""
            for pattern in user_input_patterns:
                matches = re.findall(pattern, function_source)
                sources.extend(matches)
        
        return list(set(sources))
    
    def _find_dangerous_sinks(self, tree, function, vuln_type: str, source_code: str) -> List[str]:
        """
        Find REAL dangerous operations that could lead to vulnerabilities.
        """
        sink_patterns = {
            'sql_injection': [
                r'\.execute\(',
                r'cursor\.execute',
                r'\.query\(',
                r'\.raw\(',
                r'\.extra\(',
                r'connection\.execute'
            ],
            'xss': [
                r'render_template_string\(',
                r'Markup\(',
                r'\.write\(',
                r'response\.write',
                r'HttpResponse\(',
                r'jsonify\('
            ],
            'command_injection': [
                r'os\.system\(',
                r'subprocess\.call',
                r'subprocess\.run',
                r'subprocess\.Popen',
                r'os\.popen\(',
                r'commands\.getoutput'
            ],
            'path_traversal': [
                r'open\(',
                r'file\(',
                r'\.read_file',
                r'send_file\(',
                r'send_from_directory\(',
                r'os\.path\.join'
            ]
        }
        
        patterns = sink_patterns.get(vuln_type.lower(), [])
        sinks = []
        
        if function:
            function_source = ast.get_source_segment(source_code, function) or ""
            for pattern in patterns:
                matches = re.findall(pattern, function_source)
                sinks.extend(matches)
        
        return list(set(sinks))
    
    def _detect_python_frameworks(self, source_code: str) -> List[str]:
        """
        Detect Python frameworks from import statements and usage patterns.
        """
        frameworks = []
        
        # Framework detection patterns
        framework_patterns = {
            'flask': [r'from flask import', r'import flask', r'Flask\('],
            'django': [r'from django', r'import django', r'django\.'],
            'fastapi': [r'from fastapi import', r'import fastapi', r'FastAPI\('],
            'pyramid': [r'from pyramid', r'import pyramid'],
            'tornado': [r'from tornado', r'import tornado'],
            'bottle': [r'from bottle import', r'import bottle'],
            'cherrypy': [r'import cherrypy', r'cherrypy\.'],
            'sqlalchemy': [r'from sqlalchemy', r'import sqlalchemy'],
            'peewee': [r'from peewee', r'import peewee'],
            'mongoengine': [r'from mongoengine', r'import mongoengine']
        }
        
        for framework, patterns in framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, source_code):
                    frameworks.append(framework)
                    break
        
        return frameworks
    
    def _detect_python_tech_stack(self, source_code: str) -> List[str]:
        """
        Detect technology stack components.
        """
        tech_stack = []
        
        # Database detection
        if re.search(r'sqlite3|\.sqlite', source_code):
            tech_stack.append('sqlite')
        if re.search(r'psycopg2|postgresql', source_code):
            tech_stack.append('postgresql')
        if re.search(r'pymongo|mongodb', source_code):
            tech_stack.append('mongodb')
        if re.search(r'redis|Redis', source_code):
            tech_stack.append('redis')
        
        # Template engines
        if re.search(r'jinja2|Jinja', source_code):
            tech_stack.append('jinja2')
        if re.search(r'mako', source_code):
            tech_stack.append('mako')
        
        return tech_stack
    
    def _find_database_operations(self, tree, source_code: str) -> List[str]:
        """
        Find database operations in the code.
        """
        db_patterns = [
            r'SELECT\s+.*\s+FROM',
            r'INSERT\s+INTO',
            r'UPDATE\s+.*\s+SET',
            r'DELETE\s+FROM',
            r'\.save\(\)',
            r'\.create\(',
            r'\.filter\(',
            r'\.get\(',
            r'\.all\(\)',
        ]
        
        operations = []
        for pattern in db_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            operations.extend(matches)
        
        return operations
    
    def _find_authentication_context(self, tree, source_code: str) -> Optional[str]:
        """
        Find authentication/authorization context.
        """
        auth_patterns = [
            r'@login_required',
            r'@require_.*',
            r'current_user',
            r'session\[',
            r'\.is_authenticated',
            r'check_password',
            r'authenticate\(',
        ]
        
        for pattern in auth_patterns:
            if re.search(pattern, source_code):
                return f"Authentication context detected: {pattern}"
        
        return None
    
    def _trace_data_flow(self, tree, user_inputs: List[str], dangerous_sinks: List[str]) -> List[str]:
        """
        Trace data flow from user inputs to dangerous sinks.
        """
        # This is a simplified data flow analysis
        # In a full implementation, this would use proper taint analysis
        if user_inputs and dangerous_sinks:
            return [f"{input_source} -> {sink}" for input_source in user_inputs for sink in dangerous_sinks]
        return []
    
    def _extract_function_from_line(self, source_code: str, line_number: int) -> str:
        """
        Extract function name from source code line.
        """
        lines = source_code.split('\n')
        if 0 <= line_number - 1 < len(lines):
            line = lines[line_number - 1]
            # Simple regex to find function definition
            match = re.search(r'def\s+(\w+)', line)
            if match:
                return match.group(1)
        return 'unknown'
    
    def _create_basic_context(self, finding, file_path: str, source_code: str) -> VulnerabilityContext:
        """
        Create basic context when AST parsing fails.
        """
        return VulnerabilityContext(
            file_path=file_path,
            function_name=self._extract_function_from_line(source_code, finding.line_number),
            vulnerable_line=finding.line_number,
            user_input_sources=[],
            dangerous_sinks=[],
            data_flow_path=[],
            technology_stack=[],
            frameworks_detected=[],
            database_operations=[],
            authentication_context=None
        )
    
    # Placeholder methods for other languages (to be implemented)
    def _analyze_java(self, finding, file_path: str) -> VulnerabilityContext:
        """Java source code analysis (placeholder)."""
        return self._create_basic_context(finding, file_path, "")
    
    def _analyze_javascript(self, finding, file_path: str) -> VulnerabilityContext:
        """JavaScript source code analysis (placeholder)."""
        return self._create_basic_context(finding, file_path, "")
    
    def _analyze_typescript(self, finding, file_path: str) -> VulnerabilityContext:
        """TypeScript source code analysis (placeholder)."""
        return self._create_basic_context(finding, file_path, "")
    
    def _analyze_php(self, finding, file_path: str) -> VulnerabilityContext:
        """PHP source code analysis (placeholder)."""
        return self._create_basic_context(finding, file_path, "")
    
    def _analyze_csharp(self, finding, file_path: str) -> VulnerabilityContext:
        """C# source code analysis (placeholder)."""
        return self._create_basic_context(finding, file_path, "")
    
    def _analyze_cpp(self, finding, file_path: str) -> VulnerabilityContext:
        """C++ source code analysis (placeholder)."""
        return self._create_basic_context(finding, file_path, "")
    
    def _analyze_c(self, finding, file_path: str) -> VulnerabilityContext:
        """C source code analysis (placeholder)."""
        return self._create_basic_context(finding, file_path, "") 
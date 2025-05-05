#!/usr/bin/env python3
"""
Script to fix path references in Python files.

This script:
1. Updates any relative path references to use pathlib.Path
2. Updates any os.path references to use pathlib.Path 
3. Updates BASE_DIR references to use PROJECT_ROOT
4. Ensures Flask template and static folder references use Path objects
"""
import os
import re
import glob
from pathlib import Path

# Directories to process
DIRS_TO_PROCESS = [
    'api',
    'scripts',
    'vxdf_validate',
    'engine'
]

# Regex patterns for replacements
PATTERNS = [
    # os.path.join replacements
    (r'os\.path\.join\((.*?), (.*?)\)', r'Path(\1) / \2'),
    
    # os.path.dirname replacements
    (r'os\.path\.dirname\((.*?)\)', r'Path(\1).parent'),
    
    # os.path.basename replacements
    (r'os\.path\.basename\((.*?)\)', r'Path(\1).name'),
    
    # os.path.exists replacements
    (r'os\.path\.exists\((.*?)\)', r'Path(\1).exists()'),
    
    # os.path.isfile replacements
    (r'os\.path\.isfile\((.*?)\)', r'Path(\1).is_file()'),
    
    # os.path.isdir replacements
    (r'os\.path\.isdir\((.*?)\)', r'Path(\1).is_dir()'),
    
    # BASE_DIR replacements
    (r'BASE_DIR', r'PROJECT_ROOT'),
    
    # Flask app template_folder and static_folder paths - convert string paths to str(Path)
    (r'template_folder\s*=\s*[\'"]([^\'"]+)[\'"]', r'template_folder=str(\1)'),
    (r'static_folder\s*=\s*[\'"]([^\'"]+)[\'"]', r'static_folder=str(\1)'),
    
    # Flask app template_folder and static_folder TEMPLATE_DIR/STATIC_DIR - convert to str()
    (r'template_folder\s*=\s*(TEMPLATE_DIR|STATIC_DIR)', r'template_folder=str(\1)'),
    (r'static_folder\s*=\s*(TEMPLATE_DIR|STATIC_DIR)', r'static_folder=str(\1)'),
    
    # Missing Path imports
    (r'^(import .*?)$\n^(from .*)$', r'\1\nimport pathlib\n\2'),
]

def process_file(file_path):
    """Process a single Python file."""
    # Convert file_path to string for comparison
    file_path_str = str(file_path)
    
    # Don't process this file itself
    if 'fix_paths.py' in file_path_str:
        return
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Apply regex patterns
    for pattern, replacement in PATTERNS:
        content = re.sub(pattern, replacement, content)
    
    # If no pathlib is imported but we've added Path references, add import
    if ('Path(' in content or ' / ' in content) and 'from pathlib import Path' not in content and 'import pathlib' not in content:
        import_section_match = re.search(r'^import.*?$', content, re.MULTILINE)
        if import_section_match:
            import_section = import_section_match.group(0)
            content = content.replace(import_section, f"{import_section}\nfrom pathlib import Path")
    
    # Ensure consistent spacing (no double blank lines)
    content = re.sub(r'\n\n\n+', '\n\n', content)
    
    # Only write back if changed
    if content != original_content:
        print(f"Updating {file_path}")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

def main():
    """Main entry point."""
    # Get the project root directory
    root_dir = Path(__file__).resolve().parent.parent
    print(f"Processing files in {root_dir}...")
    
    # Process each Python file in the directories
    for dir_name in DIRS_TO_PROCESS:
        dir_path = root_dir / dir_name
        if not dir_path.exists():
            print(f"Directory {dir_path} does not exist, skipping")
            continue
        
        print(f"Processing directory {dir_path}")
        for py_file in dir_path.glob('**/*.py'):
            process_file(py_file)
    
    print("Path fixing completed successfully!")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
Script to fix imports in the VXDF project.
Replaces 'from vxdf_validate' with 'from api' in all Python files.
"""
import os
import re
import sys
from pathlib import Path

def fix_imports(file_path):
    """Fix imports in a given file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace 'from vxdf_validate' with 'from api'
    new_content = re.sub(r'from vxdf_validate', 'from api', content)
    
    # Replace 'import vxdf_validate' with 'import api'
    new_content = re.sub(r'import vxdf_validate', 'import api', new_content)
    
    # Only write if changes were made
    if new_content != content:
        print(f"Fixing imports in {file_path}")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        return 1
    return 0

def main():
    # Get the root directory (assuming this script is in scripts/)
    root_dir = Path(__file__).parent.parent
    api_dir = root_dir / 'api'
    
    # Check if api directory exists
    if not api_dir.exists() or not api_dir.is_dir():
        print(f"API directory not found at {api_dir}")
        sys.exit(1)
    
    # Find all Python files
    python_files = list(api_dir.glob('**/*.py'))
    
    # Fix imports in each file
    changed = 0
    for file_path in python_files:
        changed += fix_imports(file_path)
    
    print(f"Fixed imports in {changed} files.")

if __name__ == "__main__":
    main() 
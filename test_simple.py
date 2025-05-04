#!/usr/bin/env python3
"""
Simple test for basic imports.
"""
import sys
import os

# Add the parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to import modules from the new structure
try:
    import api
    print(f"✓ Successfully imported api module (version {api.__version__})")
    
    # Test importing some modules that don't have circular dependencies
    from api.models.database import Base
    print("✓ Successfully imported database module")
    
    from api.validators import ValidatorType
    print("✓ Successfully imported validators module")
    
    from api.parsers import ParserType
    print("✓ Successfully imported parsers module")
    
    print("\nBasic imports are working!")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1) 
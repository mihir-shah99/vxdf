#!/usr/bin/env python3
"""
Test import paths for the VXDF Validate project.
"""
import sys
import os

# Add the parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to import modules from the new structure
try:
    import api
    print(f"✓ Successfully imported api module (version {api.__version__})")
    
    # Directly import specific modules instead of potentially circular imports
    import api.server
    print("✓ Successfully imported api.server module")
    
    from api.models import Base, SessionLocal
    print("✓ Successfully imported models")
    
    from api.validators import ValidatorType
    print("✓ Successfully imported validators")
    
    from api.parsers import ParserType
    print("✓ Successfully imported parsers")
    
    print("\nAll imports successful! The new structure is working correctly.")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1) 
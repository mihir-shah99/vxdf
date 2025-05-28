#!/usr/bin/env python3
"""
Comprehensive startup script for VXDF v1.0.0 application.
Ensures the application runs correctly on all machines.
"""

import os
import sys
import time
import signal
import subprocess
import threading
import requests
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VXDFLauncher:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.backend_process = None
        self.frontend_process = None
        self.backend_port = 6789
        self.frontend_port = 3000
        
    def check_prerequisites(self):
        """Check if all prerequisites are installed."""
        logger.info("🔍 Checking prerequisites...")
        
        # Check Python version
        if sys.version_info < (3, 9):
            logger.error("❌ Python 3.9+ is required")
            return False
        logger.info(f"✅ Python {sys.version.split()[0]} found")
        
        # Check if pip is available
        try:
            subprocess.run([sys.executable, '-m', 'pip', '--version'], 
                         check=True, capture_output=True)
            logger.info("✅ pip is available")
        except subprocess.CalledProcessError:
            logger.error("❌ pip is not available")
            return False
        
        # Check if Node.js is available
        try:
            result = subprocess.run(['node', '--version'], 
                                  check=True, capture_output=True, text=True)
            node_version = result.stdout.strip()
            logger.info(f"✅ Node.js {node_version} found")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("❌ Node.js is not installed")
            return False
        
        # Check if npm is available
        try:
            result = subprocess.run(['npm', '--version'], 
                                  check=True, capture_output=True, text=True)
            npm_version = result.stdout.strip()
            logger.info(f"✅ npm {npm_version} found")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("❌ npm is not installed")
            return False
        
        return True
    
    def install_dependencies(self):
        """Install Python and Node.js dependencies."""
        logger.info("📦 Installing dependencies...")
        
        # Install Python dependencies
        try:
            logger.info("Installing Python dependencies...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                         check=True, cwd=self.project_root)
            logger.info("✅ Python dependencies installed")
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to install Python dependencies: {e}")
            return False
        
        # Install Node.js dependencies
        try:
            logger.info("Installing Node.js dependencies...")
            subprocess.run(['npm', 'install'], 
                         check=True, cwd=self.project_root / 'frontend')
            logger.info("✅ Node.js dependencies installed")
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to install Node.js dependencies: {e}")
            return False
        
        return True
    
    def check_ports(self):
        """Check if required ports are available."""
        logger.info("🔌 Checking port availability...")
        
        def is_port_in_use(port):
            try:
                response = requests.get(f"http://localhost:{port}", timeout=1)
                return True
            except:
                return False
        
        if is_port_in_use(self.backend_port):
            logger.warning(f"⚠️  Port {self.backend_port} is already in use")
            return False
        
        if is_port_in_use(self.frontend_port):
            logger.warning(f"⚠️  Port {self.frontend_port} is already in use")
            return False
        
        logger.info(f"✅ Ports {self.backend_port} and {self.frontend_port} are available")
        return True
    
    def start_backend(self):
        """Start the backend API server."""
        logger.info("🔧 Starting backend API server...")
        
        try:
            env = os.environ.copy()
            env['PORT'] = str(self.backend_port)
            env['PYTHONPATH'] = str(self.project_root)
            
            self.backend_process = subprocess.Popen(
                [sys.executable, '-m', 'api.server'],
                cwd=self.project_root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for backend to start
            for i in range(30):  # Wait up to 30 seconds
                try:
                    response = requests.get(f"http://localhost:{self.backend_port}/api/stats", timeout=1)
                    if response.status_code == 200:
                        logger.info(f"✅ Backend API server started on port {self.backend_port}")
                        return True
                except:
                    time.sleep(1)
            
            logger.error("❌ Backend API server failed to start within 30 seconds")
            return False
            
        except Exception as e:
            logger.error(f"❌ Failed to start backend: {e}")
            return False
    
    def start_frontend(self):
        """Start the frontend development server."""
        logger.info("🎨 Starting frontend development server...")
        
        try:
            self.frontend_process = subprocess.Popen(
                ['npm', 'run', 'dev'],
                cwd=self.project_root / 'frontend',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for frontend to start
            for i in range(60):  # Wait up to 60 seconds for Vite
                try:
                    response = requests.get(f"http://localhost:{self.frontend_port}", timeout=1)
                    if response.status_code == 200:
                        logger.info(f"✅ Frontend development server started on port {self.frontend_port}")
                        return True
                except:
                    time.sleep(1)
            
            logger.error("❌ Frontend development server failed to start within 60 seconds")
            return False
            
        except Exception as e:
            logger.error(f"❌ Failed to start frontend: {e}")
            return False
    
    def test_integration(self):
        """Test the integration between frontend and backend."""
        logger.info("🧪 Testing integration...")
        
        try:
            # Test backend API
            response = requests.get(f"http://localhost:{self.backend_port}/api/stats", timeout=5)
            if response.status_code != 200:
                logger.error("❌ Backend API test failed")
                return False
            
            # Test frontend
            response = requests.get(f"http://localhost:{self.frontend_port}", timeout=5)
            if response.status_code != 200:
                logger.error("❌ Frontend test failed")
                return False
            
            # Test VXDF models
            sys.path.insert(0, str(self.project_root))
            from api.core.engine import ValidationEngine
            engine = ValidationEngine()
            vxdf_doc = engine.generate_vxdf([], target_name="Test Application")
            
            if vxdf_doc.vxdfVersion != "1.0.0":
                logger.error("❌ VXDF model test failed")
                return False
            
            logger.info("✅ All integration tests passed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Integration test failed: {e}")
            return False
    
    def cleanup(self):
        """Clean up processes."""
        logger.info("🧹 Cleaning up...")
        
        if self.backend_process:
            self.backend_process.terminate()
            self.backend_process.wait()
            logger.info("✅ Backend process terminated")
        
        if self.frontend_process:
            self.frontend_process.terminate()
            self.frontend_process.wait()
            logger.info("✅ Frontend process terminated")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info("🛑 Received shutdown signal")
        self.cleanup()
        sys.exit(0)
    
    def run(self):
        """Main run method."""
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        logger.info("🚀 Starting VXDF v1.0.0 Application")
        logger.info("=" * 50)
        
        try:
            # Check prerequisites
            if not self.check_prerequisites():
                logger.error("❌ Prerequisites check failed")
                return 1
            
            # Install dependencies
            if not self.install_dependencies():
                logger.error("❌ Dependency installation failed")
                return 1
            
            # Check ports
            if not self.check_ports():
                logger.error("❌ Port check failed")
                return 1
            
            # Start backend
            if not self.start_backend():
                logger.error("❌ Backend startup failed")
                return 1
            
            # Start frontend
            if not self.start_frontend():
                logger.error("❌ Frontend startup failed")
                self.cleanup()
                return 1
            
            # Test integration
            if not self.test_integration():
                logger.error("❌ Integration test failed")
                self.cleanup()
                return 1
            
            # Success message
            logger.info("=" * 50)
            logger.info("🎉 VXDF v1.0.0 Application Started Successfully!")
            logger.info(f"📊 Backend API: http://localhost:{self.backend_port}")
            logger.info(f"🎨 Frontend UI: http://localhost:{self.frontend_port}")
            logger.info("=" * 50)
            logger.info("Press Ctrl+C to stop the application")
            
            # Keep the application running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            
        except Exception as e:
            logger.error(f"❌ Unexpected error: {e}")
            return 1
        finally:
            self.cleanup()
        
        return 0

def main():
    """Main entry point."""
    launcher = VXDFLauncher()
    return launcher.run()

if __name__ == "__main__":
    sys.exit(main()) 
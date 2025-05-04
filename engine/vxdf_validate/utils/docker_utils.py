"""
Utilities for working with Docker containers for isolated validation.
"""
import os
import logging
import tempfile
import subprocess
import time
import uuid
import shutil
from typing import Dict, Any, Optional, Tuple

from vxdf_validate.config import DOCKER_BASE_IMAGE, DOCKER_NETWORK

logger = logging.getLogger(__name__)

class DockerEnvironment:
    """
    Manages Docker containers for isolated validation environments.
    """
    
    def __init__(self, base_image: str = DOCKER_BASE_IMAGE, network: str = DOCKER_NETWORK):
        """
        Initialize the Docker environment.
        
        Args:
            base_image: Base Docker image to use
            network: Docker network to use
        """
        self.base_image = base_image
        self.network = network
        self.container_id = None
        self.temp_dir = None
    
    def setup(self) -> bool:
        """
        Set up the Docker environment.
        
        Returns:
            True if setup was successful, False otherwise
        """
        try:
            # Check if Docker is available
            result = subprocess.run(['docker', '--version'], 
                                    capture_output=True, text=True, check=False)
            
            if result.returncode != 0:
                logger.error("Docker is not available on this system")
                return False
            
            # Create network if it doesn't exist
            network_exists = False
            result = subprocess.run(['docker', 'network', 'ls', '--format', '{{.Name}}'], 
                                    capture_output=True, text=True, check=True)
            
            if self.network in result.stdout.splitlines():
                network_exists = True
            
            if not network_exists:
                logger.info(f"Creating Docker network: {self.network}")
                subprocess.run(['docker', 'network', 'create', self.network], 
                              check=True)
            
            # Pull base image if needed
            logger.info(f"Pulling Docker image: {self.base_image}")
            subprocess.run(['docker', 'pull', self.base_image], 
                          check=True)
            
            return True
        
        except Exception as e:
            logger.error(f"Error setting up Docker environment: {e}", exc_info=True)
            return False
    
    def create_container(self, name_prefix: str = "vxdf_validate_", 
                         ports: Dict[int, int] = None,
                         env_vars: Dict[str, str] = None,
                         command: str = "tail -f /dev/null") -> Optional[str]:
        """
        Create a new Docker container.
        
        Args:
            name_prefix: Prefix for the container name
            ports: Dictionary of port mappings (host_port: container_port)
            env_vars: Dictionary of environment variables
            command: Command to run in the container
            
        Returns:
            Container ID if successful, None otherwise
        """
        try:
            # Create a unique container name
            container_name = f"{name_prefix}{uuid.uuid4().hex[:8]}"
            
            # Create temporary directory for file sharing
            self.temp_dir = tempfile.mkdtemp(prefix="vxdf_validate_")
            
            # Build docker run command
            cmd = ['docker', 'run', '-d', '--name', container_name]
            
            # Add network
            cmd.extend(['--network', self.network])
            
            # Add port mappings
            if ports:
                for host_port, container_port in ports.items():
                    cmd.extend(['-p', f"{host_port}:{container_port}"])
            
            # Add environment variables
            if env_vars:
                for name, value in env_vars.items():
                    cmd.extend(['-e', f"{name}={value}"])
            
            # Add volume mapping for temp directory
            cmd.extend(['-v', f"{self.temp_dir}:/tmp/shared"])
            
            # Add image and command
            cmd.extend([self.base_image, '/bin/sh', '-c', command])
            
            # Run the container
            logger.debug(f"Running Docker command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            self.container_id = result.stdout.strip()
            logger.info(f"Created Docker container: {self.container_id} ({container_name})")
            
            return self.container_id
        
        except Exception as e:
            logger.error(f"Error creating Docker container: {e}", exc_info=True)
            self.cleanup()
            return None
    
    def execute_command(self, command: str, timeout: Optional[int] = 60) -> Tuple[int, str, str]:
        """
        Execute a command in the Docker container.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if not self.container_id:
            logger.error("No container available to execute command")
            return (-1, "", "No container available")
        
        try:
            # Execute the command in the container
            cmd = ['docker', 'exec', self.container_id, '/bin/sh', '-c', command]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                    check=False, timeout=timeout)
            
            return (result.returncode, result.stdout, result.stderr)
        
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out after {timeout} seconds: {command}")
            return (-1, "", f"Command timed out after {timeout} seconds")
        
        except Exception as e:
            logger.error(f"Error executing command in container: {e}", exc_info=True)
            return (-1, "", str(e))
    
    def copy_to_container(self, src_path: str, dest_path: str) -> bool:
        """
        Copy a file to the Docker container.
        
        Args:
            src_path: Source path on the host
            dest_path: Destination path in the container
            
        Returns:
            True if successful, False otherwise
        """
        if not self.container_id:
            logger.error("No container available to copy files to")
            return False
        
        try:
            # First copy to the shared temp directory
            shared_filename = os.path.basename(src_path)
            shared_path = os.path.join(self.temp_dir, shared_filename)
            shutil.copy2(src_path, shared_path)
            
            # Then move from the shared directory to the destination in the container
            cmd = f"cp /tmp/shared/{shared_filename} {dest_path}"
            exit_code, stdout, stderr = self.execute_command(cmd)
            
            if exit_code != 0:
                logger.error(f"Error copying file to container: {stderr}")
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error copying file to container: {e}", exc_info=True)
            return False
    
    def copy_from_container(self, src_path: str, dest_path: str) -> bool:
        """
        Copy a file from the Docker container.
        
        Args:
            src_path: Source path in the container
            dest_path: Destination path on the host
            
        Returns:
            True if successful, False otherwise
        """
        if not self.container_id:
            logger.error("No container available to copy files from")
            return False
        
        try:
            # First copy to the shared directory in the container
            shared_filename = os.path.basename(src_path)
            cmd = f"cp {src_path} /tmp/shared/{shared_filename}"
            exit_code, stdout, stderr = self.execute_command(cmd)
            
            if exit_code != 0:
                logger.error(f"Error copying file in container: {stderr}")
                return False
            
            # Then copy from the shared directory to the destination
            shared_path = os.path.join(self.temp_dir, shared_filename)
            try:
                shutil.copy2(shared_path, dest_path)
                return True
            except Exception as e:
                logger.error(f"Error copying file from shared directory: {e}")
                return False
        
        except Exception as e:
            logger.error(f"Error copying file from container: {e}", exc_info=True)
            return False
    
    def install_package(self, package_name: str) -> bool:
        """
        Install a package in the Docker container.
        
        Args:
            package_name: Name of the package to install
            
        Returns:
            True if successful, False otherwise
        """
        if not self.container_id:
            logger.error("No container available to install packages")
            return False
        
        try:
            # Update package list
            cmd = "apt-get update -y"
            exit_code, stdout, stderr = self.execute_command(cmd, timeout=120)
            
            if exit_code != 0:
                logger.error(f"Error updating package list: {stderr}")
                return False
            
            # Install package
            cmd = f"apt-get install -y --no-install-recommends {package_name}"
            exit_code, stdout, stderr = self.execute_command(cmd, timeout=180)
            
            if exit_code != 0:
                logger.error(f"Error installing package {package_name}: {stderr}")
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error installing package {package_name}: {e}", exc_info=True)
            return False
    
    def install_python_package(self, package_name: str) -> bool:
        """
        Install a Python package in the Docker container.
        
        Args:
            package_name: Name of the package to install
            
        Returns:
            True if successful, False otherwise
        """
        if not self.container_id:
            logger.error("No container available to install Python packages")
            return False
        
        try:
            # Install with pip
            cmd = f"pip install --no-cache-dir {package_name}"
            exit_code, stdout, stderr = self.execute_command(cmd, timeout=120)
            
            if exit_code != 0:
                logger.error(f"Error installing Python package {package_name}: {stderr}")
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error installing Python package {package_name}: {e}", exc_info=True)
            return False
    
    def cleanup(self) -> None:
        """
        Clean up the Docker environment, stopping and removing containers.
        """
        try:
            if self.container_id:
                # Stop the container
                logger.info(f"Stopping Docker container: {self.container_id}")
                subprocess.run(['docker', 'stop', self.container_id], 
                              check=False, capture_output=True)
                
                # Remove the container
                logger.info(f"Removing Docker container: {self.container_id}")
                subprocess.run(['docker', 'rm', '-f', self.container_id], 
                              check=False, capture_output=True)
                
                self.container_id = None
            
            # Clean up temp directory
            if self.temp_dir and os.path.exists(self.temp_dir):
                logger.info(f"Removing temporary directory: {self.temp_dir}")
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                self.temp_dir = None
        
        except Exception as e:
            logger.error(f"Error cleaning up Docker environment: {e}", exc_info=True)
    
    def __enter__(self):
        """
        Enter context manager.
        
        Returns:
            The DockerEnvironment instance
        """
        if not self.setup():
            raise RuntimeError("Failed to set up Docker environment")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit context manager, cleaning up resources.
        
        Args:
            exc_type: Exception type if an exception was raised
            exc_val: Exception value if an exception was raised
            exc_tb: Exception traceback if an exception was raised
        """
        self.cleanup()

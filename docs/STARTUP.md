# VXDF Application Startup Guide

This guide provides instructions on how to start the VXDF (Validated eXploitable Data Flow) application and verify that all components are running correctly.

## Prerequisites

Before starting the application, ensure you have completed the installation steps described in the [Installation Guide](../INSTALLATION.md), including:

- Python 3.9+ installed
- Node.js 16+ installed
- All dependencies installed 

## Using the Startup Script

VXDF includes a comprehensive startup script that launches both the backend API and frontend development server, with automatic path fixing and environment setup.

### Standard Startup (Recommended)

To start the application:

```bash
# Navigate to the project root directory
cd vxdf

# Run the startup script
./scripts/startup.sh
```

Or you can run it directly from the scripts directory:

```bash
cd vxdf/scripts
./startup.sh
```

You can also customize the ports used by the API and frontend:

```bash
# Run API on port 8000 and frontend on port 3000
./scripts/startup.sh 8000 3000
```

The startup script performs the following steps:

1. Sets up the PYTHONPATH to include the project root
2. Runs the `fix_paths.py` script to ensure consistent path handling
3. Runs the `fix_templates.py` script to create necessary symlinks and template files
4. Creates required directories if they don't exist
5. Checks for port conflicts
6. Starts the API server
7. Starts the frontend development server

Once started, you'll see a success message with URLs for the API and frontend. The application will be accessible at:

- **Frontend:** http://localhost:5173 (or your custom port)
- **API:** http://localhost:5001 (or your custom port)

To stop the application, press `Ctrl+C` in the terminal where the startup script is running.

### Alternative Startup Methods

If you prefer to run components separately:

#### Start Only the API Server

```bash
cd api
python3 main.py
```

The API will be available at http://localhost:5001 by default.

#### Start Only the Frontend

```bash
cd frontend
npm run dev
```

The frontend will be available at http://localhost:5173 by default.

## Verifying the Application

After starting the application, you can verify it's working correctly by:

1. Opening the frontend URL in your browser - you should see the VXDF frontend dashboard
2. Testing the API directly:
   ```bash
   curl http://localhost:5001/api/stats
   ```

## Troubleshooting

### Path and File Reference Issues

If you encounter path-related errors:

1. Run the path fixing scripts manually:
   ```bash
   python3 scripts/fix_paths.py
   python3 scripts/fix_templates.py
   ```

2. Verify that the symlinks exist in the project root:
   ```bash
   ls -la | grep -E 'templates|static'
   ```

3. If symlinks are missing, create them:
   ```bash
   ln -s engine/templates templates
   ln -s engine/static static
   ```

### Port Conflicts

If you see an error about ports already in use:

1. Specify different ports when running the startup script:
   ```bash
   ./scripts/startup.sh 5002 5174
   ```

2. Or find and stop the processes using the default ports:
   ```bash
   # Find process using port 5001 (API)
   lsof -i :5001
   
   # Find process using port 5173 (Frontend)
   lsof -i :5173
   
   # Kill a process by PID
   kill <PID>
   
   # Force kill if necessary
   kill -9 <PID>
   ```

### Database Issues

If database errors occur:

1. Check if the database file exists at `./vxdf_validate.db`
2. If issues persist, remove and recreate the database file:
   ```bash
   rm vxdf_validate.db
   touch vxdf_validate.db
   ```

### Module Import Errors

If you see errors like `ModuleNotFoundError: No module named 'api.server'`:

1. Make sure the PYTHONPATH includes the project root:
   ```bash
   export PYTHONPATH=/path/to/vxdf:$PYTHONPATH
   ```

2. Verify import statements are compatible with both relative and absolute imports

### Template Errors

If you see errors related to templates or static files:

1. Run the fix_templates.py script:
   ```bash
   python3 scripts/fix_templates.py
   ```

2. This will create the necessary templates and static files for the Flask application

## Additional Resources

- [API Documentation](API.md) - Details on available API endpoints
- [README.md](../README.md) - Project overview and features 
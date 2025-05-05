# VXDF Application Startup Guide

This guide provides instructions on how to start the VXDF (Validated eXploitable Data Flow) application and verify that all components are running correctly.

## Prerequisites

Before starting the application, ensure you have completed the installation steps described in the [Installation Guide](../INSTALLATION.md), including:

- Python 3.9+ installed
- Node.js 18+ installed
- All dependencies installed via `./scripts/setup.sh`

## Using the Startup Script

VXDF includes a comprehensive startup script that launches both the backend API and frontend development server, while performing basic tests to ensure everything is working properly.

### Standard Startup (Recommended)

To start the application with automatic testing:

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

The startup script will:

1. Check for port conflicts (5001 for API, 5173 for frontend)
2. Ensure the database file exists
3. Start the API server
4. Test critical API endpoints
5. Verify database connectivity
6. Start the frontend development server
7. Confirm the frontend is responding

Once all tests pass, you'll see a success message with URLs for the API and frontend. The application will be accessible at:

- **Frontend:** http://localhost:5173
- **API:** http://localhost:5001

To stop the application, press `Ctrl+C` in the terminal where the startup script is running.

### Alternative Startup Methods

If you need more control over the startup process, you can use these alternative methods:

#### Start All Components (Without Testing)

```bash
./scripts/start.sh
```

This starts both the API and frontend servers without performing tests.

#### Start Only the API

```bash
cd api
python3 main.py
```

The API will be available at http://localhost:5001.

#### Start Only the Frontend

```bash
cd frontend
npm run dev
```

The frontend will be available at http://localhost:5173.

## Verifying the Application

After starting the application, you can verify it's working correctly by:

1. Opening http://localhost:5173 in your browser - you should see the VXDF frontend dashboard
2. Testing the API directly:
   ```bash
   curl http://localhost:5001/api/stats
   ```

## Troubleshooting

If you encounter issues starting the application:

### Path and File Reference Issues

The application has been refactored to use consistent path handling. If you see errors related to paths or file not found:

1. The startup script automatically runs a path fixing script to ensure consistent path references
2. Make sure symlinks are properly set up (the script should handle this automatically)
3. If issues persist, you can manually run the path fixing script:
   ```bash
   python3 scripts/fix_paths.py
   ```

### Template Files Not Found

If you see an error like "jinja2.exceptions.TemplateNotFound: index.html" when accessing the web interface:

1. The application is looking for template and static files in the project root
2. Create symlinks to the engine templates and static directories:
   ```bash
   cd /path/to/vxdf
   ln -s engine/templates templates
   ln -s engine/static static
   ```
3. Restart the application

### Port Conflicts

If you see an error about ports already in use, find and stop the processes using those ports:

```bash
# Find process using port 5001 (API)
lsof -i :5001

# Find process using port 5173 (Frontend)
lsof -i :5173

# Kill a process by PID
kill <PID>
```

### Database Issues

If database connection fails:
1. Check if the database file exists at `./vxdf_validate.db`
2. If not, create an empty file: `touch vxdf_validate.db`

### Backend Crashes

If the API server crashes, check the logs in the `logs/` directory for error details.

### Frontend Build Issues

If the frontend fails to start:
1. Navigate to the frontend directory: `cd frontend`
2. Remove node_modules: `rm -rf node_modules`
3. Reinstall dependencies: `npm install`
4. Try starting again: `npm run dev`

## Additional Resources

- [API Documentation](API.md) - Details on available API endpoints
- [INSTALLATION.md](../INSTALLATION.md) - Complete installation instructions
- [README.md](../README.md) - Project overview and features 
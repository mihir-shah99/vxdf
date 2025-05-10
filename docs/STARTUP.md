# VXDF Application Startup Guide

This guide provides instructions on how to start the VXDF (Validated eXploitable Data Flow) application and verify that all components are running correctly.

## Prerequisites

Before starting the application, ensure you have completed the installation steps described in the project README, including:

- Python 3.9+ installed
- Node.js 16+ installed
- All dependencies installed 

## Starting the Application

### Start the Backend (API)

```bash
cd vxdf
python3 -m api.server --port 5001
```

The API will be available at http://localhost:5001 by default.

### Start the Frontend (SPA)

Open a new terminal and run:

```bash
cd vxdf/frontend
npm run dev
```

The frontend will be available at http://localhost:3000 by default.

## Verifying the Application

After starting the application, you can verify it's working correctly by:

1. Opening the frontend URL in your browser - you should see the VXDF frontend dashboard
2. Testing the API directly:
   ```bash
   curl http://localhost:5001/api/stats
   ```
3. Viewing the API documentation at [http://localhost:5001/apidocs](http://localhost:5001/apidocs)

## Troubleshooting

### Port Conflicts

If you see an error about ports already in use:

1. Find and stop the processes using the default ports:
   ```bash
   # Find process using port 5001 (API)
   lsof -i :5001
   
   # Find process using port 3000 (Frontend)
   lsof -i :3000
   
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

## Additional Resources

- [API Documentation](API.md) - Details on available API endpoints
- [README.md](../README.md) - Project overview and features 
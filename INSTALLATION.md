# Installation Guide

This guide provides step-by-step instructions for setting up the VXDF Validate application.

## Prerequisites

- Python 3.9 or newer
- Node.js 18 or newer
- npm 9 or newer
- Git

## Quick Installation

For a quick start, use our setup script:

```bash
# Clone the repository
git clone https://github.com/yourusername/vxdf.git
cd vxdf

# Run the setup script
./scripts/setup.sh

# Start the application
./scripts/start.sh
```

## Manual Installation

If you prefer to install manually, follow these steps:

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/vxdf.git
cd vxdf
```

### 2. Backend Setup

```bash
# Install the Python package in development mode
pip install -e .

# Test the installation
python -c "import api; print(api.__version__)"
```

### 3. Frontend Setup

```bash
# Navigate to the frontend directory
cd frontend

# Install dependencies
npm install
```

### 4. Running the Application

```bash
# In one terminal, start the API server
cd api
python main.py

# In another terminal, start the frontend
cd frontend
npm run dev
```

The application will be available at:
- Frontend: http://localhost:5173
- API: http://localhost:5001

## Configuration

### Backend Configuration

The backend configuration is stored in `api/config.py`. You can modify the following settings:

- `DATABASE_URI`: Database connection string
- `SECRET_KEY`: Secret key for security
- `DEBUG`: Enable/disable debug mode
- `PORT`: API server port

### Frontend Configuration

The frontend configuration is stored in environment variables. Create a `.env` file in the frontend directory:

```
VITE_API_URL=http://localhost:5001
```

## Troubleshooting

### Port Already in Use

If you see an error like "Address already in use" or "Port 5001 is in use by another program":

```bash
# Find the process using the port
lsof -i :5001

# Kill the process
kill -9 <PID>
```

### Backend Dependency Issues

If you encounter dependency issues with the backend:

```bash
# Update pip
pip install --upgrade pip

# Install dependencies explicitly
pip install flask flask-cors flask-sqlalchemy pydantic
```

### Frontend Dependency Issues

If you encounter dependency issues with the frontend:

```bash
# Clear npm cache
npm cache clean --force

# Reinstall dependencies
rm -rf node_modules
npm install
```

## Next Steps

After installation, you may want to:

1. Check out the [API documentation](docs/API.md)
2. Upload a test scan file to validate
3. Explore the dashboard 
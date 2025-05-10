# VXDF Frontend

This directory contains the React/TypeScript frontend for VXDF Validate.

## Quickstart

```bash
npm install
npm run dev
```

- The frontend runs on [http://localhost:3000](http://localhost:3000) by default.
- API requests to `/api/*` are proxied to the backend at `http://localhost:5001`.

## Troubleshooting
- If you see proxy errors, make sure the backend is running on port 5001.
- If you see port conflicts, kill any processes using ports 3000 or 5001:
  ```bash
  lsof -ti:5001,3000 | xargs kill -9
  ```

## Makefile
- `make dev` — Start backend and frontend together
- `make check` — Run health checks on API endpoints

## Environment
- See `.env.example` for environment variables.

## Architecture Overview

The frontend is built using a component-based architecture that prioritizes modularity, reusability, and type safety. It's designed to provide a seamless user experience while efficiently communicating with the VXDF API backend.

```
┌──────────────────────────────────────────────┐
│                  Components                   │
│                                              │
│ ┌─────────┐ ┌──────────┐ ┌────────────────┐ │
│ │ Header  │ │ Sidebar  │ │ Dashboard      │ │
│ └─────────┘ └──────────┘ └────────────────┘ │
│                                              │
│ ┌─────────────────┐ ┌─────────────────────┐ │
│ │ FileUpload      │ │ VulnerabilityDetail │ │
│ └─────────────────┘ └─────────────────────┘ │
└──────────────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────┐
│                  Services                     │
│                                              │
│ ┌─────────────────┐ ┌─────────────────────┐ │
│ │ API Clients     │ │ Report Generator    │ │
│ └─────────────────┘ └─────────────────────┘ │
└──────────────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────┐
│                  Utilities                    │
│                                              │
│ ┌─────────────────┐ ┌─────────────────────┐ │
│ │ Parsers         │ │ Validators          │ │
│ └─────────────────┘ └─────────────────────┘ │
└──────────────────────────────────────────────┘
```

## Core Components

### 1. Entry Points

- **`main.tsx`**: Application entry point that bootstraps the React application and mounts it to the DOM.
- **`App.tsx`**: Main component that handles application state and routing between different views.

### 2. UI Components

- **`Dashboard.tsx`**: Displays summary statistics and a list of validated vulnerabilities.
- **`FileUpload.tsx`**: Handles file selection, upload, and validation initiation.
- **`VulnerabilityDetail.tsx`**: Shows detailed information about a specific vulnerability, including its data flow and evidence.
- **`Header.tsx`**: Application header with navigation and user information.
- **`Sidebar.tsx`**: Navigation sidebar for switching between different views.

### 3. API Integration (`src/api/`)

- **`validateVulnerability.ts`**: Client for the vulnerability validation API, which sends findings to the backend for analysis.

### 4. Types (`src/types/`)

- **`core.ts`**: Core type definitions including interfaces for vulnerabilities, validation results, and VXDF structure.

### 5. Parsers (`src/parsers/`)

- **`SARIFParser.ts`**: Parser for Static Analysis Results Interchange Format (SARIF) files.

### 6. Services (`src/services/`)

- **`ReportGenerator.ts`**: Service for generating detailed reports from validation results.

### 7. Utilities (`src/utils/`)

Various utility functions for data transformation, formatting, and other common operations.

## Component Architecture

The frontend follows a hierarchical component structure:

1. **App (Root Component)**
   - Maintains global application state
   - Handles routing between different views
   - Manages authentication state (when applicable)

2. **View Components**
   - Dashboard: Displays summary statistics and lists
   - Upload: Handles file uploads and scan initiation
   - Detailed views for specific vulnerabilities

3. **Reusable Components**
   - UI elements like buttons, cards, dialogs
   - Data display components like tables and charts
   - Form elements for user input

## State Management

The application uses React's built-in state management through:
- Component-level state with `useState` for local UI state
- Context API for sharing state between components (when needed)
- Props for passing data down the component tree

## Data Flow

1. **Input Processing**:
   - Users upload security scan files through the FileUpload component.
   - The appropriate parser (e.g., SARIFParser) processes the file and extracts vulnerabilities.
   - Extracted vulnerabilities are sent to the backend API for validation.

2. **Validation Display**:
   - The Dashboard component shows validation progress and results.
   - Statistical summaries are displayed in cards at the top.
   - A table lists individual vulnerabilities with key information.

3. **Detailed Analysis**:
   - The VulnerabilityDetail component shows comprehensive information about each vulnerability.
   - Data flow visualization shows the path from source to sink.
   - Evidence collected during validation is displayed.
   - Remediation guidance is provided for confirmed vulnerabilities.

## Type System

The application uses TypeScript for type safety with key interfaces:

- **Vulnerability**: Represents a security finding with source, sink, and metadata.
- **Evidence**: Proof of exploitability collected during validation.
- **VXDFReport & VXDFFlow**: Structures matching the VXDF output format.
- **ValidationStatus**: Enum representing the status of validation (Exploitable, Not Exploitable, etc.).

## Styling

The frontend uses Tailwind CSS for styling:
- Utility-first approach for rapid UI development
- Consistent design system with customizable theme
- Responsive design that works across devices
- Dark/light mode support

## Build System

The application uses Vite as its build tool:
- Fast development server with Hot Module Replacement (HMR)
- Optimized production builds
- TypeScript and React integration
- CSS post-processing with PostCSS

## Configuration Files

- **`package.json`**: Dependencies and scripts
- **`tsconfig.json`**: TypeScript configuration
- **`vite.config.ts`**: Vite build configuration
- **`tailwind.config.js`**: Tailwind CSS customization
- **`eslint.config.js`**: ESLint configuration for code quality

## Key Dependencies

- **React**: UI library for building component-based interfaces
- **TypeScript**: Type-safe JavaScript
- **Tailwind CSS**: Utility-first CSS framework
- **Lucide React**: Icon library
- **Vite**: Build tool and development server

## Integration with VXDF API

The frontend communicates with the VXDF API backend through RESTful APIs:

1. **File Upload**: Security scan results are uploaded to the API.
2. **Validation Requests**: Specific vulnerabilities are sent for validation.
3. **Status Polling**: The frontend checks validation progress.
4. **Results Retrieval**: Validated findings are fetched and displayed.

## User Interface Features

1. **Dashboard**:
   - Summary cards showing validation statistics
   - Table of vulnerabilities with filtering and sorting
   - Status indicators for each vulnerability

2. **File Upload**:
   - Drag-and-drop interface
   - File format validation
   - Upload progress indication
   - Parser selection based on file type

3. **Vulnerability Details**:
   - Source and sink code display
   - Data flow visualization
   - Evidence presentation with formatting
   - Remediation recommendations

## Browser Compatibility

The application is designed to work on modern browsers:
- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)

## Future Extensibility

The frontend is designed for easy extension:
1. **Additional Parsers**: New parser implementations can be added for other security tool formats.
2. **Enhanced Visualizations**: The component architecture allows for adding more sophisticated visualizations.
3. **Authentication & Authorization**: Infrastructure is in place to add user management when needed.
4. **Offline Support**: The application can be extended with service workers for offline capabilities. 
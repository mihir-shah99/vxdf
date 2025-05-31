# VXDF Frontend

This directory contains the React/TypeScript frontend for the VXDF (Validated eXploitable Data Flow) system, featuring a modern UI with comprehensive **evidence viewing and management capabilities**.

## 🚀 Enhanced Features

### **Evidence Management Interface**
- ✅ **Evidence Viewer** - Comprehensive inspection of 30+ evidence types
- ✅ **File Upload Interface** - Support for scanner reports and individual evidence files
- ✅ **Real-time Evidence Display** - Dynamic loading of evidence data with structured formatting
- ✅ **Evidence Type Filtering** - Filter findings by evidence type and validation status
- ✅ **Visual Evidence Support** - Built-in screenshot and visual proof viewers

### **Modern UI/UX**
- ✅ **React 18** with TypeScript for type safety
- ✅ **Vite** for fast development and optimized builds
- ✅ **Responsive Design** - Mobile-friendly interface
- ✅ **Real-time Updates** - Dynamic dashboard with live statistics
- ✅ **Intuitive Navigation** - Streamlined evidence workflow

## 📁 Directory Structure

```
frontend/
├── public/                  # Static assets
│   ├── index.html          # Main HTML template
│   └── favicon.ico         # Application icon
├── src/                    # Source code
│   ├── components/         # React components
│   │   ├── Dashboard/      # Dashboard components with evidence metrics
│   │   ├── EvidenceViewer/ # NEW: Evidence viewing components
│   │   ├── FileUpload/     # Enhanced file upload with evidence support
│   │   ├── FindingsTable/  # Findings table with evidence counts
│   │   └── common/         # Shared UI components
│   ├── config/            # Configuration files
│   │   └── sidebarConfig.ts # Sidebar navigation configuration
│   ├── hooks/             # Custom React hooks
│   │   ├── useApi.ts      # Enhanced API hooks for evidence
│   │   └── useEvidence.ts # NEW: Evidence-specific hooks
│   ├── pages/             # Page components
│   │   ├── Dashboard.tsx  # Main dashboard with evidence stats
│   │   ├── Upload.tsx     # Enhanced upload page
│   │   └── Evidence.tsx   # NEW: Evidence management page
│   ├── services/          # API service layer
│   │   ├── api.ts         # Enhanced API client with evidence endpoints
│   │   └── evidence.ts    # NEW: Evidence-specific API services
│   ├── types/             # TypeScript type definitions
│   │   ├── vxdf.ts        # VXDF type definitions
│   │   └── evidence.ts    # NEW: Evidence type definitions
│   ├── utils/             # Utility functions
│   │   ├── formatters.ts  # Data formatting utilities
│   │   └── evidenceHelpers.ts # NEW: Evidence processing utilities
│   ├── assets/            # Images and other assets
│   ├── App.tsx            # Main application component
│   └── main.tsx           # Application entry point
├── package.json           # NPM dependencies and scripts
├── tsconfig.json          # TypeScript configuration
├── vite.config.ts         # Vite configuration with API proxy
└── README.md              # This file
```

## 🔌 API Integration

### **Enhanced API Proxy Configuration**

The frontend is configured to proxy API requests to the backend running on port 5001:

```typescript
// vite.config.ts
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5001',
        changeOrigin: true,
        secure: false
      }
    }
  }
})
```

### **Evidence-Specific Endpoints**

The frontend integrates with enhanced API endpoints:

- `POST /api/upload` - Enhanced with external evidence JSON support
- `POST /api/findings/{finding_id}/attach_evidence_file` - Individual evidence upload
- `GET /api/findings` - List findings with evidence counts
- `GET /api/findings/{finding_id}/evidence` - Retrieve finding evidence
- `GET /api/supported-types` - Get supported evidence types

## 🧩 Key Components

### **Enhanced Dashboard (`src/pages/Dashboard.tsx`)**
Real-time dashboard featuring:

- **Evidence Metrics**: Total evidence items, types distribution
- **Finding Statistics**: Findings with evidence vs. without evidence
- **Validation Status**: Evidence validation success rates
- **Interactive Charts**: Evidence type distribution and trends

### **Evidence Viewer (`src/components/EvidenceViewer/`)**
Comprehensive evidence viewing system:

- **Type-Specific Renderers**: Custom views for each of 30+ evidence types
- **Structured Data Display**: JSON/XML formatted evidence data
- **Visual Evidence Support**: Screenshot and file viewers
- **Evidence Timeline**: Chronological evidence ordering

### **Enhanced File Upload (`src/components/FileUpload/`)**
Advanced upload interface supporting:

- **Scanner Report Upload**: SARIF, DAST, CycloneDX with evidence JSON
- **Individual Evidence Upload**: Direct evidence file attachment
- **Evidence Type Selection**: Dropdown with all supported types
- **Progress Tracking**: Real-time upload progress and validation

### **Findings Table (`src/components/FindingsTable/`)**
Enhanced findings display:

- **Evidence Count Columns**: Visual indicators of evidence quantity
- **Evidence Type Badges**: Quick evidence type identification
- **Validation Status Icons**: Evidence validation state display
- **Interactive Filtering**: Filter by evidence presence and type

## 🎨 UI/UX Features

### **Responsive Design**
- Mobile-first approach with breakpoints for tablet and desktop
- Adaptive layouts for evidence viewing on different screen sizes
- Touch-friendly interface for mobile evidence inspection

### **Evidence-Specific UI Elements**
- **Code Syntax Highlighting** for code snippet evidence
- **HTTP Request/Response Viewers** with formatted headers and payloads
- **Screenshot Galleries** with zoom and navigation
- **Log Entry Formatters** with timestamp and severity highlighting

### **Accessibility**
- WCAG 2.1 AA compliance for evidence viewers
- Keyboard navigation for all evidence interfaces
- Screen reader support for evidence descriptions
- High contrast mode for visual evidence inspection

## 🚀 Development Setup

### **Prerequisites**
- Node.js 16+ and npm
- Backend API running on http://localhost:5001

### **Installation**
```bash
cd frontend
npm install
```

### **Development Server**
```bash
npm run dev
```

The frontend will be available at http://localhost:3000 with:
- Hot module replacement for instant updates
- API proxy to backend automatically configured
- Source maps for debugging

### **Production Build**
```bash
npm run build
npm run preview
```

## 📊 Performance Optimizations

### **Frontend Optimizations**
- **Code Splitting**: Lazy loading of evidence viewer components
- **Memoization**: React.memo for expensive evidence rendering
- **Virtual Scrolling**: Efficient handling of large evidence lists
- **Image Optimization**: Automatic compression for screenshot evidence

### **API Efficiency**
- **Request Batching**: Combined evidence and finding requests
- **Caching**: Local storage for evidence type definitions
- **Pagination**: Efficient loading of large evidence datasets
- **Compression**: Gzip compression for evidence data transfer

## 🧪 Testing Integration

### **Component Testing**
```bash
# Run frontend tests
npm test

# Test evidence viewer components
npm test -- --grep "EvidenceViewer"

# Test upload functionality
npm test -- --grep "FileUpload"
```

### **End-to-End Testing**
The frontend supports comprehensive E2E testing scenarios:
- Evidence upload and viewing workflows
- Finding navigation with evidence inspection
- Evidence type filtering and search
- Visual regression testing for evidence displays

## 🔧 Configuration

### **Environment Variables**

Create `.env.local` for local development:

```env
VITE_API_BASE_URL=http://localhost:5001
VITE_EVIDENCE_MAX_FILE_SIZE=52428800
VITE_SUPPORTED_EVIDENCE_TYPES=30+
```

### **API Configuration**

The frontend automatically detects and configures:
- Backend API endpoint (http://localhost:5001)
- Supported evidence types from `/api/supported-types`
- File upload limits and formats
- Evidence validation schemas

### **UI Configuration**

Customize the interface via `src/config/`:
- Sidebar navigation with evidence sections
- Evidence type color coding
- Dashboard widget configuration
- Upload form field definitions

## 🐛 Troubleshooting

### **Common Issues**

1. **API Connection Issues**
```bash
# Verify backend is running
curl http://localhost:5001/api/stats

# Check proxy configuration
cat vite.config.ts
```

2. **Evidence Viewer Issues**
```bash
# Clear browser cache
# Refresh evidence type definitions
# Check console for JavaScript errors
```

3. **Upload Problems**
```bash
# Verify file size limits
# Check evidence type spelling
# Ensure proper form encoding
```

### **Development Issues**

1. **Port Conflicts**
```bash
# Kill processes on frontend port
lsof -ti:3000 | xargs kill -9
```

2. **Module Resolution**
```bash
# Clear node modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

## 📚 Documentation

- **[Component Documentation](./docs/COMPONENTS.md)** - Detailed component reference
- **[Evidence Viewer Guide](./docs/EVIDENCE_VIEWER.md)** - Evidence viewing documentation
- **[API Integration](./docs/API_INTEGRATION.md)** - Frontend-backend integration
- **[Styling Guide](./docs/STYLING.md)** - UI/UX design guidelines

## 🤝 Contributing

### **Development Guidelines**
1. Follow React/TypeScript best practices
2. Add tests for new evidence viewer components
3. Ensure responsive design for new features
4. Document evidence-specific UI components
5. Maintain backward compatibility

### **Evidence Viewer Development**
1. Create type-specific viewer components for new evidence types
2. Add proper TypeScript types for evidence data
3. Include accessibility features for new viewers
4. Test with real evidence data samples

---

## 📝 License

This project is licensed under the Apache License 2.0. 
# VXDF Integration Testing Plan

This document outlines a comprehensive testing plan to verify the successful integration between the VXDF frontend and backend components.

## 1. System Setup Verification

- [ ] Backend server starts successfully on port 5001
- [ ] Frontend development server starts successfully on port 5173
- [ ] Proxy configuration correctly forwards API requests from frontend to backend
- [ ] CORS is properly configured to allow cross-origin requests

## 2. API Endpoint Testing

### 2.1 Stats Endpoint

- [ ] `GET /api/stats` returns correct dashboard statistics format
- [ ] Stats include total findings, validated findings, exploitable findings
- [ ] Stats include severity breakdowns and vulnerability type breakdowns
- [ ] Recent findings are included in the response

### 2.2 Vulnerability Listing

- [ ] `GET /api/vulnerabilities` returns paginated list of vulnerabilities
- [ ] Pagination parameters (limit, offset) work correctly
- [ ] Filtering by category/type works correctly
- [ ] Filtering by exploitable status works correctly
- [ ] Filtering by severity works correctly

### 2.3 Vulnerability Details

- [ ] `GET /api/vulnerabilities/{id}` returns detailed information about a specific vulnerability
- [ ] All required vulnerability fields are present in the response
- [ ] Source and sink information is correctly formatted
- [ ] Evidence information is correctly formatted
- [ ] Data flow steps are included when available

### 2.4 File Upload and Validation

- [ ] `POST /api/upload` successfully accepts file uploads
- [ ] SARIF file format is processed correctly
- [ ] CycloneDX file format is processed correctly
- [ ] DAST file format is processed correctly
- [ ] Form parameters are correctly passed to the backend
- [ ] Validation process completes successfully
- [ ] Results include properly formatted vulnerability information

### 2.5 Supported Types

- [ ] `GET /api/supported-types` returns the list of supported vulnerability types

## 3. Frontend Component Testing

### 3.1 Dashboard Component

- [ ] Dashboard displays correct statistics from the API
- [ ] Dashboard shows the list of recent vulnerabilities
- [ ] Dashboard updates correctly after file upload and validation
- [ ] Loading states are handled correctly

### 3.2 File Upload Component

- [ ] File selection works via button click
- [ ] Drag and drop file selection works
- [ ] Multiple file selection is handled correctly
- [ ] File type detection works properly
- [ ] Parser type selection updates based on file extension
- [ ] Validation process shows loading indicators
- [ ] Error states are handled and displayed correctly

### 3.3 Navigation

- [ ] Sidebar navigation between views works correctly
- [ ] After file upload, view changes to dashboard to display results

## 4. End-to-End Workflows

### 4.1 Basic Upload and Validation Flow

- [ ] Upload a SARIF file containing vulnerabilities
- [ ] Verify validation process completes
- [ ] Check dashboard updates with new statistics
- [ ] Verify vulnerability list shows the new findings

### 4.2 Detailed Vulnerability Review

- [ ] Upload a file with vulnerabilities
- [ ] Navigate to view a specific vulnerability's details
- [ ] Verify all vulnerability information is displayed correctly
- [ ] Check evidence is properly rendered

### 4.3 Error Handling Scenarios

- [ ] Test with invalid file format
- [ ] Test with empty file
- [ ] Test with file containing no vulnerabilities
- [ ] Test server offline scenarios
- [ ] Verify error messages are displayed correctly

## 5. Cross-Browser Testing

- [ ] Application works in Chrome
- [ ] Application works in Firefox
- [ ] Application works in Safari
- [ ] Application works in Edge

## 6. Security Testing

- [ ] Validate file upload security restrictions
- [ ] Check for proper error handling that doesn't expose sensitive information
- [ ] Verify API endpoints handle invalid data appropriately

## Testing Tools and Methods

### Manual Testing

- Use the web interface to perform the basic workflows
- Verify UI elements display correctly during different states
- Check for visual issues or inconsistencies

### API Testing

- Use tools like Postman, curl, or specialized test scripts to test API endpoints directly
- Verify response formats match the expected schema
- Test with various query parameters and edge cases

### Automated Testing

- Create API test scripts to verify backend integration
- Use browser automation to test frontend-backend integration
- Implement unit tests for key components

## Test Data

- Sample SARIF files with various vulnerabilities
- Sample CycloneDX files with dependencies and vulnerabilities
- Sample DAST report files
- Invalid/malformed files for error testing 
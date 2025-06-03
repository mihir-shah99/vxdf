import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileText, CheckCircle, AlertTriangle, X } from 'lucide-react';
import { uploadScanFile } from '../utils/api';
import toast from 'react-hot-toast';

export default function UploadScan() {
  const navigate = useNavigate();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [scannerType, setScannerType] = useState('SARIF');
  const [targetName, setTargetName] = useState('');
  const [targetVersion, setTargetVersion] = useState('');
  const [autoValidate, setAutoValidate] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [isDragActive, setIsDragActive] = useState(false);

  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);

    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      setSelectedFile(files[0]);
    }
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      toast.error('Please select a file to upload');
      return;
    }

    setIsUploading(true);
    try {
      await uploadScanFile(selectedFile, {
        parserType: scannerType.toLowerCase(),
        validate: autoValidate,
        targetName: targetName || undefined,
        targetVersion: targetVersion || undefined,
      });

      toast.success('Scan file uploaded successfully!');
      navigate('/vulnerabilities');
    } catch (error: any) {
      toast.error(error.message || 'Failed to upload scan file');
    } finally {
      setIsUploading(false);
    }
  };

  const scannerOptions = [
    { value: 'SARIF', label: 'SARIF (Static Analysis Results)', description: 'Standard format for static analysis tools' },
    { value: 'OWASP_ZAP', label: 'OWASP ZAP', description: 'Dynamic application security testing' },
    { value: 'BURP_SUITE', label: 'Burp Suite', description: 'Web vulnerability scanner reports' },
    { value: 'SONARQUBE', label: 'SonarQube', description: 'Code quality and security analysis' },
    { value: 'VERACODE', label: 'Veracode', description: 'Application security platform' },
    { value: 'CHECKMARX', label: 'Checkmarx', description: 'Static application security testing' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Upload Security Scan</h1>
        <p className="mt-1 text-vxdf-gray-400">
          Upload and validate security scan results from SAST, DAST, and SCA tools
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Form */}
        <div className="lg:col-span-2 space-y-6">
          {/* File Upload Area */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Select Scan File</h3>
            
            <div
              className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                isDragActive
                  ? 'border-vxdf-primary bg-vxdf-primary/10'
                  : 'border-vxdf-gray-600 hover:border-vxdf-primary/50'
              }`}
              onDragEnter={handleDragEnter}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
            >
              <Upload className="h-12 w-12 mx-auto text-vxdf-gray-400 mb-4" />
              <p className="text-white mb-2">
                Drag and drop your scan file here, or click to browse
              </p>
              <p className="text-sm text-vxdf-gray-400 mb-4">
                Supports .sarif, .json, .xml, .html files up to 50MB
              </p>
              <input
                type="file"
                id="file-upload"
                className="hidden"
                accept=".sarif,.json,.xml,.html,.zip"
                onChange={handleFileSelect}
              />
              <label
                htmlFor="file-upload"
                className="btn-primary cursor-pointer inline-flex items-center"
              >
                Browse Files
              </label>
            </div>

            {selectedFile && (
              <div className="mt-4 p-4 bg-vxdf-gray-800 rounded-lg">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <FileText className="h-8 w-8 text-vxdf-primary" />
                    <div>
                      <p className="font-medium text-white">{selectedFile.name}</p>
                      <p className="text-sm text-vxdf-gray-400">
                        {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedFile(null)}
                    className="text-vxdf-gray-400 hover:text-red-400 transition-colors"
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Configuration */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Scan Configuration</h3>
            
            <div className="space-y-4">
              {/* Scanner Type */}
              <div>
                <label className="block text-sm font-medium text-vxdf-gray-300 mb-2">
                  Scanner Type
                </label>
                <select
                  value={scannerType}
                  onChange={(e) => setScannerType(e.target.value)}
                  className="w-full px-4 py-2 bg-vxdf-gray-800 border border-vxdf-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vxdf-primary"
                >
                  {scannerOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
                <p className="text-xs text-vxdf-gray-400 mt-1">
                  {scannerOptions.find(opt => opt.value === scannerType)?.description}
                </p>
              </div>

              {/* Target Information */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-vxdf-gray-300 mb-2">
                    Application Name
                  </label>
                  <input
                    type="text"
                    value={targetName}
                    onChange={(e) => setTargetName(e.target.value)}
                    placeholder="e.g., E-commerce Web App"
                    className="w-full px-4 py-2 bg-vxdf-gray-800 border border-vxdf-gray-700 rounded-lg text-white placeholder-vxdf-gray-400 focus:outline-none focus:ring-2 focus:ring-vxdf-primary"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-vxdf-gray-300 mb-2">
                    Version
                  </label>
                  <input
                    type="text"
                    value={targetVersion}
                    onChange={(e) => setTargetVersion(e.target.value)}
                    placeholder="e.g., v2.1.0"
                    className="w-full px-4 py-2 bg-vxdf-gray-800 border border-vxdf-gray-700 rounded-lg text-white placeholder-vxdf-gray-400 focus:outline-none focus:ring-2 focus:ring-vxdf-primary"
                  />
                </div>
              </div>

              {/* Auto Validation */}
              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  id="auto-validate"
                  checked={autoValidate}
                  onChange={(e) => setAutoValidate(e.target.checked)}
                  className="w-4 h-4 rounded border-vxdf-gray-600 bg-vxdf-gray-800 text-vxdf-primary focus:ring-vxdf-primary focus:ring-2"
                />
                <label htmlFor="auto-validate" className="text-sm text-vxdf-gray-300">
                  Automatically start validation for critical and high severity findings
                </label>
              </div>
            </div>
          </div>

          {/* Upload Button */}
          <div className="flex justify-between items-center">
            <button
              onClick={() => navigate('/vulnerabilities')}
              className="btn-secondary"
            >
              Cancel
            </button>
            <button
              onClick={handleUpload}
              disabled={!selectedFile || isUploading}
              className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isUploading ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Processing...
                </>
              ) : (
                <>
                  <Upload className="h-4 w-4 mr-2" />
                  Upload & Process
                </>
              )}
            </button>
          </div>
        </div>

        {/* Sidebar Information */}
        <div className="space-y-6">
          {/* Supported Formats */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Supported Formats</h3>
            <div className="space-y-3">
              <div className="flex items-start space-x-3">
                <CheckCircle className="h-5 w-5 text-green-400 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-white">SARIF 2.1.0</p>
                  <p className="text-xs text-vxdf-gray-400">Standard format for static analysis</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <CheckCircle className="h-5 w-5 text-green-400 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-white">OWASP ZAP XML/JSON</p>
                  <p className="text-xs text-vxdf-gray-400">Dynamic analysis reports</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <CheckCircle className="h-5 w-5 text-green-400 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-white">Burp Suite HTML/XML</p>
                  <p className="text-xs text-vxdf-gray-400">Web vulnerability scanner output</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <CheckCircle className="h-5 w-5 text-green-400 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-white">SonarQube JSON</p>
                  <p className="text-xs text-vxdf-gray-400">Code quality and security</p>
                </div>
              </div>
            </div>
          </div>

          {/* Process Info */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-white mb-4">What Happens Next?</h3>
            <div className="space-y-3">
              <div className="flex items-start space-x-3">
                <div className="w-6 h-6 bg-vxdf-primary rounded-full flex items-center justify-center text-white text-xs font-bold">
                  1
                </div>
                <div>
                  <p className="text-sm font-medium text-white">File Processing</p>
                  <p className="text-xs text-vxdf-gray-400">Parse and normalize findings</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <div className="w-6 h-6 bg-vxdf-primary rounded-full flex items-center justify-center text-white text-xs font-bold">
                  2
                </div>
                <div>
                  <p className="text-sm font-medium text-white">VXDF Analysis</p>
                  <p className="text-xs text-vxdf-gray-400">Map to universal vulnerability language</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <div className="w-6 h-6 bg-vxdf-primary rounded-full flex items-center justify-center text-white text-xs font-bold">
                  3
                </div>
                <div>
                  <p className="text-sm font-medium text-white">Validation</p>
                  <p className="text-xs text-vxdf-gray-400">Docker-based exploitability testing</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <div className="w-6 h-6 bg-vxdf-primary rounded-full flex items-center justify-center text-white text-xs font-bold">
                  4
                </div>
                <div>
                  <p className="text-sm font-medium text-white">Results</p>
                  <p className="text-xs text-vxdf-gray-400">Evidence-based security posture</p>
                </div>
              </div>
            </div>
          </div>

          {/* Tips */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Tips</h3>
            <div className="space-y-2 text-xs text-vxdf-gray-400">
              <p>• Ensure your scan file includes source/sink information for best validation results</p>
              <p>• SARIF files provide the most comprehensive data for VXDF analysis</p>
              <p>• Enable auto-validation for immediate exploitability testing</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
} 
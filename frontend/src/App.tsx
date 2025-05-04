import React, { useState, useEffect } from 'react';
import { FileUpload } from './components/FileUpload';
import { Dashboard } from './components/Dashboard';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { AlertTriangle } from 'lucide-react';
import { Vulnerability, getStats, uploadScanFile } from './api/validateVulnerability';

function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [validatedVulnerabilities, setValidatedVulnerabilities] = useState<Vulnerability[]>([]);
  const [isValidating, setIsValidating] = useState(false);
  const [validationStats, setValidationStats] = useState<{
    total: number;
    confirmed: number;
    falsePositive: number;
    inProgress: number;
  }>({
    total: 0,
    confirmed: 0,
    falsePositive: 0,
    inProgress: 0
  });
  const [error, setError] = useState<string | null>(null);
  
  // Fetch initial stats on component mount
  useEffect(() => {
    fetchStats();
  }, []);
  
  // Function to fetch dashboard stats
  const fetchStats = async () => {
    try {
      const stats = await getStats();
      setValidationStats({
        total: stats.total,
        confirmed: stats.exploitable,
        falsePositive: stats.nonExploitable,
        inProgress: stats.inProgress
      });
      
      if (stats.recentFindings && stats.recentFindings.length > 0) {
        setValidatedVulnerabilities(stats.recentFindings);
      }
    } catch (err) {
      console.error('Error fetching stats:', err);
      setError('Failed to fetch dashboard statistics');
    }
  };

  const handleFileUpload = async (files: File[]) => {
    if (!files || !files.length) return;
    
    setIsValidating(true);
    setError(null);
    
    try {
      // Upload first file (can be extended to support multiple files)
      const file = files[0];
      
      // Determine parser type based on file extension
      let parserType = 'sarif';
      if (file.name.endsWith('.xml') || file.name.endsWith('.json') && file.name.includes('cyclone')) {
        parserType = 'cyclonedx';
      } else if (file.name.endsWith('.xml') || file.name.endsWith('.json') && file.name.includes('zap')) {
        parserType = 'dast';
      }
      
      const result = await uploadScanFile(file, {
        parserType,
        validate: true,
        targetName: 'Uploaded Application',
        minSeverity: 'LOW'
      });
      
      if (result.success) {
        setValidatedVulnerabilities(result.findings);
        setValidationStats(prev => ({
          ...prev,
          total: result.findings.length,
          confirmed: result.findings.filter(v => v.exploitable).length,
          falsePositive: result.findings.filter(v => v.exploitable === false).length,
          inProgress: 0
        }));
        
        // Switch to dashboard view to show results
        setActiveView('dashboard');
      } else {
        setError('File upload failed: ' + result.message);
      }
    } catch (err) {
      console.error('Error during file validation:', err);
      setError('File validation failed: ' + ((err as Error)?.message || 'Unknown error'));
    } finally {
      setIsValidating(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <Header />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar activeView={activeView} setActiveView={setActiveView} />
        <main className="flex-1 overflow-auto p-6">
          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4 flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2" />
              <span>{error}</span>
              <button 
                className="ml-auto text-red-700 hover:text-red-900"
                onClick={() => setError(null)}
              >
                ×
              </button>
            </div>
          )}
          
          {activeView === 'dashboard' && (
            <Dashboard 
              validatedVulnerabilities={validatedVulnerabilities} 
              stats={validationStats}
              isValidating={isValidating}
            />
          )}
          {activeView === 'upload' && (
            <FileUpload onUpload={handleFileUpload} isUploading={isValidating} />
          )}
        </main>
      </div>
      <div className="h-1 bg-gradient-to-r from-blue-600 via-teal-500 to-orange-500"></div>
    </div>
  );
}

export default App;
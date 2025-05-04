import React, { useState } from 'react';
import { FileUpload } from './components/FileUpload';
import { Dashboard } from './components/Dashboard';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { ArrowUp as FileArrowUp, GitBranch, Check, AlertTriangle } from 'lucide-react';

function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [validatedVulnerabilities, setValidatedVulnerabilities] = useState([]);
  const [isValidating, setIsValidating] = useState(false);
  const [validationStats, setValidationStats] = useState({
    total: 0,
    confirmed: 0,
    falsePositive: 0,
    inProgress: 0
  });

  const handleFileUpload = async (files) => {
    setIsValidating(true);
    
    // Simulate validation process
    setTimeout(() => {
      const newValidatedVulns = [
        {
          id: "VUL-001",
          title: "SQL Injection in Login Form",
          severity: "Critical",
          category: "Injection",
          exploitable: true,
          evidence: "User input flows directly into SQL query without sanitization",
          source: {
            file: "src/controllers/AuthController.js",
            line: 42,
            snippet: "db.query(`SELECT * FROM users WHERE username='${req.body.username}'`)"
          },
          sink: {
            file: "src/database/queries.js",
            line: 15,
            snippet: "return connection.query(queryString);"
          }
        },
        {
          id: "VUL-002",
          title: "Cross-Site Scripting in Profile Page",
          severity: "High",
          category: "XSS",
          exploitable: true,
          evidence: "User profile data rendered without escaping HTML entities",
          source: {
            file: "src/components/Profile.js",
            line: 28,
            snippet: "div.innerHTML = userData.bio;"
          },
          sink: {
            file: "src/components/Profile.js",
            line: 28,
            snippet: "div.innerHTML = userData.bio;"
          }
        },
        {
          id: "VUL-003",
          title: "Potential Path Traversal",
          severity: "Medium",
          category: "Path Traversal",
          exploitable: false,
          evidence: "Input validation prevents directory traversal sequences",
          source: {
            file: "src/utils/fileHelper.js",
            line: 53,
            snippet: "const filePath = req.params.fileName;"
          },
          sink: {
            file: "src/utils/fileHelper.js",
            line: 55,
            snippet: "if (filePath.includes('../')) return res.status(400).send('Invalid filename');"
          }
        }
      ];
      
      setValidatedVulnerabilities(newValidatedVulns);
      setValidationStats({
        total: newValidatedVulns.length,
        confirmed: newValidatedVulns.filter(v => v.exploitable).length,
        falsePositive: newValidatedVulns.filter(v => !v.exploitable).length,
        inProgress: 0
      });
      setIsValidating(false);
    }, 2000);
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <Header />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar activeView={activeView} setActiveView={setActiveView} />
        <main className="flex-1 overflow-auto p-6">
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
import React from 'react';
import { LayoutDashboard, Upload, Settings, Database, AlertTriangle, FileText, GitBranch } from 'lucide-react';

interface SidebarProps {
  activeView: string;
  setActiveView: (view: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeView, setActiveView }) => {
  const navItems = [
    { id: 'dashboard', icon: <LayoutDashboard size={20} />, label: 'Dashboard' },
    { id: 'upload', icon: <Upload size={20} />, label: 'Upload Scans' },
    { id: 'vulnerabilities', icon: <AlertTriangle size={20} />, label: 'Vulnerabilities' },
    { id: 'reports', icon: <FileText size={20} />, label: 'Reports' },
    { id: 'environments', icon: <GitBranch size={20} />, label: 'Environments' },
    { id: 'database', icon: <Database size={20} />, label: 'Database' },
    { id: 'settings', icon: <Settings size={20} />, label: 'Settings' }
  ];

  return (
    <div className="w-64 bg-white border-r border-gray-200 flex flex-col">
      <div className="p-4">
        <h2 className="text-sm font-medium text-gray-500">NAVIGATION</h2>
      </div>
      <nav className="flex-1">
        <ul>
          {navItems.map(item => (
            <li key={item.id}>
              <button
                onClick={() => setActiveView(item.id)}
                className={`w-full flex items-center space-x-3 px-4 py-3 text-sm font-medium ${
                  activeView === item.id 
                    ? 'bg-blue-50 text-blue-600 border-r-4 border-blue-600' 
                    : 'text-gray-700 hover:bg-gray-50'
                }`}
              >
                <span className={activeView === item.id ? 'text-blue-600' : 'text-gray-500'}>
                  {item.icon}
                </span>
                <span>{item.label}</span>
              </button>
            </li>
          ))}
        </ul>
      </nav>
      <div className="p-4 mt-auto">
        <div className="rounded-md bg-blue-50 p-3">
          <div className="flex items-center">
            <div className="text-blue-900">
              <p className="text-sm font-medium">Validator v0.1.0</p>
              <p className="text-xs">Community Edition</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
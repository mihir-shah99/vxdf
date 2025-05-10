import React from 'react';
import * as LucideIcons from 'lucide-react';
import { sidebarConfig } from '../config/sidebarConfig';
import logo from '../assets/logo.png';

interface SidebarProps {
  activeView: string;
  setActiveView: (view: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeView, setActiveView }) => {
  return (
    <div className="w-64 bg-gray-900 text-white flex flex-col min-h-screen border-r border-gray-800">
      <div className="p-6 pb-2 flex items-center gap-2">
        <img src={logo} alt="VXDF Logo" className="h-8 w-8" />
        <span className="text-blue-400 font-bold text-xl">VXDF</span>
        <span className="ml-auto bg-blue-600 text-xs px-2 py-1 rounded-full font-semibold">Beta</span>
      </div>
      {sidebarConfig.map(section => (
        <React.Fragment key={section.section}>
          <div className="px-6 pt-4 pb-1">
            <h2 className="text-xs font-semibold text-gray-400 tracking-wider">{section.section}</h2>
          </div>
          <ul>
            {section.items.map(item => {
              const IconComponent = typeof LucideIcons[item.icon as keyof typeof LucideIcons] === 'function'
                ? LucideIcons[item.icon as keyof typeof LucideIcons] as React.ComponentType<any>
                : null;
              return (
                <li key={item.id}>
                  <button
                    onClick={() => setActiveView(item.id)}
                    className={`w-full flex items-center gap-3 px-6 py-3 text-sm font-medium rounded transition-colors ${
                      activeView === item.id
                        ? 'bg-blue-700 text-white shadow border-l-4 border-blue-400'
                        : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                    }`}
                  >
                    <span className={activeView === item.id ? 'text-white' : 'text-blue-400'}>
                      {IconComponent && <IconComponent size={20} />}
                    </span>
                    <span>{item.label}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </React.Fragment>
      ))}
      <div className="p-6 mt-auto">
        <div className="rounded-md bg-blue-900/60 p-4 flex flex-col items-start">
          <span className="text-blue-300 font-bold text-sm">Validator v0.1.0</span>
          <span className="text-xs text-blue-200">Community Edition</span>
        </div>
      </div>
    </div>
  );
};
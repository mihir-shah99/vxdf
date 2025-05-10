import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from '../Sidebar';
import TopBar from './TopBar';

const Layout: React.FC = () => {
  const [activeView, setActiveView] = useState('dashboard');

  return (
    <div className="flex min-h-screen bg-gray-900">
      <Sidebar activeView={activeView} setActiveView={setActiveView} />
      <div className="flex-1 flex flex-col">
        <TopBar />
        <main className="flex-1 overflow-x-hidden p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout; 
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Shield, 
  Home, 
  AlertTriangle, 
  GitBranch, 
  Upload,
  Activity,
  Menu,
  X
} from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
}

const navigation = [
  { name: 'Dashboard', href: '/', icon: Home },
  { name: 'Vulnerabilities', href: '/vulnerabilities', icon: AlertTriangle },
  { name: 'Validation', href: '/validation', icon: GitBranch },
  { name: 'Upload Scan', href: '/upload', icon: Upload },
];

export default function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);

  return (
    <div className="min-h-screen bg-vxdf-gray-950 flex">
      {/* Desktop Sidebar */}
      <div className="hidden lg:flex lg:w-64 lg:flex-col">
        <div className="flex flex-col flex-grow pt-5 pb-4 overflow-y-auto bg-vxdf-gray-900 border-r border-vxdf-gray-800">
          {/* Logo */}
          <div className="flex items-center flex-shrink-0 px-4">
            <Shield className="h-8 w-8 text-vxdf-primary" />
            <div className="ml-3">
              <h1 className="text-xl font-bold text-white">VXDF</h1>
              <p className="text-xs text-vxdf-gray-400">Security Posture Management</p>
            </div>
          </div>

          {/* Navigation */}
          <nav className="mt-8 flex-1 px-2 space-y-1">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors ${
                    isActive
                      ? 'bg-vxdf-primary text-white'
                      : 'text-vxdf-gray-300 hover:bg-vxdf-gray-800 hover:text-white'
                  }`}
                >
                  <item.icon
                    className={`mr-3 flex-shrink-0 h-5 w-5 ${
                      isActive ? 'text-white' : 'text-vxdf-gray-400 group-hover:text-white'
                    }`}
                  />
                  {item.name}
                </Link>
              );
            })}
          </nav>

          {/* Status Indicator */}
          <div className="flex-shrink-0 px-4 py-4 border-t border-vxdf-gray-800">
            <div className="flex items-center">
              <Activity className="h-5 w-5 text-green-400" />
              <div className="ml-3">
                <p className="text-sm text-vxdf-gray-300">System Status</p>
                <p className="text-xs text-green-400">All systems operational</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Mobile menu overlay */}
      {isMobileMenuOpen && (
        <div className="lg:hidden fixed inset-0 flex z-40">
          <div 
            className="fixed inset-0 bg-vxdf-gray-600 bg-opacity-75" 
            onClick={() => setIsMobileMenuOpen(false)} 
          />
          <div className="relative flex-1 flex flex-col max-w-xs w-full bg-vxdf-gray-900">
            <div className="absolute top-0 right-0 -mr-12 pt-2">
              <button
                type="button"
                className="ml-1 flex items-center justify-center h-10 w-10 rounded-full text-white"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                <X className="h-6 w-6" />
              </button>
            </div>
            {/* Mobile navigation content */}
            <div className="flex-1 h-0 pt-5 pb-4 overflow-y-auto">
              <div className="flex-shrink-0 flex items-center px-4">
                <Shield className="h-8 w-8 text-vxdf-primary" />
                <div className="ml-3">
                  <h1 className="text-xl font-bold text-white">VXDF</h1>
                  <p className="text-xs text-vxdf-gray-400">Security Posture Management</p>
                </div>
              </div>
              <nav className="mt-5 px-2 space-y-1">
                {navigation.map((item) => {
                  const isActive = location.pathname === item.href;
                  return (
                    <Link
                      key={item.name}
                      to={item.href}
                      onClick={() => setIsMobileMenuOpen(false)}
                      className={`group flex items-center px-2 py-2 text-base font-medium rounded-md ${
                        isActive
                          ? 'bg-vxdf-primary text-white'
                          : 'text-vxdf-gray-300 hover:bg-vxdf-gray-800 hover:text-white'
                      }`}
                    >
                      <item.icon className="mr-4 h-6 w-6" />
                      {item.name}
                    </Link>
                  );
                })}
              </nav>
            </div>
          </div>
        </div>
      )}

      {/* Main content area */}
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Mobile header */}
        <header className="lg:hidden bg-vxdf-gray-900 border-b border-vxdf-gray-800">
          <div className="flex items-center justify-between px-4 py-2">
            <div className="flex items-center">
              <button
                type="button"
                className="text-vxdf-gray-300 hover:text-white"
                onClick={() => setIsMobileMenuOpen(true)}
              >
                <Menu className="h-6 w-6" />
              </button>
              <div className="ml-3 flex items-center">
                <Shield className="h-6 w-6 text-vxdf-primary" />
                <span className="ml-2 text-lg font-semibold text-white">VXDF</span>
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 relative overflow-y-auto focus:outline-none">
          <div className="py-6">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
              {children}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
} 
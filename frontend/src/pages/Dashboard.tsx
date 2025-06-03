import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  AlertTriangle, 
  Shield, 
  Activity, 
  TrendingUp,
  TrendingDown,
  CheckCircle,
  Clock,
  XCircle,
  ArrowRight,
  Upload,
  GitBranch,
  Eye,
  Zap,
  Target,
  Server,
  Lock,
  Unlock
} from 'lucide-react';
import { useVulnerabilityStats } from '../hooks/useVulnerabilities';

interface AnimatedCounterProps {
  end: number;
  duration?: number;
  suffix?: string;
}

function AnimatedCounter({ end, duration = 2000, suffix = '' }: AnimatedCounterProps) {
  const [count, setCount] = useState(0);

  useEffect(() => {
    let startTime: number;
    let animationFrame: number;

    const animate = (currentTime: number) => {
      if (!startTime) startTime = currentTime;
      const progress = Math.min((currentTime - startTime) / duration, 1);
      const easeOutQuart = 1 - Math.pow(1 - progress, 4);
      setCount(Math.floor(easeOutQuart * end));

      if (progress < 1) {
        animationFrame = requestAnimationFrame(animate);
      }
    };

    animationFrame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationFrame);
  }, [end, duration]);

  return <span>{count}{suffix}</span>;
}

interface EnhancedStatCardProps {
  title: string;
  value: number | string;
  icon: React.ComponentType<{ className?: string }>;
  gradient: string;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  description?: string;
  onClick?: () => void;
}

function EnhancedStatCard({ title, value, icon: Icon, gradient, trend, description, onClick }: EnhancedStatCardProps) {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <div 
      className={`relative overflow-hidden rounded-2xl p-6 transition-all duration-500 cursor-pointer transform hover:scale-105 hover:shadow-2xl ${onClick ? 'hover:shadow-vxdf-primary/20' : ''}`}
      style={{ background: gradient }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={onClick}
    >
      {/* Glassmorphism overlay */}
      <div className="absolute inset-0 bg-white/5 backdrop-blur-sm" />
      
      {/* Animated background pattern */}
      <div className={`absolute inset-0 opacity-10 transition-opacity duration-500 ${isHovered ? 'opacity-20' : ''}`}>
        <div className="absolute -top-4 -right-4 w-24 h-24 bg-white rounded-full animate-pulse" />
        <div className="absolute -bottom-6 -left-6 w-32 h-32 bg-white/30 rounded-full animate-pulse" style={{ animationDelay: '1s' }} />
      </div>

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className="p-3 bg-white/20 rounded-xl backdrop-blur-sm">
            <Icon className="h-8 w-8 text-white drop-shadow-lg" />
          </div>
          {trend && (
            <div className={`flex items-center space-x-1 px-3 py-1 rounded-full bg-white/20 backdrop-blur-sm ${trend.isPositive ? 'text-green-200' : 'text-red-200'}`}>
              {trend.isPositive ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
              <span className="text-sm font-medium">{Math.abs(trend.value)}%</span>
            </div>
          )}
        </div>

        <div className="space-y-2">
          <h3 className="text-sm font-medium text-white/80 uppercase tracking-wider">{title}</h3>
          <p className="text-3xl font-bold text-white drop-shadow-lg">
            {typeof value === 'number' ? <AnimatedCounter end={value} /> : value}
          </p>
          {description && (
            <p className="text-sm text-white/70">{description}</p>
          )}
        </div>
      </div>
    </div>
  );
}

interface CircularProgressProps {
  percentage: number;
  size?: number;
  strokeWidth?: number;
  color?: string;
  children?: React.ReactNode;
}

function CircularProgress({ percentage, size = 120, strokeWidth = 8, color = '#0066ff', children }: CircularProgressProps) {
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const strokeDasharray = `${(percentage / 100) * circumference} ${circumference}`;

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} className="transform -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth={strokeWidth}
          fill="none"
          className="text-vxdf-gray-800"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={strokeWidth}
          fill="none"
          strokeDasharray={strokeDasharray}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
          style={{
            filter: 'drop-shadow(0 0 6px rgba(0, 102, 255, 0.6))'
          }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        {children}
      </div>
    </div>
  );
}

interface SeverityBarProps {
  severity: string;
  count: number;
  total: number;
  color: string;
}

function SeverityBar({ severity, count, total, color }: SeverityBarProps) {
  const percentage = total > 0 ? (count / total) * 100 : 0;

  return (
    <div className="group">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center space-x-2">
          <div className={`w-3 h-3 rounded-full ${color} shadow-lg`} />
          <span className="text-sm font-medium text-white capitalize">{severity}</span>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-vxdf-gray-400">{percentage.toFixed(1)}%</span>
          <span className="text-sm font-bold text-white">{count}</span>
        </div>
      </div>
      <div className="relative h-2 bg-vxdf-gray-800 rounded-full overflow-hidden">
        <div 
          className={`absolute left-0 top-0 h-full ${color} rounded-full transition-all duration-1000 ease-out shadow-lg`}
          style={{ 
            width: `${percentage}%`,
            filter: 'drop-shadow(0 0 4px rgba(255, 255, 255, 0.3))'
          }}
        />
      </div>
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const { data: stats, isLoading } = useVulnerabilityStats();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="relative">
          <div className="w-16 h-16 border-4 border-vxdf-primary/20 border-t-vxdf-primary rounded-full animate-spin"></div>
          <div className="absolute inset-0 w-16 h-16 border-4 border-transparent border-t-vxdf-secondary rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1s' }}></div>
        </div>
      </div>
    );
  }

  const riskScore = stats ? Math.round((stats.exploitable / stats.total) * 100) : 0;
  const validationRate = stats ? Math.round((stats.validated / stats.total) * 100) : 0;
  const securityPosture = riskScore < 25 ? 'EXCELLENT' : riskScore < 50 ? 'GOOD' : riskScore < 75 ? 'MODERATE' : 'CRITICAL';

  return (
    <div className="space-y-6 sm:space-y-8 pb-8">
      {/* Hero Section */}
      <div className="relative overflow-hidden rounded-2xl sm:rounded-3xl bg-gradient-to-br from-vxdf-primary via-blue-600 to-vxdf-secondary p-6 sm:p-8 text-white">
        <div className="absolute inset-0 bg-black/10" />
        <div className="absolute -top-12 sm:-top-24 -right-12 sm:-right-24 w-24 h-24 sm:w-48 sm:h-48 bg-white/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-6 sm:-bottom-12 -left-6 sm:-left-12 w-16 h-16 sm:w-32 sm:h-32 bg-white/5 rounded-full blur-2xl" />
        
        <div className="relative z-10">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
            <div className="space-y-3 sm:space-y-4">
              <div className="flex items-center space-x-3">
                <Shield className="h-8 w-8 sm:h-12 sm:w-12 text-white drop-shadow-lg" />
                <div>
                  <h1 className="text-2xl sm:text-4xl font-bold bg-gradient-to-r from-white to-blue-100 bg-clip-text text-transparent">
                    Security Command Center
                  </h1>
                  <p className="text-sm sm:text-base text-blue-100">Advanced Application Security Posture Management</p>
                </div>
              </div>
              
              <div className="flex flex-col sm:flex-row sm:items-center space-y-2 sm:space-y-0 sm:space-x-6">
                <div className="px-3 py-2 sm:px-4 sm:py-2 bg-white/20 rounded-full backdrop-blur-sm">
                  <span className="text-xs sm:text-sm font-medium">Security Posture: </span>
                  <span className={`font-bold ${securityPosture === 'EXCELLENT' ? 'text-green-200' : securityPosture === 'CRITICAL' ? 'text-red-200' : 'text-yellow-200'}`}>
                    {securityPosture}
                  </span>
                </div>
                <div className="flex items-center space-x-2 text-blue-100">
                  <Server className="h-3 w-3 sm:h-4 sm:w-4" />
                  <span className="text-xs sm:text-sm">Docker Validation Active</span>
                </div>
              </div>
            </div>

            <div className="mt-4 sm:mt-6 lg:mt-0 flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-4">
              <button 
                onClick={() => navigate('/upload')}
                className="flex items-center justify-center px-4 py-2 sm:px-6 sm:py-3 bg-white/20 hover:bg-white/30 backdrop-blur-sm rounded-xl text-white font-medium transition-all duration-300 hover:scale-105 hover:shadow-2xl text-sm sm:text-base"
              >
                <Upload className="h-4 w-4 sm:h-5 sm:w-5 mr-2" />
                Upload Scan
              </button>
              <button 
                onClick={() => navigate('/validation')}
                className="flex items-center justify-center px-4 py-2 sm:px-6 sm:py-3 bg-gradient-to-r from-white/10 to-white/5 hover:from-white/20 hover:to-white/10 backdrop-blur-sm rounded-xl text-white font-medium border border-white/20 transition-all duration-300 hover:scale-105 text-sm sm:text-base"
              >
                <GitBranch className="h-4 w-4 sm:h-5 sm:w-5 mr-2" />
                Validation Center
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
        <EnhancedStatCard
          title="Total Vulnerabilities"
          value={stats?.total || 0}
          icon={AlertTriangle}
          gradient="linear-gradient(135deg, #f97316 0%, #ea580c 100%)"
          trend={{ value: 12, isPositive: false }}
          description="Across all security tools"
          onClick={() => navigate('/vulnerabilities')}
        />
        <EnhancedStatCard
          title="Risk Score"
          value={`${riskScore}%`}
          icon={riskScore > 50 ? Unlock : Lock}
          gradient={riskScore > 50 ? "linear-gradient(135deg, #ef4444 0%, #dc2626 100%)" : "linear-gradient(135deg, #10b981 0%, #059669 100%)"}
          trend={{ value: 8, isPositive: false }}
          description="Exploitability assessment"
          onClick={() => navigate('/vulnerabilities?filter=risk')}
        />
        <EnhancedStatCard
          title="Validated Findings"
          value={stats?.validated || 0}
          icon={CheckCircle}
          gradient="linear-gradient(135deg, #10b981 0%, #059669 100%)"
          trend={{ value: 15, isPositive: true }}
          description="Docker-verified results"
          onClick={() => navigate('/vulnerabilities?filter=validated')}
        />
        <EnhancedStatCard
          title="Validation Rate"
          value={`${validationRate}%`}
          icon={Activity}
          gradient="linear-gradient(135deg, #0066ff 0%, #0052cc 100%)"
          trend={{ value: 5, isPositive: true }}
          description="Evidence-based validation"
          onClick={() => navigate('/validation')}
        />
      </div>

      {/* Security Analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Assessment */}
        <div className="lg:col-span-1">
          <div className="card p-6 sm:p-8 bg-gradient-to-br from-vxdf-gray-900 via-vxdf-gray-800 to-vxdf-gray-900 border-2 border-vxdf-gray-700 hover:border-vxdf-primary/50 transition-all duration-500">
            <div className="text-center space-y-4 sm:space-y-6">
              <h3 className="text-lg sm:text-xl font-semibold text-white">Security Posture</h3>
              
              <CircularProgress 
                percentage={100 - riskScore} 
                size={mounted ? 140 : 120} 
                strokeWidth={12}
                color={riskScore > 50 ? '#ef4444' : '#10b981'}
              >
                <div className="text-center">
                  <div className="text-2xl sm:text-3xl font-bold text-white">
                    {mounted ? <AnimatedCounter end={100 - riskScore} suffix="%" /> : `${100 - riskScore}%`}
                  </div>
                  <div className="text-xs sm:text-sm text-vxdf-gray-400">Secure</div>
                </div>
              </CircularProgress>

              <div className="grid grid-cols-2 gap-3 sm:gap-4 text-center">
                <div className="p-2 sm:p-3 bg-vxdf-gray-800 rounded-xl cursor-pointer hover:bg-vxdf-gray-700 transition-colors" onClick={() => navigate('/vulnerabilities?filter=validated')}>
                  <div className="text-base sm:text-lg font-bold text-green-400">
                    {mounted ? <AnimatedCounter end={stats?.validated || 0} /> : stats?.validated || 0}
                  </div>
                  <div className="text-xs text-vxdf-gray-400">Validated</div>
                </div>
                <div className="p-2 sm:p-3 bg-vxdf-gray-800 rounded-xl cursor-pointer hover:bg-vxdf-gray-700 transition-colors" onClick={() => navigate('/vulnerabilities?filter=exploitable')}>
                  <div className="text-base sm:text-lg font-bold text-red-400">
                    {mounted ? <AnimatedCounter end={stats?.exploitable || 0} /> : stats?.exploitable || 0}
                  </div>
                  <div className="text-xs text-vxdf-gray-400">Exploitable</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Vulnerability Breakdown */}
        <div className="lg:col-span-2">
          <div className="card p-4 sm:p-6 bg-gradient-to-br from-vxdf-gray-900 to-vxdf-gray-800 border border-vxdf-gray-700">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-4 sm:mb-6 space-y-2 sm:space-y-0">
              <h3 className="text-lg sm:text-xl font-semibold text-white">Vulnerability Analysis</h3>
              <button 
                onClick={() => navigate('/vulnerabilities')}
                className="flex items-center space-x-2 text-vxdf-primary hover:text-vxdf-secondary transition-colors text-sm sm:text-base"
              >
                <span>View Details</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            </div>
            
            <div className="space-y-3 sm:space-y-4">
              {stats?.bySeverity && Object.entries(stats.bySeverity).map(([severity, count]) => {
                const colors = {
                  critical: 'bg-gradient-to-r from-red-500 to-red-600',
                  high: 'bg-gradient-to-r from-orange-500 to-orange-600',
                  medium: 'bg-gradient-to-r from-yellow-500 to-yellow-600',
                  low: 'bg-gradient-to-r from-green-500 to-green-600',
                  info: 'bg-gradient-to-r from-blue-500 to-blue-600'
                };
                
                return (
                  <div 
                    key={severity} 
                    className="cursor-pointer hover:bg-vxdf-gray-800/50 p-2 rounded-lg transition-colors"
                    onClick={() => navigate(`/vulnerabilities?severity=${severity.toLowerCase()}`)}
                  >
                    <SeverityBar
                      severity={severity}
                      count={count}
                      total={stats.total}
                      color={colors[severity.toLowerCase() as keyof typeof colors] || colors.info}
                    />
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Activity Feed & Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Live Activity Feed */}
        <div className="card p-4 sm:p-6 bg-gradient-to-br from-vxdf-gray-900 to-vxdf-gray-800">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-4 sm:mb-6 space-y-2 sm:space-y-0">
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 sm:w-3 sm:h-3 bg-vxdf-primary rounded-full animate-pulse"></div>
              <h3 className="text-lg sm:text-xl font-semibold text-white">Live Activity</h3>
            </div>
            <button 
              onClick={() => navigate('/validation')}
              className="text-vxdf-primary hover:text-vxdf-secondary transition-colors"
            >
              <Eye className="h-4 w-4 sm:h-5 sm:w-5" />
            </button>
          </div>
          
          <div className="space-y-3 sm:space-y-4">
            {[
              { type: 'validation', title: 'SQL Injection validation completed', status: 'success', time: '2m ago', icon: CheckCircle },
              { type: 'scan', title: 'New SARIF scan processed', status: 'info', time: '5m ago', icon: Upload },
              { type: 'validation', title: 'XSS validation in progress', status: 'warning', time: '8m ago', icon: Clock },
              { type: 'finding', title: 'Critical path traversal detected', status: 'error', time: '15m ago', icon: AlertTriangle }
            ].map((item, index) => (
              <div 
                key={index} 
                className="flex items-center space-x-3 sm:space-x-4 p-2 sm:p-3 bg-vxdf-gray-800/50 rounded-lg hover:bg-vxdf-gray-800 transition-colors cursor-pointer"
                onClick={() => navigate(item.type === 'validation' ? '/validation' : '/vulnerabilities')}
              >
                <div className={`p-1.5 sm:p-2 rounded-lg flex-shrink-0 ${
                  item.status === 'success' ? 'bg-green-500/20 text-green-400' :
                  item.status === 'warning' ? 'bg-yellow-500/20 text-yellow-400' :
                  item.status === 'error' ? 'bg-red-500/20 text-red-400' :
                  'bg-blue-500/20 text-blue-400'
                }`}>
                  <item.icon className="h-3 w-3 sm:h-4 sm:w-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs sm:text-sm font-medium text-white truncate">{item.title}</p>
                  <p className="text-xs text-vxdf-gray-400">{item.time}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Enhanced Quick Actions */}
        <div className="card p-4 sm:p-6 bg-gradient-to-br from-vxdf-gray-900 to-vxdf-gray-800">
          <h3 className="text-lg sm:text-xl font-semibold text-white mb-4 sm:mb-6">Security Operations</h3>
          
          <div className="space-y-3 sm:space-y-4">
            <button
              onClick={() => navigate('/upload')}
              className="w-full flex items-center p-3 sm:p-4 bg-gradient-to-r from-vxdf-primary/20 to-blue-600/20 hover:from-vxdf-primary/30 hover:to-blue-600/30 rounded-xl transition-all duration-300 hover:scale-105 group border border-vxdf-primary/20"
            >
              <div className="p-2 sm:p-3 bg-vxdf-primary rounded-lg mr-3 sm:mr-4 group-hover:scale-110 transition-transform flex-shrink-0">
                <Upload className="h-4 w-4 sm:h-6 sm:w-6 text-white" />
              </div>
              <div className="text-left flex-1 min-w-0">
                <p className="text-sm sm:text-base font-medium text-white">Upload Security Scan</p>
                <p className="text-xs sm:text-sm text-vxdf-gray-400">SARIF, ZAP, Burp Suite, SonarQube</p>
              </div>
              <ArrowRight className="h-4 w-4 sm:h-5 sm:w-5 text-vxdf-gray-400 group-hover:text-white transition-colors flex-shrink-0" />
            </button>
            
            <button
              onClick={() => navigate('/vulnerabilities')}
              className="w-full flex items-center p-3 sm:p-4 bg-gradient-to-r from-orange-500/20 to-red-500/20 hover:from-orange-500/30 hover:to-red-500/30 rounded-xl transition-all duration-300 hover:scale-105 group border border-orange-500/20"
            >
              <div className="p-2 sm:p-3 bg-orange-500 rounded-lg mr-3 sm:mr-4 group-hover:scale-110 transition-transform flex-shrink-0">
                <Target className="h-4 w-4 sm:h-6 sm:w-6 text-white" />
              </div>
              <div className="text-left flex-1 min-w-0">
                <p className="text-sm sm:text-base font-medium text-white">Analyze Vulnerabilities</p>
                <p className="text-xs sm:text-sm text-vxdf-gray-400">Review and prioritize findings</p>
              </div>
              <ArrowRight className="h-4 w-4 sm:h-5 sm:w-5 text-vxdf-gray-400 group-hover:text-white transition-colors flex-shrink-0" />
            </button>
            
            <button
              onClick={() => navigate('/validation')}
              className="w-full flex items-center p-3 sm:p-4 bg-gradient-to-r from-green-500/20 to-emerald-500/20 hover:from-green-500/30 hover:to-emerald-500/30 rounded-xl transition-all duration-300 hover:scale-105 group border border-green-500/20"
            >
              <div className="p-2 sm:p-3 bg-green-500 rounded-lg mr-3 sm:mr-4 group-hover:scale-110 transition-transform flex-shrink-0">
                <Zap className="h-4 w-4 sm:h-6 sm:w-6 text-white" />
              </div>
              <div className="text-left flex-1 min-w-0">
                <p className="text-sm sm:text-base font-medium text-white">Docker Validation</p>
                <p className="text-xs sm:text-sm text-vxdf-gray-400">Prove exploitability with evidence</p>
              </div>
              <ArrowRight className="h-4 w-4 sm:h-5 sm:w-5 text-vxdf-gray-400 group-hover:text-white transition-colors flex-shrink-0" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
} 
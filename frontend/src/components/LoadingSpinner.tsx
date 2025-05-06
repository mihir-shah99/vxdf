import React from 'react';

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 'md',
  className = '',
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
  };

  return (
    <div className={`flex items-center justify-center ${className}`}>
      <div
        className={`
          ${sizeClasses[size]}
          border-2
          border-current
          border-t-transparent
          rounded-full
          animate-spin
        `}
        role="status"
        aria-label="Loading"
      />
    </div>
  );
};

export default LoadingSpinner; 
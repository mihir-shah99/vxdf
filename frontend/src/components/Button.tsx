import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'success' | 'warning';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
  fullWidth?: boolean;
}

const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  fullWidth = false,
  className = '',
  disabled,
  ...props
}) => {
  const baseClasses = 'inline-flex items-center justify-center rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900';
  
  const variantClasses = {
    primary: 'bg-primary-500 hover:bg-primary-600 focus:ring-primary-500 text-white',
    secondary: 'bg-gray-700 hover:bg-gray-600 focus:ring-gray-500 text-white',
    danger: 'bg-danger-500 hover:bg-danger-600 focus:ring-danger-500 text-white',
    success: 'bg-success-500 hover:bg-success-600 focus:ring-success-500 text-white',
    warning: 'bg-warning-500 hover:bg-warning-600 focus:ring-warning-500 text-white',
  };

  const sizeClasses = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg',
  };

  const widthClass = fullWidth ? 'w-full' : '';

  return (
    <button
      className={`
        ${baseClasses}
        ${variantClasses[variant]}
        ${sizeClasses[size]}
        ${widthClass}
        ${disabled || isLoading ? 'opacity-50 cursor-not-allowed' : ''}
        ${className}
      `}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <div className="mr-2">
          <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
        </div>
      ) : null}
      {children}
    </button>
  );
};

export default Button; 
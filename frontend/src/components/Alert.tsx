import React from 'react';

interface AlertProps {
  children: React.ReactNode;
  variant?: 'primary' | 'success' | 'danger' | 'warning' | 'info';
  title?: string;
  onClose?: () => void;
  className?: string;
}

const Alert: React.FC<AlertProps> = ({
  children,
  variant = 'primary',
  title,
  onClose,
  className = '',
}) => {
  const variantClasses = {
    primary: 'bg-primary-500/10 border-primary-500 text-primary-400',
    success: 'bg-success-500/10 border-success-500 text-success-400',
    danger: 'bg-danger-500/10 border-danger-500 text-danger-400',
    warning: 'bg-warning-500/10 border-warning-500 text-warning-400',
    info: 'bg-blue-500/10 border-blue-500 text-blue-400',
  };

  return (
    <div
      className={`
        relative rounded-lg border p-4
        ${variantClasses[variant]}
        ${className}
      `}
      role="alert"
    >
      {onClose && (
        <button
          className="absolute top-4 right-4 text-current hover:opacity-75"
          onClick={onClose}
          aria-label="Close"
        >
          <svg
            className="h-4 w-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        </button>
      )}

      {title && (
        <h5 className="mb-1 font-medium">{title}</h5>
      )}

      <div className="text-sm">{children}</div>
    </div>
  );
};

export default Alert; 
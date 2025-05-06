import React from 'react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  fullWidth?: boolean;
}

const Input: React.FC<InputProps> = ({
  label,
  error,
  helperText,
  fullWidth = false,
  className = '',
  ...props
}) => {
  return (
    <div className={`${fullWidth ? 'w-full' : ''} ${className}`}>
      {label && (
        <label className="block text-sm font-medium text-gray-300 mb-1">
          {label}
        </label>
      )}
      <input
        className={`
          w-full px-4 py-2 bg-gray-800 border rounded-lg
          focus:outline-none focus:ring-2 focus:ring-primary-500
          ${error ? 'border-danger-500' : 'border-gray-600'}
          ${props.disabled ? 'opacity-50 cursor-not-allowed' : ''}
        `}
        {...props}
      />
      {(error || helperText) && (
        <p className={`mt-1 text-sm ${error ? 'text-danger-500' : 'text-gray-400'}`}>
          {error || helperText}
        </p>
      )}
    </div>
  );
};

export default Input; 
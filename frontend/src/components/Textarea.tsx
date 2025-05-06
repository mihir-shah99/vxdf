import React from 'react';

interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
  helperText?: string;
  fullWidth?: boolean;
}

const Textarea: React.FC<TextareaProps> = ({
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
      <textarea
        className={`
          w-full px-4 py-2 bg-gray-800 border rounded-lg
          focus:outline-none focus:ring-2 focus:ring-primary-500
          ${error ? 'border-danger-500' : 'border-gray-600'}
          ${props.disabled ? 'opacity-50 cursor-not-allowed' : ''}
          min-h-[100px] resize-y
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

export default Textarea; 
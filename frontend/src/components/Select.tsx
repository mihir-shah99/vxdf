import React from 'react';

interface Option {
  value: string;
  label: string;
}

interface SelectProps extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'onChange'> {
  label?: string;
  error?: string;
  helperText?: string;
  options: Option[];
  fullWidth?: boolean;
  onChange?: (value: string) => void;
}

const Select: React.FC<SelectProps> = ({
  label,
  error,
  helperText,
  options,
  fullWidth = false,
  className = '',
  onChange,
  ...props
}) => {
  const handleChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    if (onChange) {
      onChange(e.target.value);
    }
  };

  return (
    <div className={`${fullWidth ? 'w-full' : ''} ${className}`}>
      {label && (
        <label className="block text-sm font-medium text-gray-300 mb-1">
          {label}
        </label>
      )}
      <select
        className={`
          w-full px-4 py-2 bg-gray-800 border rounded-lg
          focus:outline-none focus:ring-2 focus:ring-primary-500
          ${error ? 'border-danger-500' : 'border-gray-600'}
          ${props.disabled ? 'opacity-50 cursor-not-allowed' : ''}
        `}
        onChange={handleChange}
        {...props}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {(error || helperText) && (
        <p className={`mt-1 text-sm ${error ? 'text-danger-500' : 'text-gray-400'}`}>
          {error || helperText}
        </p>
      )}
    </div>
  );
};

export default Select; 
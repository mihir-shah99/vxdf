import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  title?: string;
  subtitle?: string;
  footer?: React.ReactNode;
}

const Card: React.FC<CardProps> = ({
  children,
  className = '',
  title,
  subtitle,
  footer,
}) => {
  return (
    <div className={`bg-gray-700 rounded-lg shadow-lg ${className}`}>
      {(title || subtitle) && (
        <div className="px-6 py-4 border-b border-gray-600">
          {title && <h3 className="text-lg font-semibold text-white">{title}</h3>}
          {subtitle && <p className="mt-1 text-sm text-gray-400">{subtitle}</p>}
        </div>
      )}
      <div className="p-6">{children}</div>
      {footer && (
        <div className="px-6 py-4 border-t border-gray-600 bg-gray-800/50 rounded-b-lg">
          {footer}
        </div>
      )}
    </div>
  );
};

export default Card; 
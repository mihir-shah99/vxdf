import React, { useEffect } from 'react';
import { createPortal } from 'react-dom';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  footer,
  size = 'md',
}) => {
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
      document.body.style.overflow = 'hidden';
    }

    return () => {
      document.removeEventListener('keydown', handleEscape);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const sizeClasses = {
    sm: 'max-w-sm',
    md: 'max-w-md',
    lg: 'max-w-lg',
    xl: 'max-w-xl',
  };

  return createPortal(
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-screen items-center justify-center p-4">
        <div
          className="fixed inset-0 bg-black bg-opacity-50 transition-opacity"
          onClick={onClose}
        />

        <div
          className={`
            relative bg-gray-800 rounded-lg shadow-xl
            ${sizeClasses[size]} w-full
          `}
        >
          {title && (
            <div className="px-6 py-4 border-b border-gray-700">
              <h3 className="text-lg font-semibold text-white">{title}</h3>
            </div>
          )}

          <div className="px-6 py-4">{children}</div>

          {footer && (
            <div className="px-6 py-4 border-t border-gray-700 bg-gray-900/50 rounded-b-lg">
              {footer}
            </div>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
};

export default Modal; 
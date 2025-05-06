import React, { useState, useRef, useEffect } from 'react';

interface DropdownItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
  disabled?: boolean;
  onClick?: () => void;
}

interface DropdownProps {
  trigger: React.ReactNode;
  items: DropdownItem[];
  align?: 'left' | 'right';
  className?: string;
}

const Dropdown: React.FC<DropdownProps> = ({
  trigger,
  items,
  align = 'left',
  className = '',
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleItemClick = (item: DropdownItem) => {
    if (!item.disabled) {
      item.onClick?.();
      setIsOpen(false);
    }
  };

  return (
    <div className={`relative inline-block ${className}`} ref={dropdownRef}>
      <div onClick={() => setIsOpen(!isOpen)}>{trigger}</div>

      {isOpen && (
        <div
          className={`
            absolute z-50 mt-2 w-48 rounded-md shadow-lg bg-gray-800 ring-1 ring-black ring-opacity-5
            ${align === 'right' ? 'right-0' : 'left-0'}
          `}
        >
          <div
            className="py-1"
            role="menu"
            aria-orientation="vertical"
            aria-labelledby="options-menu"
          >
            {items.map((item) => (
              <button
                key={item.id}
                onClick={() => handleItemClick(item)}
                className={`
                  w-full text-left px-4 py-2 text-sm
                  ${
                    item.disabled
                      ? 'text-gray-500 cursor-not-allowed'
                      : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                  }
                `}
                role="menuitem"
                disabled={item.disabled}
              >
                <div className="flex items-center">
                  {item.icon && <span className="mr-3">{item.icon}</span>}
                  {item.label}
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default Dropdown; 
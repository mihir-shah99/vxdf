import React, { useState, useRef, useEffect } from 'react';

interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactNode;
  position?: 'top' | 'right' | 'bottom' | 'left';
  delay?: number;
}

const Tooltip: React.FC<TooltipProps> = ({
  content,
  children,
  position = 'top',
  delay = 200,
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [coords, setCoords] = useState({ x: 0, y: 0 });
  const triggerRef = useRef<HTMLDivElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  let timeout: NodeJS.Timeout;

  const updatePosition = () => {
    if (!triggerRef.current || !tooltipRef.current) return;

    const trigger = triggerRef.current.getBoundingClientRect();
    const tooltip = tooltipRef.current.getBoundingClientRect();

    const positions = {
      top: {
        x: trigger.left + (trigger.width - tooltip.width) / 2,
        y: trigger.top - tooltip.height - 8,
      },
      right: {
        x: trigger.right + 8,
        y: trigger.top + (trigger.height - tooltip.height) / 2,
      },
      bottom: {
        x: trigger.left + (trigger.width - tooltip.width) / 2,
        y: trigger.bottom + 8,
      },
      left: {
        x: trigger.left - tooltip.width - 8,
        y: trigger.top + (trigger.height - tooltip.height) / 2,
      },
    };

    setCoords(positions[position]);
  };

  const handleMouseEnter = () => {
    timeout = setTimeout(() => {
      setIsVisible(true);
      updatePosition();
    }, delay);
  };

  const handleMouseLeave = () => {
    clearTimeout(timeout);
    setIsVisible(false);
  };

  useEffect(() => {
    if (isVisible) {
      updatePosition();
      window.addEventListener('scroll', updatePosition);
      window.addEventListener('resize', updatePosition);
    }

    return () => {
      window.removeEventListener('scroll', updatePosition);
      window.removeEventListener('resize', updatePosition);
    };
  }, [isVisible]);

  return (
    <div
      ref={triggerRef}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      className="inline-block"
    >
      {children}
      {isVisible && (
        <div
          ref={tooltipRef}
          className="fixed z-50 px-3 py-2 text-sm text-white bg-gray-900 rounded-lg shadow-lg"
          style={{
            left: `${coords.x}px`,
            top: `${coords.y}px`,
          }}
        >
          {content}
        </div>
      )}
    </div>
  );
};

export default Tooltip; 
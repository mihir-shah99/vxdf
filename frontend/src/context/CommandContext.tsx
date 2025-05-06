import { createContext, useContext } from 'react';

interface CommandContextType {
  isOpen: boolean;
  setIsOpen: (isOpen: boolean) => void;
}

export const CommandContext = createContext<CommandContextType>({
  isOpen: false,
  setIsOpen: () => {},
});

export const useCommand = () => useContext(CommandContext); 
import { createContext, useContext, ReactNode } from 'react';

interface ThemeContextType {
  theme: 'light' | 'dark';
  setTheme: (theme: 'light' | 'dark') => void;
}

export const ThemeContext = createContext<ThemeContextType>({
  theme: 'dark',
  setTheme: () => {},
});

export const useTheme = () => useContext(ThemeContext); 
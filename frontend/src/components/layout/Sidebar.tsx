import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import styled from 'styled-components';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard,
  ShieldAlert,
  Search,
  Settings,
  ChevronLeft,
  ChevronRight,
  BarChart2,
  FileText,
  Code,
  Users,
} from 'lucide-react';

interface SidebarProps {
  isCollapsed: boolean;
  onToggle: () => void;
}

const SidebarContainer = styled(motion.aside)<{ $isCollapsed: boolean }>`
  width: ${({ $isCollapsed }) => ($isCollapsed ? '80px' : '280px')};
  height: 100vh;
  background: ${({ theme }) => theme.colors.background.secondary};
  border-right: 1px solid ${({ theme }) => theme.colors.border.primary};
  transition: width ${({ theme }) => theme.transitions.default};
  position: fixed;
  left: 0;
  top: 0;
  z-index: ${({ theme }) => theme.zIndices.docked};
  overflow: hidden;
`;

const SidebarHeader = styled.div`
  height: 64px;
  display: flex;
  align-items: center;
  padding: ${({ theme }) => theme.space[4]};
  border-bottom: 1px solid ${({ theme }) => theme.colors.border.primary};
`;

const Logo = styled.div`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.space[3]};
  color: ${({ theme }) => theme.colors.primary[400]};
  font-weight: ${({ theme }) => theme.fontWeights.bold};
  font-size: ${({ theme }) => theme.fontSizes.xl};
`;

const ToggleButton = styled.button`
  background: none;
  border: none;
  color: ${({ theme }) => theme.colors.text.secondary};
  cursor: pointer;
  padding: ${({ theme }) => theme.space[2]};
  border-radius: ${({ theme }) => theme.radii.full};
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all ${({ theme }) => theme.transitions.default};

  &:hover {
    background: ${({ theme }) => theme.colors.background.tertiary};
    color: ${({ theme }) => theme.colors.text.primary};
  }
`;

const NavSection = styled.div`
  padding: ${({ theme }) => theme.space[4]};
`;

const NavTitle = styled.h3<{ $isCollapsed: boolean }>`
  color: ${({ theme }) => theme.colors.text.secondary};
  font-size: ${({ theme }) => theme.fontSizes.sm};
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: ${({ theme }) => theme.space[3]};
  opacity: ${({ $isCollapsed }) => ($isCollapsed ? 0 : 1)};
  transition: opacity ${({ theme }) => theme.transitions.default};
`;

const NavList = styled.ul`
  list-style: none;
  padding: 0;
  margin: 0;
`;

const NavItem = styled(Link)<{ $isActive: boolean }>`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.space[3]};
  padding: ${({ theme }) => theme.space[3]};
  color: ${({ theme, $isActive }) =>
    $isActive ? theme.colors.primary[400] : theme.colors.text.secondary};
  text-decoration: none;
  border-radius: ${({ theme }) => theme.radii.md};
  transition: all ${({ theme }) => theme.transitions.default};
  background: ${({ theme, $isActive }) =>
    $isActive ? theme.colors.background.tertiary : 'transparent'};

  &:hover {
    background: ${({ theme }) => theme.colors.background.tertiary};
    color: ${({ theme }) => theme.colors.text.primary};
  }
`;

const NavIcon = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
`;

const NavText = styled.span<{ $isCollapsed: boolean }>`
  opacity: ${({ $isCollapsed }) => ($isCollapsed ? 0 : 1)};
  transition: opacity ${({ theme }) => theme.transitions.default};
  white-space: nowrap;
`;

const navItems = [
  {
    title: 'Main',
    items: [
      { icon: LayoutDashboard, label: 'Dashboard', path: '/' },
      { icon: ShieldAlert, label: 'Findings', path: '/findings' },
      { icon: Search, label: 'Analysis', path: '/analysis' },
    ],
  },
  {
    title: 'Tools',
    items: [
      { icon: BarChart2, label: 'Reports', path: '/reports' },
      { icon: FileText, label: 'Documents', path: '/documents' },
      { icon: Code, label: 'API', path: '/api' },
    ],
  },
  {
    title: 'Settings',
    items: [
      { icon: Users, label: 'Team', path: '/team' },
      { icon: Settings, label: 'Settings', path: '/settings' },
    ],
  },
];

export default function Sidebar({ isCollapsed, onToggle }: SidebarProps) {
  const location = useLocation();

  return (
    <SidebarContainer
      $isCollapsed={isCollapsed}
      initial={false}
      animate={{ width: isCollapsed ? 80 : 280 }}
    >
      <SidebarHeader>
        <Logo>
          <ShieldAlert size={24} />
          <AnimatePresence>
            {!isCollapsed && (
              <motion.span
                initial={{ opacity: 0, width: 0 }}
                animate={{ opacity: 1, width: 'auto' }}
                exit={{ opacity: 0, width: 0 }}
              >
                VXDF
              </motion.span>
            )}
          </AnimatePresence>
        </Logo>
        <ToggleButton onClick={onToggle}>
          {isCollapsed ? <ChevronRight size={20} /> : <ChevronLeft size={20} />}
        </ToggleButton>
      </SidebarHeader>

      {navItems.map((section) => (
        <NavSection key={section.title}>
          <NavTitle $isCollapsed={isCollapsed}>{section.title}</NavTitle>
          <NavList>
            {section.items.map((item) => (
              <NavItem
                key={item.path}
                to={item.path}
                $isActive={location.pathname === item.path}
              >
                <NavIcon>
                  <item.icon size={20} />
                </NavIcon>
                <NavText $isCollapsed={isCollapsed}>{item.label}</NavText>
              </NavItem>
            ))}
          </NavList>
        </NavSection>
      ))}
    </SidebarContainer>
  );
} 
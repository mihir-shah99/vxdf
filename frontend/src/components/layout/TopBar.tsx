import { useState } from 'react';
import styled from 'styled-components';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search,
  Bell,
  User,
  Settings,
  LogOut,
  ChevronDown,
  X,
} from 'lucide-react';

const TopBarContainer = styled.header`
  height: 64px;
  background: ${({ theme }) => theme.colors.background.secondary};
  border-bottom: 1px solid ${({ theme }) => theme.colors.border.primary};
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 ${({ theme }) => theme.space[6]};
  position: sticky;
  top: 0;
  z-index: ${({ theme }) => theme.zIndices.sticky};
`;

const SearchContainer = styled.div`
  position: relative;
  width: 400px;
`;

const SearchInput = styled.input`
  width: 100%;
  padding: ${({ theme }) => theme.space[3]} ${({ theme }) => theme.space[10]};
  background: ${({ theme }) => theme.colors.background.tertiary};
  border: 1px solid ${({ theme }) => theme.colors.border.primary};
  border-radius: ${({ theme }) => theme.radii.full};
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.fontSizes.sm};
  transition: all ${({ theme }) => theme.transitions.default};

  &:focus {
    outline: none;
    border-color: ${({ theme }) => theme.colors.primary[400]};
    box-shadow: 0 0 0 2px ${({ theme }) => theme.colors.primary[400]}20;
  }
`;

const SearchIcon = styled(Search)`
  position: absolute;
  left: ${({ theme }) => theme.space[3]};
  top: 50%;
  transform: translateY(-50%);
  color: ${({ theme }) => theme.colors.text.secondary};
  width: 20px;
  height: 20px;
`;

const ActionsContainer = styled.div`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.space[4]};
`;

const IconButton = styled.button`
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
  position: relative;

  &:hover {
    background: ${({ theme }) => theme.colors.background.tertiary};
    color: ${({ theme }) => theme.colors.text.primary};
  }
`;

const NotificationBadge = styled.span`
  position: absolute;
  top: 0;
  right: 0;
  background: ${({ theme }) => theme.colors.error[500]};
  color: white;
  font-size: ${({ theme }) => theme.fontSizes.xs};
  padding: 2px 6px;
  border-radius: ${({ theme }) => theme.radii.full};
  transform: translate(25%, -25%);
`;

const UserMenuButton = styled(IconButton)`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.space[2]};
  padding: ${({ theme }) => theme.space[2]} ${({ theme }) => theme.space[3]};
`;

const UserAvatar = styled.div`
  width: 32px;
  height: 32px;
  border-radius: ${({ theme }) => theme.radii.full};
  background: ${({ theme }) => theme.colors.primary[500]};
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-weight: ${({ theme }) => theme.fontWeights.medium};
`;

const UserName = styled.span`
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.fontSizes.sm};
`;

const MenuContainer = styled(motion.div)`
  position: absolute;
  top: 100%;
  right: 0;
  margin-top: ${({ theme }) => theme.space[2]};
  background: ${({ theme }) => theme.colors.background.secondary};
  border: 1px solid ${({ theme }) => theme.colors.border.primary};
  border-radius: ${({ theme }) => theme.radii.lg};
  box-shadow: ${({ theme }) => theme.shadows.lg};
  width: 240px;
  overflow: hidden;
`;

const MenuItem = styled.button`
  width: 100%;
  padding: ${({ theme }) => theme.space[3]};
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.space[3]};
  color: ${({ theme }) => theme.colors.text.primary};
  background: none;
  border: none;
  cursor: pointer;
  transition: all ${({ theme }) => theme.transitions.default};

  &:hover {
    background: ${({ theme }) => theme.colors.background.tertiary};
  }
`;

const MenuDivider = styled.div`
  height: 1px;
  background: ${({ theme }) => theme.colors.border.primary};
  margin: ${({ theme }) => theme.space[1]} 0;
`;

export default function TopBar() {
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <TopBarContainer>
      <SearchContainer>
        <SearchIcon size={20} />
        <SearchInput
          type="text"
          placeholder="Search findings, reports, or settings..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        {searchQuery && (
          <IconButton
            onClick={() => setSearchQuery('')}
            style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)' }}
          >
            <X size={16} />
          </IconButton>
        )}
      </SearchContainer>

      <ActionsContainer>
        <IconButton>
          <Bell size={20} />
          <NotificationBadge>3</NotificationBadge>
        </IconButton>

        <div style={{ position: 'relative' }}>
          <UserMenuButton onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}>
            <UserAvatar>MS</UserAvatar>
            <UserName>Mihir Shah</UserName>
            <ChevronDown size={16} />
          </UserMenuButton>

          <AnimatePresence>
            {isUserMenuOpen && (
              <MenuContainer
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
              >
                <MenuItem>
                  <User size={16} />
                  Profile
                </MenuItem>
                <MenuItem>
                  <Settings size={16} />
                  Settings
                </MenuItem>
                <MenuDivider />
                <MenuItem>
                  <LogOut size={16} />
                  Sign out
                </MenuItem>
              </MenuContainer>
            )}
          </AnimatePresence>
        </div>
      </ActionsContainer>
    </TopBarContainer>
  );
} 
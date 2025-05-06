import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import styled from 'styled-components';
import Sidebar from './Sidebar';
import TopBar from './TopBar';

const LayoutContainer = styled.div`
  display: flex;
  min-height: 100vh;
  background-color: ${({ theme }) => theme.colors.background.primary};
`;

const MainContent = styled.main<{ $isCollapsed: boolean }>`
  flex: 1;
  margin-left: ${({ $isCollapsed }) => ($isCollapsed ? '80px' : '280px')};
  transition: margin-left ${({ theme }) => theme.transitions.default};
  padding: ${({ theme }) => theme.space[6]};
  overflow-x: hidden;
`;

const Layout: React.FC = () => {
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);

  return (
    <LayoutContainer>
      <Sidebar
        isCollapsed={isSidebarCollapsed}
        onToggle={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
      />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <TopBar />
        <MainContent $isCollapsed={isSidebarCollapsed}>
          <Outlet />
        </MainContent>
      </div>
    </LayoutContainer>
  );
};

export default Layout; 
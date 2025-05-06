import { createGlobalStyle } from 'styled-components';

export const GlobalStyle = createGlobalStyle`
  /* Modern CSS Reset */
  *, *::before, *::after {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  /* Remove default margin */
  body,
  h1,
  h2,
  h3,
  h4,
  p,
  figure,
  blockquote,
  dl,
  dd {
    margin: 0;
  }

  /* Set core root defaults */
  html:focus-within {
    scroll-behavior: smooth;
  }

  /* Set core body defaults */
  body {
    min-height: 100vh;
    text-rendering: optimizeSpeed;
    line-height: 1.5;
    font-family: ${({ theme }) => theme.fonts.body};
    background-color: ${({ theme }) => theme.colors.background.primary};
    color: ${({ theme }) => theme.colors.text.primary};
  }

  /* Make images easier to work with */
  img,
  picture {
    max-width: 100%;
    display: block;
  }

  /* Inherit fonts for inputs and buttons */
  input,
  button,
  textarea,
  select {
    font: inherit;
  }

  /* Remove all animations, transitions and smooth scroll for people that prefer not to see them */
  @media (prefers-reduced-motion: reduce) {
    html:focus-within {
      scroll-behavior: auto;
    }
    
    *,
    *::before,
    *::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
      scroll-behavior: auto !important;
    }
  }

  /* Custom Scrollbar */
  ::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }

  ::-webkit-scrollbar-track {
    background: ${({ theme }) => theme.colors.background.secondary};
  }

  ::-webkit-scrollbar-thumb {
    background: ${({ theme }) => theme.colors.neutral[600]};
    border-radius: 4px;
  }

  ::-webkit-scrollbar-thumb:hover {
    background: ${({ theme }) => theme.colors.neutral[500]};
  }

  /* App Container */
  .app-container {
    display: flex;
    min-height: 100vh;
    background-color: ${({ theme }) => theme.colors.background.primary};
  }

  /* Main Content */
  .main-content {
    flex: 1;
    padding: ${({ theme }) => theme.space[6]};
    transition: margin-left ${({ theme }) => theme.transitions.default};
    overflow-x: hidden;

    &.expanded {
      margin-left: 80px;
    }
  }

  /* Command Palette */
  .command-palette {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 90%;
    max-width: 640px;
    max-height: 85vh;
    background: ${({ theme }) => theme.colors.background.secondary};
    border-radius: ${({ theme }) => theme.radii.lg};
    box-shadow: ${({ theme }) => theme.shadows['2xl']};
    padding: ${({ theme }) => theme.space[4]};
    z-index: ${({ theme }) => theme.zIndices.modal};
    border: 1px solid ${({ theme }) => theme.colors.border.primary};
  }

  /* Glassmorphism */
  .glass {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.1);
  }

  /* Animations */
  @keyframes fadeIn {
    from {
      opacity: 0;
    }
    to {
      opacity: 1;
    }
  }

  @keyframes slideIn {
    from {
      transform: translateY(20px);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }

  /* Utility Classes */
  .fade-in {
    animation: fadeIn 0.3s ease-in-out;
  }

  .slide-in {
    animation: slideIn 0.3s ease-in-out;
  }
`; 
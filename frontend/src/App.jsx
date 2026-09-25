import { Outlet, useLocation } from 'react-router-dom';
import TopNav from './components/TopNav.jsx';
import ErrorBoundary from './components/ErrorBoundary.jsx';
import CommandPalette from './components/CommandPalette.jsx';

export default function App() {
  const { pathname } = useLocation();
  return (
    <>
      <CommandPalette />
      <TopNav />
      {/* Keyed on the route: navigating away resets a caught error instead of
          leaving the operator stuck on a dead screen. */}
      <ErrorBoundary key={pathname}>
        <Outlet />
      </ErrorBoundary>
    </>
  );
}

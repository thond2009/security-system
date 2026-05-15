import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { MantineProvider, createTheme } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Notifications } from '@mantine/notifications';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Shell } from './components/Shell';
import Login from './pages/Login';
import Builds from './pages/Builds';
import BuildDetail from './pages/BuildDetail';
import Trends from './pages/Trends';

import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';
import '@mantine/dates/styles.css';

const theme = createTheme({
  primaryColor: 'blue',
  fontFamily: 'Inter, system-ui, sans-serif',
});

const queryClient = new QueryClient();

function ProtectedRoute() {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <Shell><Outlet /></Shell>;
}

export default function App() {
  return (
    <MantineProvider theme={theme}>
      <Notifications />
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route element={<ProtectedRoute />}>
                <Route path="/" element={<Builds />} />
                <Route path="/builds/:id" element={<BuildDetail />} />
                <Route path="/trends/:product" element={<Trends />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </AuthProvider>
      </QueryClientProvider>
    </MantineProvider>
  );
}

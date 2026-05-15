import { AppShell as MantineShell, Group, Title, Burger, NavLink as MNavLink, ActionIcon, Text } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { Link, useLocation } from 'react-router-dom';
import { IconHome, IconChartLine, IconLogout } from '@tabler/icons-react';
import { useAuth } from '../context/AuthContext';

export function Shell({ children }: { children: React.ReactNode }) {
  const [opened, { toggle }] = useDisclosure(false);
  const { logout, username } = useAuth();
  const location = useLocation();

  return (
    <MantineShell
      header={{ height: 56 }}
      navbar={{ width: 240, breakpoint: 'sm', collapsed: { mobile: !opened } }}
      padding="md"
    >
      <MantineShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group>
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Title order={3}>Security Dashboard</Title>
          </Group>
          <Group>
            <Text size="sm" c="dimmed">{username}</Text>
            <ActionIcon variant="subtle" onClick={logout} title="Logout">
              <IconLogout size={18} />
            </ActionIcon>
          </Group>
        </Group>
      </MantineShell.Header>

      <MantineShell.Navbar p="xs">
        <MNavLink
          component={Link}
          to="/"
          label="Builds"
          leftSection={<IconHome size={18} />}
          active={location.pathname === '/'}
          mb={4}
        />
        <MNavLink
          component={Link}
          to="/trends/all"
          label="Trends"
          leftSection={<IconChartLine size={18} />}
          active={location.pathname.startsWith('/trends')}
        />
      </MantineShell.Navbar>

      <MantineShell.Main>
        {children}
      </MantineShell.Main>
    </MantineShell>
  );
}

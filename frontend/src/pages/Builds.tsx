import { useState } from 'react';
import { Table, Badge, Group, Title, Card, SimpleGrid, Text, Loader, Select } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { BuildSummary } from '../api/types';

export default function Builds() {
  const [product, setProduct] = useState<string | null>(null);

  const { data: builds, isLoading } = useQuery({
    queryKey: ['builds', product],
    queryFn: () => {
      const params = product ? `?product_name=${encodeURIComponent(product)}` : '';
      return api.get<BuildSummary[]>(`/builds${params}`);
    },
    refetchInterval: 30000,
  });

  const products = [...new Set((builds || []).map(b => b.product_name))];

  if (isLoading) return <Loader m="xl" />;

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={2}>Builds</Title>
      </Group>

      <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }} mb="lg">
        <Card shadow="sm" padding="lg" radius="md" withBorder>
          <Text size="xs" c="dimmed" tt="uppercase">Total Builds</Text>
          <Text fw={700} size="xl">{builds?.length || 0}</Text>
        </Card>
        <Card shadow="sm" padding="lg" radius="md" withBorder>
          <Text size="xs" c="dimmed" tt="uppercase">Open Critical CVEs</Text>
          <Text fw={700} size="xl" c="red">
            {builds?.reduce((s, b) => s + b.critical_cves, 0) || 0}
          </Text>
        </Card>
        <Card shadow="sm" padding="lg" radius="md" withBorder>
          <Text size="xs" c="dimmed" tt="uppercase">Open High CVEs</Text>
          <Text fw={700} size="xl" c="orange">
            {builds?.reduce((s, b) => s + b.high_cves, 0) || 0}
          </Text>
        </Card>
        <Card shadow="sm" padding="lg" radius="md" withBorder>
          <Text size="xs" c="dimmed" tt="uppercase">Avg. Compliance</Text>
          <Text fw={700} size="xl" c="green">
            {builds?.length
              ? `${Math.round(builds.reduce((s, b) =>
                  s + (b.hardening_total ? (b.hardening_passes / b.hardening_total) * 100 : 0), 0
                ) / builds.length)}%`
              : '—'}
          </Text>
        </Card>
      </SimpleGrid>

      <Group mb="md">
        <Select
          placeholder="Filter by product"
          data={products.map(p => ({ value: p, label: p }))}
          value={product}
          onChange={setProduct}
          clearable
          searchable
        />
      </Group>

      <Table striped highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Product</Table.Th>
            <Table.Th>Image</Table.Th>
            <Table.Th>Build #</Table.Th>
            <Table.Th>Date</Table.Th>
            <Table.Th>Packages</Table.Th>
            <Table.Th>Critical</Table.Th>
            <Table.Th>High</Table.Th>
            <Table.Th>Medium</Table.Th>
            <Table.Th>Compliance</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {(builds || []).map(b => (
            <Table.Tr key={b.build_id}>
              <Table.Td>
                <Link to={`/builds/${b.build_id}`} style={{ textDecoration: 'none', fontWeight: 600 }}>
                  {b.product_name}
                </Link>
              </Table.Td>
              <Table.Td>{b.image_name}</Table.Td>
              <Table.Td>#{b.build_number}</Table.Td>
              <Table.Td>{new Date(b.build_ts).toLocaleDateString()}</Table.Td>
              <Table.Td>{b.total_packages}</Table.Td>
              <Table.Td>
                {b.critical_cves > 0 && <Badge color="red" size="sm">{b.critical_cves}</Badge>}
                {b.critical_cves === 0 && '—'}
              </Table.Td>
              <Table.Td>
                {b.high_cves > 0 && <Badge color="orange" size="sm">{b.high_cves}</Badge>}
                {b.high_cves === 0 && '—'}
              </Table.Td>
              <Table.Td>
                {b.medium_cves > 0 && <Badge color="yellow" size="sm">{b.medium_cves}</Badge>}
                {b.medium_cves === 0 && '—'}
              </Table.Td>
              <Table.Td>
                {b.hardening_total > 0 ? (
                  <Badge
                    color={b.hardening_passes / b.hardening_total >= 0.8 ? 'green' : 'red'}
                    size="sm"
                  >
                    {Math.round((b.hardening_passes / b.hardening_total) * 100)}%
                  </Badge>
                ) : '—'}
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </>
  );
}

import { useState } from 'react';
import { Group, Title, Select, SimpleGrid, Card, Text, Loader, Paper } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useParams } from 'react-router-dom';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import { api } from '../api/client';
import type { BuildSummary, TrendPoint } from '../api/types';

export default function Trends() {
  const { product: paramProduct } = useParams<{ product: string }>();
  const [product, setProduct] = useState(paramProduct === 'all' ? '' : (paramProduct || ''));
  const [days] = useState(90);

  const { data: builds } = useQuery({
    queryKey: ['builds', product],
    queryFn: () => {
      const params = product ? `?product_name=${encodeURIComponent(product)}` : '';
      return api.get<BuildSummary[]>(`/builds${params}`);
    },
  });

  const selectedProduct = product || (builds?.[0]?.product_name || '');

  const { data: cveTrends } = useQuery({
    queryKey: ['cve-trends', selectedProduct, days],
    queryFn: () => api.get<TrendPoint[]>(`/products/${selectedProduct}/trends/cves?days=${days}`),
    enabled: !!selectedProduct,
  });

  const { data: complianceTrends } = useQuery({
    queryKey: ['compliance-trends', selectedProduct, days],
    queryFn: () => api.get<TrendPoint[]>(`/products/${selectedProduct}/trends/compliance?days=${days}`),
    enabled: !!selectedProduct,
  });

  const products = [...new Set((builds || []).map(b => b.product_name))];
  const selectedBuild = builds?.find(b => b.product_name === selectedProduct);

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={2}>Trends & Analytics</Title>
        <Select
          placeholder="Select product"
          data={products.map(p => ({ value: p, label: p }))}
          value={selectedProduct}
          onChange={p => setProduct(p || '')}
          searchable
        />
      </Group>

      {!selectedProduct && <Text c="dimmed">Select a product to view trends.</Text>}

      {selectedProduct && (
        <SimpleGrid cols={{ base: 1, md: 2 }} mb="lg">
          <Card shadow="sm" padding="lg" radius="md" withBorder>
            <Text size="xs" c="dimmed" tt="uppercase" mb="xs">CVE Trend</Text>
            {cveTrends ? (
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={cveTrends}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="build_number" label={{ value: 'Build #', position: 'insideBottom', offset: -5 }} />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Line type="monotone" dataKey="value" stroke="#e03131" name="New CVEs" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            ) : <Loader />}
          </Card>

          <Card shadow="sm" padding="lg" radius="md" withBorder>
            <Text size="xs" c="dimmed" tt="uppercase" mb="xs">Compliance Trend</Text>
            {complianceTrends ? (
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={complianceTrends}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="build_number" label={{ value: 'Build #', position: 'insideBottom', offset: -5 }} />
                  <YAxis domain={[0, 100]} />
                  <Tooltip formatter={(v) => `${v}%`} />
                  <Line type="monotone" dataKey="value" stroke="#2f9e44" name="Compliance %" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            ) : <Loader />}
          </Card>
        </SimpleGrid>
      )}

      {selectedBuild && (
        <Card shadow="sm" padding="lg" radius="md" withBorder>
          <Text size="xs" c="dimmed" tt="uppercase" mb="xs">
            Current CVE Breakdown — {selectedProduct}
          </Text>
          <SimpleGrid cols={{ base: 2, md: 4 }}>
            <Paper p="sm" withBorder>
              <Text size="xs" c="dimmed">Critical</Text>
              <Text fw={700} size="lg" c="red">{selectedBuild.critical_cves}</Text>
            </Paper>
            <Paper p="sm" withBorder>
              <Text size="xs" c="dimmed">High</Text>
              <Text fw={700} size="lg" c="orange">{selectedBuild.high_cves}</Text>
            </Paper>
            <Paper p="sm" withBorder>
              <Text size="xs" c="dimmed">Medium</Text>
              <Text fw={700} size="lg" c="yellow">{selectedBuild.medium_cves}</Text>
            </Paper>
            <Paper p="sm" withBorder>
              <Text size="xs" c="dimmed">All Open</Text>
              <Text fw={700} size="lg">{selectedBuild.total_open_cves}</Text>
            </Paper>
          </SimpleGrid>
        </Card>
      )}
    </>
  );
}

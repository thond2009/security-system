import { useParams, Link } from 'react-router-dom';
import { Tabs, Table, Badge, Group, Title, Text, Card, Loader, Select, Textarea, Button, Modal, Paper, Grid } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../api/client';
import type { Build, CVEFinding, HardeningResult, HardeningRule } from '../api/types';

const severityColors: Record<string, string> = {
  CRITICAL: 'red', HIGH: 'orange', MEDIUM: 'yellow', LOW: 'blue',
};

const statusColors: Record<string, string> = {
  new: 'red', affected: 'orange', false_positive: 'gray',
  not_applicable: 'gray', waived: 'yellow', mitigated: 'teal', fixed: 'green',
};

export default function BuildDetail() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const [cveFilter, setCveFilter] = useState<string | null>(null);
  const [selectedCve, setSelectedCve] = useState<CVEFinding | null>(null);
  const [opened, { open, close }] = useDisclosure(false);
  const [triageStatus, setTriageStatus] = useState('');
  const [triageNotes, setTriageNotes] = useState('');

  const { data: build } = useQuery({
    queryKey: ['build', id],
    queryFn: () => api.get<Build>(`/builds/${id}`),
    enabled: !!id,
  });

  const { data: cves } = useQuery({
    queryKey: ['cves', id, cveFilter],
    queryFn: () => {
      const params = [];
      if (cveFilter) params.push(`status=${cveFilter}`);
      if (cveFilter && cveFilter !== 'all') params.push(`severity=${cveFilter.toUpperCase()}`);
      else if (cveFilter) params.push(`severity=${cveFilter.toUpperCase()}`);
      const qs = params.length ? `?${params.join('&')}` : '';
      return api.get<CVEFinding[]>(`/builds/${id}/cves${qs}`);
    },
    enabled: !!id,
  });

  const { data: hardening } = useQuery({
    queryKey: ['hardening', id],
    queryFn: () => api.get<HardeningResult[]>(`/builds/${id}/hardening`),
    enabled: !!id,
  });

  const { data: rules } = useQuery({
    queryKey: ['rules'],
    queryFn: () => api.get<HardeningRule[]>('/hardening/rules'),
    enabled: !!id,
  });

  const statusMutation = useMutation({
    mutationFn: ({ cveId, status, notes }: { cveId: string; status: string; notes: string }) =>
      api.patch<CVEFinding>(`/cves/${cveId}/status`, { status, triage_notes: notes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cves', id] });
      close();
    },
  });

  if (!build) return <Loader m="xl" />;

  const ruleMap = new Map((rules || []).map(r => [r.id, r]));
  const hrByCategory: Record<string, HardeningResult[]> = {};
  (hardening || []).forEach(hr => {
    const rule = ruleMap.get(hr.rule_id);
    const cat = rule?.category || 'unknown';
    if (!hrByCategory[cat]) hrByCategory[cat] = [];
    hrByCategory[cat].push(hr);
  });

  const handleTriage = (cve: CVEFinding) => {
    setSelectedCve(cve);
    setTriageStatus(cve.status);
    setTriageNotes(cve.triage_notes || '');
    open();
  };

  const submitTriage = () => {
    if (!selectedCve) return;
    statusMutation.mutate({ cveId: selectedCve.id, status: triageStatus, notes: triageNotes });
  };

  return (
    <>
      <Group mb="md">
        <Link to="/" style={{ textDecoration: 'none', color: 'inherit' }}>
          <Text size="sm" c="dimmed">← Back to builds</Text>
        </Link>
      </Group>

      <Title order={2} mb="md">
        {build.product_name} — {build.image_name} #{build.build_number}
      </Title>

      <Grid mb="lg">
        <Grid.Col span={{ base: 6, md: 3 }}>
          <Text size="xs" c="dimmed">Machine</Text>
          <Text size="sm">{build.machine}</Text>
        </Grid.Col>
        <Grid.Col span={{ base: 6, md: 3 }}>
          <Text size="xs" c="dimmed">Distro</Text>
          <Text size="sm">{build.distro} {build.distro_version || ''}</Text>
        </Grid.Col>
        <Grid.Col span={{ base: 6, md: 3 }}>
          <Text size="xs" c="dimmed">Yocto Version</Text>
          <Text size="sm">{build.yocto_version || '—'}</Text>
        </Grid.Col>
        <Grid.Col span={{ base: 6, md: 3 }}>
          <Text size="xs" c="dimmed">Build Date</Text>
          <Text size="sm">{new Date(build.build_ts).toLocaleString()}</Text>
        </Grid.Col>
      </Grid>

      <Tabs defaultValue="cves">
        <Tabs.List>
          <Tabs.Tab value="cves">CVEs ({(cves || []).length})</Tabs.Tab>
          <Tabs.Tab value="hardening">Hardening ({hardening?.length || 0})</Tabs.Tab>
          <Tabs.Tab value="info">Build Info</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="cves" pt="md">
          <Group mb="sm">
            <Select
              placeholder="Filter by status/severity"
              data={[
                { value: 'new', label: 'New' },
                { value: 'affected', label: 'Affected' },
                { value: 'waived', label: 'Waived' },
                { value: 'false_positive', label: 'False Positive' },
                { value: 'fixed', label: 'Fixed' },
                { value: 'CRITICAL', label: 'Critical severity' },
                { value: 'HIGH', label: 'High severity' },
              ]}
              value={cveFilter}
              onChange={setCveFilter}
              clearable
            />
          </Group>

          <Table striped highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>CVE</Table.Th>
                <Table.Th>Package</Table.Th>
                <Table.Th>Severity</Table.Th>
                <Table.Th>CVSS</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Fixed In</Table.Th>
                <Table.Th>Action</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {(cves || []).map(c => (
                <Table.Tr key={c.id}>
                  <Table.Td style={{ fontFamily: 'monospace', fontSize: 13 }}>
                    {c.cve_id}
                  </Table.Td>
                  <Table.Td>{c.package_id.substring(0, 8)}</Table.Td>
                  <Table.Td>
                    <Badge color={severityColors[c.severity || ''] || 'gray'} size="sm">
                      {c.severity || '—'}
                    </Badge>
                  </Table.Td>
                  <Table.Td>{c.cvss_score ?? '—'}</Table.Td>
                  <Table.Td>
                    <Badge color={statusColors[c.status] || 'gray'} size="sm">
                      {c.status}
                    </Badge>
                  </Table.Td>
                  <Table.Td style={{ fontFamily: 'monospace', fontSize: 12 }}>
                    {c.fixed_version || '—'}
                  </Table.Td>
                  <Table.Td>
                    <Button size="xs" variant="light" onClick={() => handleTriage(c)}>
                      Triage
                    </Button>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Tabs.Panel>

        <Tabs.Panel value="hardening" pt="md">
          {Object.entries(hrByCategory).map(([cat, results]) => {
            const pass = results.filter(r => r.status === 'PASS').length;
            const fail = results.filter(r => r.status === 'FAIL').length;
            const total = results.length;
            return (
              <Card key={cat} shadow="sm" padding="md" radius="md" withBorder mb="sm">
                <Group justify="space-between" mb="xs">
                  <Title order={5} tt="capitalize">{cat.replace(/-/g, ' ')}</Title>
                  <Badge color={fail === 0 ? 'green' : 'red'} size="lg">
                    {pass}/{total} ({Math.round((pass / total) * 100)}%)
                  </Badge>
                </Group>
                <Table>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Rule</Table.Th>
                      <Table.Th>Status</Table.Th>
                      <Table.Th>Message</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {results.map(r => {
                      const rule = ruleMap.get(r.rule_id);
                      return (
                        <Table.Tr key={r.id}>
                          <Table.Td>{rule?.title || r.rule_id}</Table.Td>
                          <Table.Td>
                            <Badge color={r.status === 'PASS' ? 'green' : r.status === 'FAIL' ? 'red' : 'yellow'} size="sm">
                              {r.status}
                            </Badge>
                          </Table.Td>
                          <Table.Td style={{ fontSize: 12 }}>{r.message || '—'}</Table.Td>
                        </Table.Tr>
                      );
                    })}
                  </Table.Tbody>
                </Table>
              </Card>
            );
          })}
        </Tabs.Panel>

        <Tabs.Panel value="info" pt="md">
          <Paper p="md" withBorder>
            <pre style={{ fontSize: 12, overflow: 'auto' }}>
              {JSON.stringify(build, null, 2)}
            </pre>
          </Paper>
        </Tabs.Panel>
      </Tabs>

      <Modal opened={opened} onClose={close} title={`Triage ${selectedCve?.cve_id}`}>
        {selectedCve && (
          <>
            <Text size="sm" mb="md">{selectedCve.summary}</Text>
            <Select
              label="Status"
              data={[
                { value: 'affected', label: 'Affected' },
                { value: 'false_positive', label: 'False Positive' },
                { value: 'not_applicable', label: 'Not Applicable' },
                { value: 'waived', label: 'Waived' },
                { value: 'fixed', label: 'Fixed' },
                { value: 'mitigated', label: 'Mitigated' },
              ]}
              value={triageStatus}
              onChange={v => setTriageStatus(v || '')}
              mb="sm"
            />
            <Textarea
              label="Notes"
              value={triageNotes}
              onChange={e => setTriageNotes(e.currentTarget.value)}
              minRows={3}
              mb="md"
            />
            <Button onClick={submitTriage} loading={statusMutation.isPending}>
              Save
            </Button>
          </>
        )}
      </Modal>
    </>
  );
}

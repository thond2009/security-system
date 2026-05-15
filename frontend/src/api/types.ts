export interface BuildSummary {
  build_id: string;
  product_name: string;
  image_name: string;
  build_number: number;
  build_ts: string;
  total_packages: number;
  critical_cves: number;
  high_cves: number;
  medium_cves: number;
  total_new_cves: number;
  total_open_cves: number;
  total_waived_cves: number;
  hardening_fails: number;
  hardening_passes: number;
  hardening_total: number;
}

export interface Build {
  id: string;
  image_name: string;
  product_name: string;
  machine: string;
  distro: string;
  distro_version: string | null;
  yocto_version: string | null;
  build_number: number;
  build_ts: string;
  ci_build_url: string | null;
  ci_build_id: string | null;
  total_packages: number;
  status: string;
  metadata_: Record<string, unknown> | null;
}

export interface CVEFinding {
  id: string;
  build_id: string;
  package_id: string;
  cve_id: string;
  osv_id: string | null;
  summary: string | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  affected_version: string | null;
  fixed_version: string | null;
  status: string;
  remediation: string | null;
  triage_notes: string | null;
  triaged_by: string | null;
  triaged_at: string | null;
  discovered_at: string;
  updated_at: string;
  aliases: string[] | null;
}

export interface HardeningResult {
  id: string;
  build_id: string;
  rule_id: string;
  status: 'PASS' | 'FAIL' | 'ERROR' | 'SKIPPED';
  message: string | null;
  evidence: Record<string, unknown> | null;
  evaluated_at: string;
}

export interface HardeningRule {
  id: string;
  rule_id: string;
  category: string;
  title: string;
  description: string | null;
  severity: string;
  eval_type: string;
  params: Record<string, unknown>;
  source: string | null;
  enabled: boolean;
}

export interface TrendPoint {
  date: string;
  build_number: number;
  value: number;
}

export interface BuildCompare {
  build_a: Build;
  build_b: Build;
  new_cves: CVEFinding[];
  resolved_cves: CVEFinding[];
}

'use strict';

const TEAMS = [
  { id: 'apps_engineering',  name: 'Apps & Engineering',        description: 'SAP, Microsoft, internal & client-facing apps' },
  { id: 'infrastructure',    name: 'Infrastructure',             description: 'Non-SCADA physical infrastructure, datacenters' },
  { id: 'network_operations',name: 'Network Operations Center',  description: 'ESRI mapping functions' },
  { id: 'scada',             name: 'SCADA',                      description: 'Physical hardware & remote management' },
  { id: 'service_desk',      name: 'Service Desk',               description: 'Fallback for unclassified threats' },
];

// keyed by threat_id
const tickets = {};

function getTeams() {
  return TEAMS.map(t => ({
    ...t,
    open: Object.values(tickets).filter(tk => tk.team_id === t.id && tk.status !== 'resolved').length,
    total: Object.values(tickets).filter(tk => tk.team_id === t.id).length,
  }));
}

function getTickets(teamId) {
  const all = Object.values(tickets);
  return teamId ? all.filter(t => t.team_id === teamId) : all;
}

function getTicket(id) {
  return tickets[id] || null;
}

function createTicket(payload) {
  const id = payload.threat_id || `tid-${Date.now()}`;
  tickets[id] = {
    threat_id: id,
    stix_id: payload.stix_id || null,
    title: payload.title,
    team_id: TEAMS.find(t => t.id === payload.asset_category) ? payload.asset_category : 'service_desk',
    asset_category_display: payload.asset_category_display || payload.asset_category,
    severity: payload.severity || 'medium',
    confidence: payload.confidence ?? null,
    summary: payload.summary || '',
    affected_assets: payload.affected_assets || [],
    cve_ids: payload.cve_ids || [],
    assessed_at: payload.assessed_at || new Date().toISOString(),
    mark_processed_url_hint: payload.mark_processed_url_hint || null,
    status: 'open',
    created_at: new Date().toISOString(),
    comments: [],
  };
  return tickets[id];
}

function updateTicket(id, changes) {
  const t = tickets[id];
  if (!t) return null;
  if (changes.status)   t.status   = changes.status;
  if (changes.severity) t.severity = changes.severity;
  if (changes.comment)  t.comments.push({ text: changes.comment, at: new Date().toISOString() });
  t.updated_at = new Date().toISOString();
  return t;
}

// ── seed data so the UI isn't empty on first load ──────────────────────────
const seeds = [
  { threat_id: 'seed-001', title: 'Schneider PLC Firmware RCE (CVE-2024-12345)', asset_category: 'scada',
    asset_category_display: 'SCADA', severity: 'critical', confidence: 0.97,
    summary: 'Remote code execution vulnerability in Schneider Electric Modicon M340 PLC firmware allows unauthenticated attackers to execute arbitrary code via crafted Modbus packets.',
    affected_assets: ['Schneider Modicon M340', 'Unity Pro XL'], cve_ids: ['CVE-2024-12345'],
    assessed_at: '2026-05-25T06:00:00Z', mark_processed_url_hint: 'POST /threats/seed-001/processed' },
  { threat_id: 'seed-002', title: 'Cisco IOS XE Privilege Escalation (CVE-2024-20399)', asset_category: 'network_operations',
    asset_category_display: 'Network Operations Center', severity: 'high', confidence: 0.91,
    summary: 'Authenticated privilege escalation in Cisco IOS XE allows a low-privilege user to gain root access via CLI injection.',
    affected_assets: ['Cisco Catalyst 9300', 'IOS XE 17.9.3'], cve_ids: ['CVE-2024-20399'],
    assessed_at: '2026-05-25T07:30:00Z', mark_processed_url_hint: 'POST /threats/seed-002/processed' },
  { threat_id: 'seed-003', title: 'Microsoft Exchange NTLM Relay (CVE-2024-21410)', asset_category: 'apps_engineering',
    asset_category_display: 'Apps & Engineering', severity: 'high', confidence: 0.88,
    summary: 'NTLM credential relay attack against Microsoft Exchange Server allows attackers to authenticate as any user.',
    affected_assets: ['Microsoft Exchange Server 2019', 'Exchange 2016 CU23'], cve_ids: ['CVE-2024-21410'],
    assessed_at: '2026-05-25T08:15:00Z', mark_processed_url_hint: 'POST /threats/seed-003/processed' },
  { threat_id: 'seed-004', title: 'VMware ESXi Heap Overflow (CVE-2024-22252)', asset_category: 'infrastructure',
    asset_category_display: 'Infrastructure', severity: 'critical', confidence: 0.95,
    summary: 'Heap overflow in VMware ESXi XHCI USB controller allows guest-to-host escape with local admin privileges on the VM.',
    affected_assets: ['VMware ESXi 8.0', 'vCenter Server 8.0'], cve_ids: ['CVE-2024-22252'],
    assessed_at: '2026-05-25T09:00:00Z', mark_processed_url_hint: 'POST /threats/seed-004/processed' },
  { threat_id: 'seed-005', title: 'Unclassified Threat — Juniper JunOS', asset_category: 'service_desk',
    asset_category_display: 'Service Desk', severity: 'medium', confidence: 0.61,
    summary: 'Low-confidence classification for Juniper JunOS advisory. Routed to Service Desk for manual triage.',
    affected_assets: ['Juniper SRX Series', 'JunOS 22.4R1'], cve_ids: ['CVE-2024-30385'],
    assessed_at: '2026-05-25T10:00:00Z', mark_processed_url_hint: 'POST /threats/seed-005/processed' },
];
seeds.forEach(createTicket);

module.exports = { getTeams, getTickets, getTicket, createTicket, updateTicket };

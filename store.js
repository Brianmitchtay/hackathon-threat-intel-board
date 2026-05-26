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
  const assessedAt = payload.assessed_at || new Date().toISOString();
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
    assessed_at: assessedAt,
    mark_processed_url_hint: payload.mark_processed_url_hint || null,
    status: 'open',
    // Use assessed_at as created_at for historical threats, otherwise use current time
    created_at: payload.assessed_at || new Date().toISOString(),
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
  // Old threats (>3 days) - should appear in aging threats
  { threat_id: 'seed-001', title: 'Schneider PLC Firmware RCE (CVE-2024-12345)', asset_category: 'scada',
    asset_category_display: 'SCADA', severity: 'critical', confidence: 0.97,
    summary: 'Remote code execution vulnerability in Schneider Electric Modicon M340 PLC firmware allows unauthenticated attackers to execute arbitrary code via crafted Modbus packets.',
    affected_assets: ['Schneider Modicon M340', 'Unity Pro XL'], cve_ids: ['CVE-2024-12345'],
    assessed_at: '2026-05-18T06:00:00Z', mark_processed_url_hint: 'POST /threats/seed-001/processed' },
  { threat_id: 'seed-002', title: 'Cisco IOS XE Privilege Escalation (CVE-2024-20399)', asset_category: 'network_operations',
    asset_category_display: 'Network Operations Center', severity: 'high', confidence: 0.91,
    summary: 'Authenticated privilege escalation in Cisco IOS XE allows a low-privilege user to gain root access via CLI injection.',
    affected_assets: ['Cisco Catalyst 9300', 'IOS XE 17.9.3'], cve_ids: ['CVE-2024-20399'],
    assessed_at: '2026-05-20T07:30:00Z', mark_processed_url_hint: 'POST /threats/seed-002/processed' },
  { threat_id: 'seed-003', title: 'Microsoft Exchange NTLM Relay (CVE-2024-21410)', asset_category: 'apps_engineering',
    asset_category_display: 'Apps & Engineering', severity: 'high', confidence: 0.88,
    summary: 'NTLM credential relay attack against Microsoft Exchange Server allows attackers to authenticate as any user.',
    affected_assets: ['Microsoft Exchange Server 2019', 'Exchange 2016 CU23'], cve_ids: ['CVE-2024-21410'],
    assessed_at: '2026-05-25T08:15:00Z', mark_processed_url_hint: 'POST /threats/seed-003/processed' },
  { threat_id: 'seed-004', title: 'VMware ESXi Heap Overflow (CVE-2024-22252)', asset_category: 'infrastructure',
    asset_category_display: 'Infrastructure', severity: 'critical', confidence: 0.95,
    summary: 'Heap overflow in VMware ESXi XHCI USB controller allows guest-to-host escape with local admin privileges on the VM.',
    affected_assets: ['VMware ESXi 8.0', 'vCenter Server 8.0'], cve_ids: ['CVE-2024-22252'],
    assessed_at: '2026-05-19T09:00:00Z', mark_processed_url_hint: 'POST /threats/seed-004/processed' },
  { threat_id: 'seed-005', title: 'Unclassified Threat — Juniper JunOS', asset_category: 'service_desk',
    asset_category_display: 'Service Desk', severity: 'medium', confidence: 0.61,
    summary: 'Low-confidence classification for Juniper JunOS advisory. Routed to Service Desk for manual triage.',
    affected_assets: ['Juniper SRX Series', 'JunOS 22.4R1'], cve_ids: ['CVE-2024-30385'],
    assessed_at: '2026-05-25T10:00:00Z', mark_processed_url_hint: 'POST /threats/seed-005/processed' },

  // Additional threats - variety of ages and severities
  { threat_id: 'seed-006', title: 'Apache Log4j Remote Code Execution (CVE-2024-44556)', asset_category: 'apps_engineering',
    asset_category_display: 'Apps & Engineering', severity: 'critical', confidence: 0.99,
    summary: 'Critical remote code execution vulnerability in Apache Log4j library affecting multiple Java applications.',
    affected_assets: ['Internal Portal', 'Customer API Gateway', 'Analytics Platform'], cve_ids: ['CVE-2024-44556'],
    assessed_at: '2026-05-17T14:20:00Z', mark_processed_url_hint: 'POST /threats/seed-006/processed' },

  { threat_id: 'seed-007', title: 'Dell PowerEdge BIOS Authentication Bypass', asset_category: 'infrastructure',
    asset_category_display: 'Infrastructure', severity: 'high', confidence: 0.87,
    summary: 'Authentication bypass in Dell PowerEdge server BIOS allows unauthorized firmware modifications.',
    affected_assets: ['Dell PowerEdge R740', 'Dell PowerEdge R640'], cve_ids: ['CVE-2024-33221'],
    assessed_at: '2026-05-21T11:45:00Z', mark_processed_url_hint: 'POST /threats/seed-007/processed' },

  { threat_id: 'seed-008', title: 'Siemens SIMATIC Denial of Service (CVE-2024-55443)', asset_category: 'scada',
    asset_category_display: 'SCADA', severity: 'high', confidence: 0.93,
    summary: 'Denial of service vulnerability in Siemens SIMATIC PLC can cause production line shutdown.',
    affected_assets: ['Siemens SIMATIC S7-1500', 'SIMATIC HMI Panels'], cve_ids: ['CVE-2024-55443'],
    assessed_at: '2026-05-19T16:30:00Z', mark_processed_url_hint: 'POST /threats/seed-008/processed' },

  { threat_id: 'seed-009', title: 'Oracle Database SQL Injection (CVE-2024-66778)', asset_category: 'apps_engineering',
    asset_category_display: 'Apps & Engineering', severity: 'medium', confidence: 0.82,
    summary: 'SQL injection vulnerability in Oracle Database Management system allows data exfiltration.',
    affected_assets: ['Oracle 19c', 'Oracle 21c'], cve_ids: ['CVE-2024-66778'],
    assessed_at: '2026-05-24T09:00:00Z', mark_processed_url_hint: 'POST /threats/seed-009/processed' },

  { threat_id: 'seed-010', title: 'Fortinet FortiGate SSL-VPN Buffer Overflow', asset_category: 'network_operations',
    asset_category_display: 'Network Operations Center', severity: 'critical', confidence: 0.96,
    summary: 'Buffer overflow in Fortinet FortiGate SSL-VPN allows pre-authentication remote code execution.',
    affected_assets: ['FortiGate 60F', 'FortiGate 100F', 'FortiGate 200F'], cve_ids: ['CVE-2024-77889'],
    assessed_at: '2026-05-16T08:00:00Z', mark_processed_url_hint: 'POST /threats/seed-010/processed' },

  { threat_id: 'seed-011', title: 'Windows Active Directory Certificate Services Escalation', asset_category: 'infrastructure',
    asset_category_display: 'Infrastructure', severity: 'high', confidence: 0.89,
    summary: 'Privilege escalation vulnerability in Windows AD CS allows domain admin compromise.',
    affected_assets: ['Windows Server 2019', 'Windows Server 2022'], cve_ids: ['CVE-2024-88990'],
    assessed_at: '2026-05-22T13:00:00Z', mark_processed_url_hint: 'POST /threats/seed-011/processed' },

  { threat_id: 'seed-012', title: 'Rockwell Automation FactoryTalk Hardcoded Credentials', asset_category: 'scada',
    asset_category_display: 'SCADA', severity: 'critical', confidence: 0.94,
    summary: 'Hardcoded credentials in Rockwell FactoryTalk View allow unauthorized access to industrial controls.',
    affected_assets: ['FactoryTalk View SE', 'FactoryTalk Linx'], cve_ids: ['CVE-2024-99001'],
    assessed_at: '2026-05-15T10:30:00Z', mark_processed_url_hint: 'POST /threats/seed-012/processed' },

  { threat_id: 'seed-013', title: 'Nginx Web Server Path Traversal', asset_category: 'apps_engineering',
    asset_category_display: 'Apps & Engineering', severity: 'medium', confidence: 0.76,
    summary: 'Path traversal vulnerability in Nginx web server allows file system access.',
    affected_assets: ['Nginx 1.24', 'Nginx 1.25'], cve_ids: ['CVE-2024-11223'],
    assessed_at: '2026-05-25T15:00:00Z', mark_processed_url_hint: 'POST /threats/seed-013/processed' },

  { threat_id: 'seed-014', title: 'Palo Alto Networks PAN-OS Command Injection', asset_category: 'network_operations',
    asset_category_display: 'Network Operations Center', severity: 'high', confidence: 0.92,
    summary: 'Command injection in Palo Alto PAN-OS web interface allows remote code execution.',
    affected_assets: ['PA-5220', 'PA-3220', 'VM-Series'], cve_ids: ['CVE-2024-22334'],
    assessed_at: '2026-05-18T12:00:00Z', mark_processed_url_hint: 'POST /threats/seed-014/processed' },

  { threat_id: 'seed-015', title: 'IBM Mainframe Security Bypass', asset_category: 'infrastructure',
    asset_category_display: 'Infrastructure', severity: 'low', confidence: 0.68,
    summary: 'Security bypass in IBM z/OS allows unauthorized access under specific conditions.',
    affected_assets: ['IBM z15', 'IBM z14'], cve_ids: ['CVE-2024-33445'],
    assessed_at: '2026-05-23T07:00:00Z', mark_processed_url_hint: 'POST /threats/seed-015/processed' },
];
seeds.forEach(createTicket);

module.exports = { getTeams, getTickets, getTicket, createTicket, updateTicket };

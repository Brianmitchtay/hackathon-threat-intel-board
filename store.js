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
  const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  return TEAMS.map(t => {
    const teamTickets = Object.values(tickets).filter(tk => tk.team_id === t.id);
    const incomingThisWeek = teamTickets.filter(tk => tk.created_at >= oneWeekAgo).length;
    const resolvedThisWeek = teamTickets.filter(tk => tk.status === 'resolved' && tk.updated_at && tk.updated_at >= oneWeekAgo).length;
    return {
      ...t,
      open: teamTickets.filter(tk => tk.status === 'open').length,
      in_progress: teamTickets.filter(tk => tk.status === 'in_progress').length,
      total: teamTickets.length,
      incoming_this_week: incomingThisWeek,
      resolved_this_week: resolvedThisWeek,
    };
  });
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
  if (changes.team_id) {
    t.team_id = changes.team_id;
    const team = TEAMS.find(tm => tm.id === changes.team_id);
    if (team) t.asset_category_display = team.name;
  }
  if (changes.comment)  t.comments.push({ text: changes.comment, at: new Date().toISOString() });
  t.updated_at = new Date().toISOString();
  return t;
}

// ── seed data mirroring real pipeline threats ─────────────────────────────
const seeds = [
  { threat_id: 'seed-001', title: 'ABB REF615 Protection Relay Setting Manipulation', asset_category: 'scada',
    asset_category_display: 'SCADA', severity: 'critical', confidence: 0.99,
    summary: 'ABB REF615 protection relays vulnerable to unauthorized modification of protection settings via unauthenticated IEC 61850 MMS write operations.',
    affected_assets: ['ABB REF615 protection relay', 'IEC 61850 MMS station bus', 'Substation automation systems'], cve_ids: ['CVE-2026-80041'],
    assessed_at: '2026-05-18T05:32:00Z' },

  { threat_id: 'seed-002', title: 'Palo Alto Panorama Management Server Auth Bypass', asset_category: 'network_operations',
    asset_category_display: 'Network Operations Center', severity: 'critical', confidence: 0.93,
    summary: 'Authentication bypass in Palo Alto Panorama management servers allows unauthenticated attackers to send crafted XML-API requests to gain admin access.',
    affected_assets: ['Palo Alto Panorama Management Server', 'Palo Alto NGFW fleet', 'XML-API management interface'], cve_ids: ['CVE-2026-80047'],
    assessed_at: '2026-05-20T05:32:00Z' },

  { threat_id: 'seed-003', title: 'Microsoft Entra ID Token Forging', asset_category: 'apps_engineering',
    asset_category_display: 'Apps & Engineering', severity: 'critical', confidence: 0.92,
    summary: 'Cryptographic weakness in Microsoft Entra ID token validation permits forging of access tokens for any tenant when specific key rotation conditions are met.',
    affected_assets: ['Microsoft Entra ID', 'Microsoft 365', 'Azure AD federated applications'], cve_ids: ['CVE-2026-80043'],
    assessed_at: '2026-05-25T05:32:00Z' },

  { threat_id: 'seed-004', title: 'Commvault Backup Server Remote Code Execution', asset_category: 'infrastructure',
    asset_category_display: 'Infrastructure', severity: 'critical', confidence: 0.82,
    summary: 'Unauthenticated remote code execution in Commvault Command Center via deserialization of untrusted data in the web service endpoint.',
    affected_assets: ['Commvault Command Center', 'Commvault Backup Server', 'Backup and disaster recovery infrastructure'], cve_ids: ['CVE-2026-80042'],
    assessed_at: '2026-05-19T05:32:00Z' },

  { threat_id: 'seed-005', title: 'Zscaler Private Access Client Privilege Escalation', asset_category: 'network_operations',
    asset_category_display: 'Network Operations Center', severity: 'medium', confidence: 0.72,
    summary: 'Local privilege escalation in Zscaler Private Access client for Windows via named pipe impersonation in the tunnel service.',
    affected_assets: ['Zscaler Private Access (ZPA) client for Windows', 'Network management workstations'], cve_ids: ['CVE-2026-80036'],
    assessed_at: '2026-05-25T05:32:00Z' },

  { threat_id: 'seed-006', title: 'GE Mark VIe Turbine Controller Unauthorized Command Execution', asset_category: 'scada',
    asset_category_display: 'SCADA', severity: 'critical', confidence: 0.99,
    summary: 'Unauthenticated command execution in GE Mark VIe turbine controllers where EGD protocol accepts arbitrary control commands without authentication.',
    affected_assets: ['GE Mark VIe turbine controllers', 'EGD protocol endpoints', 'Turbine control networks'], cve_ids: ['CVE-2026-80050'],
    assessed_at: '2026-05-17T05:32:00Z' },

  { threat_id: 'seed-007', title: 'NetApp ONTAP Storage Array RCE', asset_category: 'infrastructure',
    asset_category_display: 'Infrastructure', severity: 'critical', confidence: 0.92,
    summary: 'Remote code execution in NetApp ONTAP 9.x via crafted NFS requests when NFSv4.1 session trunking is enabled.',
    affected_assets: ['NetApp ONTAP 9.x storage arrays', 'NFS storage infrastructure', 'NFSv4.1 session trunking endpoints'], cve_ids: ['CVE-2026-80038'],
    assessed_at: '2026-05-21T05:32:00Z' },

  { threat_id: 'seed-008', title: 'Siemens WinCC OA SCADA HMI Path Traversal', asset_category: 'scada',
    asset_category_display: 'SCADA', severity: 'high', confidence: 0.98,
    summary: 'Path traversal in Siemens WinCC OA SCADA HMI web navigation interface allows reading of arbitrary server-side files including project databases.',
    affected_assets: ['Siemens WinCC OA SCADA HMI server', 'WinCC OA web navigation interface', 'SCADA project databases'], cve_ids: ['CVE-2026-80039'],
    assessed_at: '2026-05-19T05:32:00Z' },

  { threat_id: 'seed-009', title: 'Ivanti Neurons for ITSM SSRF to Internal Access', asset_category: 'apps_engineering',
    asset_category_display: 'Apps & Engineering', severity: 'high', confidence: 0.82,
    summary: 'Server-Side Request Forgery in Ivanti Neurons for ITSM exploitable through the integration connector component.',
    affected_assets: ['Ivanti Neurons for ITSM', 'ITSM integration connectors', 'Internal network services'], cve_ids: ['CVE-2026-80049'],
    assessed_at: '2026-05-24T05:32:00Z' },

  { threat_id: 'seed-010', title: 'Cisco Nexus 9000 ACI Fabric Controller Injection', asset_category: 'network_operations',
    asset_category_display: 'Network Operations Center', severity: 'high', confidence: 0.88,
    summary: 'Policy injection in Cisco Nexus 9000 ACI fabric controllers via crafted OpFlex protocol messages to inject unauthorized network policies.',
    affected_assets: ['Cisco Nexus 9000 series switches', 'Cisco ACI Fabric Controller', 'OpFlex protocol endpoints'], cve_ids: ['CVE-2026-80044'],
    assessed_at: '2026-05-18T05:32:00Z' },

  { threat_id: 'seed-011', title: 'Schweitzer Engineering SEL-751 Relay Firmware Upload', asset_category: 'scada',
    asset_category_display: 'SCADA', severity: 'critical', confidence: 0.98,
    summary: 'Arbitrary firmware upload to SEL-751 feeder protection relays via the rear serial port without authentication.',
    affected_assets: ['SEL-751 feeder protection relay', 'Distribution substation feeder protection', 'Substation serial engineering ports'], cve_ids: ['CVE-2026-80048'],
    assessed_at: '2026-05-16T05:32:00Z' },

  { threat_id: 'seed-012', title: 'Broadcom CA Automic Workload Automation RCE', asset_category: 'apps_engineering',
    asset_category_display: 'Apps & Engineering', severity: 'high', confidence: 0.75,
    summary: 'Remote Code Execution in Broadcom CA Automic Workload Automation via crafted job definitions submitted to the AWA agent.',
    affected_assets: ['Broadcom CA Automic Workload Automation', 'AWA Agent', 'Workload automation infrastructure'], cve_ids: ['CVE-2026-80046'],
    assessed_at: '2026-05-22T05:32:00Z' },

  { threat_id: 'seed-013', title: 'Schneider Electric PowerLogic ION9000 Auth Bypass', asset_category: 'scada',
    asset_category_display: 'SCADA', severity: 'high', confidence: 0.97,
    summary: 'Authentication bypass in Schneider Electric PowerLogic ION9000 power meter web interface allows unauthenticated modification of metering configurations.',
    affected_assets: ['Schneider Electric PowerLogic ION9000 power meters', 'Substation revenue metering systems'], cve_ids: ['CVE-2026-80037'],
    assessed_at: '2026-05-23T05:32:00Z' },

  { threat_id: 'seed-014', title: 'Beckhoff TwinCAT PLC Runtime Memory Corruption', asset_category: 'scada',
    asset_category_display: 'SCADA', severity: 'high', confidence: 0.97,
    summary: 'Memory corruption in Beckhoff TwinCAT 3 PLC runtime via malformed ADS protocol packets from the engineering network.',
    affected_assets: ['Beckhoff TwinCAT 3 PLC runtime', 'Engineering workstations', 'OT engineering VLAN'], cve_ids: ['CVE-2026-80045'],
    assessed_at: '2026-05-20T05:32:00Z' },

  { threat_id: 'seed-015', title: 'AWS Lambda Function URL Authentication Bypass', asset_category: 'infrastructure',
    asset_category_display: 'Infrastructure', severity: 'low', confidence: 0.72,
    summary: 'Misconfiguration pattern in AWS Lambda Function URLs allows IAM authentication bypass via crafted unsigned requests.',
    affected_assets: ['AWS Lambda Function URLs', 'AWS IAM authentication configurations'], cve_ids: ['CVE-2026-80040'],
    assessed_at: '2026-05-25T05:32:00Z' },
];
seeds.forEach(createTicket);

// Simulate team progress — mark some as in_progress and resolved
const statusUpdates = [
  // Apps & Engineering: 1 resolved, 1 in progress
  { id: 'seed-003', status: 'in_progress', comment: 'Entra ID token rotation initiated, monitoring for anomalies.' },
  { id: 'seed-009', status: 'resolved', comment: 'Ivanti ITSM connector patched, SSRF vector closed.' },

  // Infrastructure: 2 resolved, 1 in progress
  { id: 'seed-007', status: 'resolved', comment: 'NetApp ONTAP patched to 9.14P2, session trunking hardened.' },
  { id: 'seed-015', status: 'resolved', comment: 'Lambda function URLs reconfigured with IAM auth enforcement.' },
  { id: 'seed-004', status: 'in_progress', comment: 'Commvault team assessing patch compatibility with backup schedules.' },

  // Network Operations: 1 resolved, 1 in progress
  { id: 'seed-002', status: 'in_progress', comment: 'Palo Alto TAC engaged on Panorama auth bypass. Interim ACLs applied.' },
  { id: 'seed-010', status: 'resolved', comment: 'Nexus 9000 firmware updated, OpFlex policy injection fixed.' },

  // SCADA: 2 resolved, 1 in progress
  { id: 'seed-008', status: 'resolved', comment: 'WinCC OA web interface patched, path traversal confirmed fixed.' },
  { id: 'seed-013', status: 'resolved', comment: 'PowerLogic ION9000 firmware updated, auth bypass eliminated.' },
  { id: 'seed-001', status: 'in_progress', comment: 'ABB REF615 patch scheduled for next substation maintenance window.' },

  // Service Desk: 1 in progress
  { id: 'seed-005', status: 'in_progress', comment: 'Escalated to network operations for manual classification.' },
];

statusUpdates.forEach(u => {
  const t = tickets[u.id];
  if (t) {
    t.status = u.status;
    t.updated_at = new Date(Date.now() - Math.random() * 3 * 24 * 60 * 60 * 1000).toISOString();
    if (u.comment) t.comments.push({ text: u.comment, at: t.updated_at });
  }
});

module.exports = { getTeams, getTickets, getTicket, createTicket, updateTicket };

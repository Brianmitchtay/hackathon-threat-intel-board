'use strict';
const express = require('express');
const { getTeams, getTickets, getTicket, createTicket, updateTicket } = require('./store');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, ScanCommand, UpdateCommand } = require('@aws-sdk/lib-dynamodb');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const THREATS_TABLE = process.env.THREATS_TABLE || 'ThreatIntelStack-Threats60AEF56D-99IUR3JELUDY';
const ddbClient = DynamoDBDocumentClient.from(new DynamoDBClient({ region: 'us-east-1' }));

// ── health ─────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// ── teams ──────────────────────────────────────────────────────────────────
app.get('/api/teams', (_req, res) => res.json(getTeams()));

// ── tickets ────────────────────────────────────────────────────────────────
app.get('/api/tickets', (req, res) => res.json(getTickets(req.query.team)));

app.post('/api/tickets', (req, res) => {
  const ticket = createTicket(req.body);
  res.status(201).json(ticket);
});

// ── single ticket ──────────────────────────────────────────────────────────
app.get('/api/ticket/:id', (req, res) => {
  const t = getTicket(req.params.id);
  return t ? res.json(t) : res.status(404).json({ error: 'Not found' });
});

// ── update ticket ──────────────────────────────────────────────────────────
app.post('/api/update-ticket/:id', (req, res) => {
  const t = updateTicket(req.params.id, req.body);
  return t ? res.json(t) : res.status(404).json({ error: 'Not found' });
});

// ── pipeline data (DynamoDB) ──────────────────────────────────────────────
app.get('/api/pipeline/threats', async (_req, res) => {
  try {
    const result = await ddbClient.send(new ScanCommand({ TableName: THREATS_TABLE }));
    res.json(result.Items || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to read from DynamoDB', detail: err.message });
  }
});

app.post('/api/pipeline/feedback/:threatId', async (req, res) => {
  const { threatId } = req.params;
  const { new_team, original_team, reason } = req.body;
  try {
    await ddbClient.send(new UpdateCommand({
      TableName: THREATS_TABLE,
      Key: { threat_id: threatId },
      UpdateExpression: 'SET reassigned_to = :newTeam, reassigned_from = :origTeam, reassignment_reason = :reason, reassigned_at = :ts',
      ExpressionAttributeValues: {
        ':newTeam': new_team,
        ':origTeam': original_team,
        ':reason': reason || 'Manual reassignment from dashboard',
        ':ts': new Date().toISOString(),
      },
    }));
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update DynamoDB', detail: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Threat Intel Board running on :${PORT}`));

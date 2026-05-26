'use strict';
const express = require('express');
const { getTeams, getTickets, getTicket, createTicket, updateTicket } = require('./store');

const app = express();
app.use(express.json());
app.use(express.static('public'));

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Threat Intel Board running on :${PORT}`));

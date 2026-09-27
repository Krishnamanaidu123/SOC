# SOCX — Security Operations Center

A full-stack defensive SOC portfolio project: **ingest → detect → triage → investigate → incident → evidence → MITRE → report**.

## Features
- React/Vite SOC dashboard with responsive UI
- FastAPI backend
- PostgreSQL persistence
- Live alert updates over WebSocket + polling fallback
- Synthetic detection rules for SSH brute force, Windows 4625, port scanning, impossible-travel-style auth and suspicious PowerShell
- Severity/status workflow
- MITRE ATT&CK mapping
- IOC lookup
- Incident creation, analyst notes and evidence
- JSON, HTML and PDF incident reports
- Generic event ingestion and a simplified Wazuh JSON ingestion route

## Run with Docker

```bash
docker compose up --build
```

Then open:
- http://localhost:5173 — UI
- http://localhost:8000/docs — API docs
- http://localhost:8000/api/health — health check

Stop:

```bash
docker compose down
```

Remove database volume too:

```bash
docker compose down -v
```

## Useful test commands

Generate a synthetic alert from the UI, or send an event:

```bash
curl -X POST http://localhost:8000/api/ingest/event \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"ssh_failed_login","source_ip":"10.10.10.55","destination_ip":"10.10.10.20","username":"root","message":"Failed SSH authentication"}'
```

Windows event example:

```bash
curl -X POST http://localhost:8000/api/ingest/event \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"windows_event","event_id":4625,"source_ip":"10.10.10.56","username":"Administrator","message":"An account failed to log on"}'
```

Simplified Wazuh-style event:

```bash
curl -X POST http://localhost:8000/api/ingest/wazuh \
  -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-09-27T08:00:00Z","rule":{"id":"5710","description":"sshd authentication failed"},"agent":{"name":"kali-lab"},"data":{"srcip":"10.10.10.55","dstip":"10.10.10.20","srcuser":"root"},"full_log":"Failed password for root"}'
```

## Project workflow

1. Event arrives at `/api/ingest/event` or `/api/ingest/wazuh`.
2. The detector scores and classifies it.
3. The backend creates an alert and stores any observed IPs as local IOCs.
4. The UI receives the new alert through WebSocket.
5. Analyst investigates the alert and changes status.
6. Analyst creates an incident.
7. Analyst records notes and evidence.
8. MITRE technique stays attached to the case.
9. Analyst exports JSON/HTML/PDF reports.

## Portfolio positioning

Suggested GitHub title:

**SOCX — Security Operations Center & Incident Response Platform**

Suggested resume bullet:

> Built a full-stack SOC monitoring platform with React, FastAPI and PostgreSQL that ingests security events, applies detection rules, maps alerts to MITRE ATT&CK, manages incidents/evidence, and generates JSON, HTML and PDF reports.

## Important

This repository uses **synthetic lab telemetry** for demonstration. The detection rules are portfolio-oriented examples, not a complete production SIEM or ATT&CK implementation. For real deployment add authentication/RBAC, HTTPS, signed webhooks, rate limits, audit logging, secrets management, migrations and a message queue.

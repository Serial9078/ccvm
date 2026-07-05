# ADR-001: CCVM Architecture

## Status
Accepted

## Decision
CCVM uses a modular architecture:

- React frontend
- FastAPI backend
- PostgreSQL database
- Redis queue/cache
- Worker layer
- Scanner plugin system
- Gotenberg for PDF rendering

## Reason
The platform must support multiple scanner integrations such as Nuclei, Cisco, VMware, Microsoft, OpenVAS and Nessus imports.

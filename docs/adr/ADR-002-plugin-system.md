# ADR-002: Scanner Plugin System

## Status
Accepted

## Decision
All scanner integrations must implement the same plugin interface: `health`, `discover`, `scan` and `normalize`.

## Reason
CCVM must support Nuclei, Cisco, VMware, Microsoft and imports from commercial scanners without tightly coupling the backend to a single scanner.

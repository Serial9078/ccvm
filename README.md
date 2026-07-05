# CCVM - CloudCollab Vulnerability Manager

Sprint 0.4 "Phoenix" turns CCVM from a placeholder into a real product foundation.

## Included

- FastAPI backend with structured app layout
- SQLAlchemy models for customers, assets, scans, findings and plugins
- Repository and service layer
- React + Vite + TypeScript frontend
- Material UI application shell with sidebar navigation
- Dashboard, Customers and Assets pages
- Plugin SDK foundation
- Portainer-ready Docker Compose stack

## URLs

- Frontend: `http://SERVER-IP:8090`
- Backend health: `http://SERVER-IP:8088/health`
- Backend docs: `http://SERVER-IP:8088/docs`

## Deployment

Copy this release over `/opt/ccvm`, then update the `ccvm` stack in Portainer.

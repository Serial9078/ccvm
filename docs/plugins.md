# Plugin System

Each scanner is implemented as an isolated plugin.

Plugins

- nuclei
- nmap
- tls
- http
- ssh
- snmp
- vmware
- azure
- m365

Interface

scan(asset, profile)

returns

Findings


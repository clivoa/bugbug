---
name: internal-service-discovery
version: "1.0.0"
description: "Internal port scanning, service enumeration, SMB/AD/Certificate Services discovery — DISABLED BY DEFAULT"
risk_level: L2-L3
approval: "requires private-pentest or local-lab profile with explicit operator confirmation"
program_types: [private-pentest, local-lab]
source: "reviewed from , L3 catalog, and internal-recon catalog"
disabled_by_default: true
profile_required: [private-pentest, local-lab]
actions:
  - operator.internal.enum.service-ports
  - internal.impacket-secretsdump
  - internal.impacket-smbclient
  - internal.impacket-wmiexec
  - internal.impacket-psexec
  - internal.impacket-ntlmrelayx
  - internal.impacket-getnpusers
  - internal.impacket-getuserspns
  - internal.nxc-smb
  - internal.nxc-ldap
  - internal.nxc-ssh
  - internal.nxc-winrm
  - internal.nxc-mssql
  - internal.nxc-rdp
  - internal.nxc-ftp
  - internal.responder
  - internal.bloodhound-python
  - internal.certipy
  - internal.evil-winrm
  - internal.chisel
  - internal.ligolo
catalog: credential-l3-catalog.md
---

# Internal Service Discovery

**Code-owned catalog:** [../credential-l3-catalog.md](../credential-l3-catalog.md)

**⚠️ DISABLED BY DEFAULT.** L2-L3 actions for internal network service
enumeration, SMB/AD/Certificate Services discovery, and exploitation.

All L3 actions require:
- Confirmed authorization
- Asset in code-checked scope
- Every exact capability flag Boolean `true`
- Explicit operator confirmation

## L2 Actions (explicit approval)

| Action | Tool |
|--------|------|
| `operator.internal.enum.service-ports` | nmap |

## L3 Actions (operator responsibility)

All internal Impacket, NetExec (crackmapexec), Responder, BloodHound, Certipy,
evil-winrm, chisel, and ligolo-ng actions are available under ANY confirmed
engagement profile when authorization is confirmed and capability flags are on.
The operator bears full responsibility.

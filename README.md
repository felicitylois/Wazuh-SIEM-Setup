# Wazuh-SIEM-Setup
I implemented Wazuh, an open-source SIEM and XDR platform, to analyze logs, detect threats, and automate alerts inside a controlled lab environment.

## 🛠️ Tools & Technologies Used
- Wazuh Manager
- Wazuh Dashboard (Elastic Stack-based UI)
- Wazuh Agents (Linux & Windows)
- Ubuntu Server 22.04
- Windows 10 VM
- VirtualBox / VMware / Proxmox
- SSH & WinRM
- Filebeat / Auditd
- Sysmon for advanced Windows telemetry
- Threat Intelligence (OTX feeds)
- Suricata IDS (optional integration)

## 🎯 Project Goals
- Deploy a fully functional Wazuh SIEM environment
- Collect logs from Linux and Windows endpoints
- Detect malicious events using Wazuh rules, decoders, and MITRE ATT&CK mapping
- Perform vulnerability detection and file integrity monitoring
- Trigger real-time alerts and investigate security incidents
- Integrate external threat intelligence
- Document incident response steps and findings

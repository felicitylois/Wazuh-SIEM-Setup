# Wazuh-SIEM-Setup
I implemented Wazuh, an open-source SIEM and XDR platform, to analyze logs, detect threats, and automate alerts inside a controlled lab environment.
<img width="1400" height="818" alt="image" src="https://github.com/user-attachments/assets/6a8ce86b-9c0f-45d9-97b8-396dc6e6564d" />


## 🛠️ Tools & Technologies Used
- Wazuh Manager
- Wazuh Dashboard (Elastic Stack-based UI)
- Wazuh Agents (Linux & Windows)
- Ubuntu Server 22.04
- Virtualbox on Windows
- Suricata IDS (optional integration)

## 🎯 What This Lab Covers
- Deploy a fully functional Wazuh SIEM environment
- Collect logs from Linux and Windows endpoints
- Detect malicious events using Wazuh rules, decoders, and MITRE ATT&CK mapping
- Perform vulnerability detection and file integrity monitoring
- Trigger real-time alerts and investigate security incidents
- Integrate external threat intelligence
- Document incident response steps and findings

## Step 1: Setting Up the Wazuh SIEM Server on Ubuntu
I deployed the Wazuh manager on Ubuntu Server, which mirrors how SIEM infrastructure is commonly deployed in production environments.

First, I updated the system:
```
sudo apt update && sudo apt upgrade -y
```
Next, I downloaded and ran the official Wazuh installation script on Ubuntu terminal. This installer sets up the Wazuh manager, API, OpenSearch backend, and dashboard automatically.

<img width="1400" height="882" alt="image" src="https://github.com/user-attachments/assets/93d57f7a-6c23-4328-a0e5-e1e30ce7f19d" />

```
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

<img width="866" height="629" alt="image" src="https://github.com/user-attachments/assets/7a5b4d7c-e9ca-424e-b4e0-3fb3cc2cad65" />

The installation took some time, but once it completed, I had a fully operational SIEM backend. At the end of the process, Wazuh generated dashboard login credentials, which I saved for later access.

<img width="866" height="629" alt="image" src="https://github.com/user-attachments/assets/6aec995a-d8bc-4b81-9e6a-63ad16fef70a" />

At this stage, the SIEM infrastructure was live but had no endpoint data yet.

## Step 2: Logging Into the Wazuh Dashboard
Using a browser, I accessed the dashboard at:

```
https://<server-ip>
```

<img width="866" height="670" alt="image" src="https://github.com/user-attachments/assets/645fffe6-8116-4b22-b854-5904041011a4" />

Because the setup uses self signed certificates, the browser displayed a warning, which I acknowledged and proceeded past.

<img width="1400" height="882" alt="image" src="https://github.com/user-attachments/assets/3fe42cd2-f5a1-482b-b493-5c49ecd85fca" />

After logging in with the generated credentials, I could see:

- The Wazuh overview dashboard
- System health metrics
- Agent management sections
- Alert and event panels
This confirmed that the SIEM was functioning correctly. The next step was connecting endpoints so the system could begin collecting real security data.

<img width="1400" height="882" alt="image" src="https://github.com/user-attachments/assets/ad60e4f7-03f6-4eae-95a7-20832b0639a2" />

## Step 3: Setting Up a Linux Agent
To simulate endpoint monitoring, I first deployed a Linux agent.
<img width="1400" height="882" alt="image" src="https://github.com/user-attachments/assets/572bcac0-1b4d-436e-b0c6-068916c49199" />

From the Wazuh dashboard, I navigated to the agent management section and generated an installation command for a Linux endpoint. On the target Linux system, I ran:

<img width="1400" height="437" alt="image" src="https://github.com/user-attachments/assets/9a6219a5-391a-4fa1-b31d-c95287c619bb" />

```
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x.x-1_amd64.deb
sudo WAZUH_MANAGER="<server-ip>" dpkg -i wazuh-agent.deb
```

<img width="1400" height="437" alt="image" src="https://github.com/user-attachments/assets/665734d5-ebc9-4836-a2aa-bf5d63306a2a" />

Then I enabled and started the agent service:

```
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/ac453d2e-c251-41c9-8da7-cc8b7c1b29fe" />

Within seconds, the agent appeared as Active in the dashboard.

This step gave me hands on experience with endpoint onboarding, a common SOC responsibility.

<img width="1400" height="882" alt="image" src="https://github.com/user-attachments/assets/9d582607-7e1b-402a-b2e2-b7505f293fab" />

## Step 4: Exploring Linux Agent Security Data
Once the Linux agent connected, security data started flowing immediately.

From the dashboard, I was able to observe:

- Authentication events
- SSH login activity
- Failed login attempts
- File integrity monitoring alerts
- System level changes
- This was where the SIEM truly came to life. Actions that normally go unnoticed, such as logging in via SSH or modifying configuration files, were now visible as structured security events.

From a SOC perspective, this helped me understand how:

- Brute force attempts would surface through repeated authentication failures
- Unauthorized access attempts can be identified quickly
- Baseline system behavior can be distinguished from suspicious activity
- I explored alert severity levels, rule IDs, and timestamps to understand how Wazuh prioritizes and categorizes events.

<img width="1256" height="824" alt="image" src="https://github.com/user-attachments/assets/479ecde8-8a96-4954-9eee-a20eca04a65c" />

## Step 5: Setting Up a Windows Agent Using PowerShell
To expand coverage, I added a Windows endpoint, which is critical in most enterprise environments.

From the dashboard, I generated the Windows agent installer. On the Windows system, I opened PowerShell as Administrator and ran:

```
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.x.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="<server-ip>"
```

After installation, I started the service:

```
Start-Service WazuhSvc
```

The Windows agent appeared shortly afterward in the dashboard.

This step gave me experience deploying and managing Windows endpoints, including working with PowerShell and Windows services.








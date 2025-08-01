# SIEM (ELK Stack) Security Monitoring Lab

This project demonstrates the setup of a virtual Security Information and Event Management (SIEM) environment using the ELK Stack (Elasticsearch, Logstash, and Kibana) on Ubuntu Server. It simulates a basic Security Operations Center (SOC) scenario with log collection, attack simulation, and detection—all within a home lab environment running on VMWare.

## Project Overview

The goal of this project is to build a functional security monitoring lab that replicates a real-world SOC setup. This includes:
- A **SIEM server** (Ubuntu) running the full ELK Stack.
- Multiple **client machines** (Windows, Linux) sending system and security logs to the SIEM.
- A **Kali Linux attacker box** used to simulate realistic cyberattacks for detection and response.
- Visualization and query-based detection using **Kibana** dashboards.

## Table of Contents

- [Project Setup](#project-setup)
- [Architecture Diagram](#architecture-diagram)
- [Network Configuration](#network-configuration)
- [SIEM Installation and Configuration](#siem-installation-and-configuration)
- [Client Log Forwarding](#client-log-forwarding)
- [Simulated Attacks](#simulated-attacks)
- [Detection and Visualization](#detection-and-visualization)
- [Screenshots](#screenshots)
- [Conclusion](#conclusion)

## Project Setup

### Prerequisites

- **Oracle VMWare** (or VMware Workstation)
- **Ubuntu Server ISO** for ELK stack installation
- **Windows 10 ISO** for endpoint simulation
- **CentOS or Ubuntu Linux ISO** for Linux log source
- **Kali Linux ISO** for offensive testing

### VM Resources

| VM              | vCPU | RAM  | Storage | Role                              |
|------------------|------|------|---------|------------------------------------|
| Ubuntu ELK       | 2–4  | 4–8GB| 50GB    | SIEM: Elasticsearch, Logstash, Kibana |
| Windows 10       | 2    | 4GB  | 30GB    | Endpoint with Sysmon + Winlogbeat |
| CentOS (Linux)   | 1–2  | 2GB  | 20GB    | Logs from Filebeat/Auditbeat     |
| Kali Linux       | 2    | 2GB  | 30GB    | Simulated attacker (nmap, metasploit, etc.) |

## Architecture Diagram

The following diagram shows the virtual environment and log flow between machines:

![SIEM Lab Architecture](assets/SIEM_Lab_Architecture.png)

- **Ubuntu ELK Server** – `192.168.33.133`
- **CentOS Client** – `192.168.33.134`
- **Windows 10 Client** – `192.168.33.135`
- **Kali Linux Attacker** – `192.168.33.136`

All machines are connected via an **Internal Network** in VMWare to simulate an isolated corporate LAN.

## Network Configuration

Each VM is configured with a static IP on the same subnet (`192.168.33.0/24`) using the internal adapter in VMWare.

### IP Assignments

| VM              | IP Address       |
|------------------|------------------|
| Ubuntu ELK       | 192.168.33.133   |
| CentOS Client    | 192.168.33.134   |
| Windows 10 Client| 192.168.33.135   |
| Kali Linux       | 192.168.33.136   |

## SIEM Installation and Configuration

The Ubuntu server is used to install and configure the ELK stack.

### ELK Setup Process

1. **Install Elasticsearch** – stores and indexes log data.
2. **Install Logstash** – parses incoming logs from Beats agents.
3. **Install Kibana** – visualizes and queries logs.
4. **Configure Logstash pipelines** to accept logs from:
   - Winlogbeat (Windows)
   - Filebeat (Linux)
5. **Open Firewall ports**: 5044 (Beats), 5601 (Kibana UI), 9200 (Elasticsearch API)

## Client Log Forwarding

### Windows 10 (Sysmon + Winlogbeat)

1. Install **Sysmon** with the SwiftOnSecurity config.
2. Install **Winlogbeat** and configure output to Logstash on `192.168.33.133`.
3. Ensure Event IDs like 4688 (process creation) and 4625 (failed logon) are being captured.

### CentOS (Filebeat)

1. Install **Filebeat** and enable modules like `system`, `auth`, and `auditd`.
2. Configure Filebeat to forward logs to Logstash on the ELK server.

## Simulated Attacks

The Kali Linux box is used to simulate common attacker behaviors:

- **Brute force** (RDP, SSH)
- **Malicious PowerShell scripts**
- **Lateral movement** attempts
- **Reverse shells using msfvenom/metasploit**

These actions generate logs that are sent to the ELK server for detection and analysis.

## Detection and Visualization

Using **Kibana**, dashboards are built to visualize and detect suspicious behavior:

- Top failed login attempts
- Rare or suspicious process execution
- Unusual user activity by time or host
- MITRE ATT&CK mapping based on logs and detections

### Example Detections

| Event | Tool Used | Log Source | MITRE ID |
|-------|-----------|------------|----------|
| Brute Force (4625) | Winlogbeat | Windows Event Logs | T1110 |
| PowerShell Execution | Sysmon | Windows | T1059.001 |
| SSH login failure | Filebeat | Linux auth.log | T1021.004 |

## Screenshots

The following screenshots show components of the working lab:

### Kibana Dashboard

![Kibana Dashboards](assets/kibana_dashboard.png)
*Kibana showing failed login attempts over time and alert volume.*

### Logstash Pipeline

![Logstash Config](assets/logstash_pipeline.png)
*Logstash pipeline configuration receiving logs from Winlogbeat and Filebeat.*

### Simulated Brute Force Detection

![Brute Force Detection](assets/brute_force.png)
*Visualization of repeated failed login attempts from a simulated attack.*

## Conclusion

This project demonstrates a practical, hands-on SIEM setup that mimics real-world SOC workflows. By building a home lab using the ELK Stack and simulating attacks, I developed skills in log collection, parsing, dashboard creation, and threat detection. This environment provides a strong foundation for junior SOC analyst roles and ongoing security monitoring practice.

---

For questions or collaboration, feel free to connect or open an issue.
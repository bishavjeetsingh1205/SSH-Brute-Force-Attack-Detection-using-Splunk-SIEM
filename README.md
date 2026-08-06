
# 🛡️ SSH Brute-Force Attack Detection using Splunk SIEM

**Detecting and investigating SSH brute-force attacks with Splunk Enterprise, SPL, and MITRE ATT&CK mapping.**


## 📖 Table of Contents

- [Overview](#-overview)
- [Objectives](#-objectives)
- [Lab Environment](#-lab-environment)
- [Architecture](#-architecture)
- [Project Workflow](#-project-workflow)
- [Technologies Used](#-technologies-used)
- [Detection Queries](#-detection-queries)
- [Alert Rules](#-alert-rules)
- [Dashboard](#-dashboard)
- [Lookup Table](#-lookup-table)
- [Attack Simulation](#-attack-simulation)
- [Validation](#-validation)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Repository Structure](#-repository-structure)
- [Future Improvements](#-future-improvements)
- [Learning Outcomes](#-learning-outcomes)
- [Author](#-author)

---

## 🔎 Overview

This project demonstrates the detection of **SSH brute-force attacks** using **Splunk Enterprise**.

The lab environment consists of a **Kali Linux** attacker machine attempting SSH authentication attacks against an **Ubuntu Server** running **OpenSSH**. Authentication logs are collected from `/var/log/auth.log`, indexed into Splunk, and analyzed using custom SPL detection rules, dashboards, and alerts.

The project simulates real-world **SOC (Security Operations Center)** monitoring by detecting suspicious SSH authentication activity and generating alerts based on predefined detection rules.

---

## 🎯 Objectives

- [x] Monitor SSH authentication logs
- [x] Detect failed SSH login attempts
- [x] Detect successful SSH logins
- [x] Identify attacker IP addresses
- [x] Detect brute-force attacks
- [x] Detect username enumeration
- [x] Detect successful login after brute-force
- [x] Detect privileged account login from untrusted IPs
- [x] Visualize authentication activity using Splunk dashboards
- [x] Generate real-time security alerts

---

## 🧪 Lab Environment

| Component      | Description               |
|-----------------|---------------------------|
| **SIEM**        | Splunk Enterprise 10.0.8  |
| **Attacker**    | Kali Linux                |
| **Victim**      | Ubuntu Server             |
| **SSH Server**  | OpenSSH                   |
| **Hypervisor**  | VMware Workstation        |
| **Log Source**  | `/var/log/auth.log`       |

---

## 🏗️ Architecture

```
                  ┌───────────────────┐
                  │   Kali Linux VM   │
                  │    (Attacker)     │
                  └─────────┬─────────┘
                            │
                    SSH Attack Traffic
                            │
                            ▼
                  ┌───────────────────┐
                  │  Ubuntu Server VM │
                  │      OpenSSH      │
                  └─────────┬─────────┘
                            │
                     /var/log/auth.log
                            │
                            ▼
                  ┌───────────────────┐
                  │ Splunk Enterprise │
                  │       SIEM        │
                  └─────────┬─────────┘
                            │
        ┌──────────────┬───┴──────────┬─────────────────┐
        ▼              ▼               ▼                 ▼
  Detection Rules   Dashboards       Alerts       Investigation
```

---

## 🔄 Project Workflow

```
SSH Attack
    │
    ▼
Ubuntu Server (OpenSSH)
    │
    ▼
Authentication Logs (/var/log/auth.log)
    │
    ▼
Splunk Indexing (index=main)
    │
    ▼
SPL Detection Rules
    │
    ▼
Dashboards & Alerts
```

---

## 🧰 Technologies Used

- Splunk Enterprise 10.0.8
- Search Processing Language (SPL)
- Ubuntu Server
- Kali Linux
- OpenSSH
- VMware Workstation

---

## 🔍 Detection Queries

<details>
<summary><b>🩺 Health Check</b></summary>

- Verify data is being indexed

</details>

<details>
<summary><b>🧩 Core Detection Rules</b></summary>

- Detect failed SSH logins
- Detect successful SSH logins
- Find attacker IP addresses
- Find targeted usernames
- Detect possible brute-force attacks
- SSH authentication summary by host and attacker

</details>

<details>
<summary><b>📊 Dashboard Queries</b></summary>

- Count failed login attempts
- Failed logins over time
- Successful logins by user
- Top client source port analysis
- SSH authentication status distribution

</details>

<details>
<summary><b>🕵️ Investigation Queries</b></summary>

- View only SSH authentication logs
- View recent SSH events
- IP activity summary

</details>

> 📁 Full SPL queries are documented in [`queries/all_spl_queries.md`](queries/all_spl_queries.md)

---

## 🚨 Alert Rules

| # | Alert | Trigger Condition |
|---|-------|--------------------|
| 1 | **Possible Brute-Force Attack** | Same IP performs 5+ failed SSH logins within one minute |
| 2 | **Suspicious Successful Login After Failures** | Multiple failed logins from same IP, followed by a success within 5 minutes |
| 3 | **SSH Login Outside Business Hours** | Successful login occurs outside 09:00–18:00 |
| 4 | **Username Enumeration Attempt** | Same IP tries 3+ different usernames within 5 minutes |
| 5 | **Privileged Login from Untrusted IP** | Successful privileged account login from an IP not in the trusted allowlist |

---

## 📈 Dashboard

The Splunk dashboard includes:

- 📉 Total Failed Login Attempts
- ⏱️ Failed Logins Over Time
- ✅ Successful Logins by User
- 🔌 Top Client Source Ports
- 🥧 Authentication Status Distribution

<p align="center">
  <i>See <code>screenshots/dashboard.png</code> for a preview.</i>
</p>

---

## 📋 Lookup Table

The project uses a lookup table — **`trusted_ips.csv`** — to detect privileged logins from untrusted sources.

| Attacker_IP | Hostname | Owner | Role | Trusted |
|-------------|----------|-------|------|---------|
| x.x.x.x     | Kali     | Security Team | PenTester | Yes |

---

## 🎭 Attack Simulation

The following attack scenarios were simulated from the Kali Linux attacker machine:

- 🔓 SSH brute-force attack
- 🧑‍💻 Username enumeration
- ✅ Successful SSH login
- 🌙 Login outside business hours
- 👑 Privileged account login from an untrusted IP

---

## ✅ Validation

Each detection rule and alert was validated by generating the corresponding attack activity.

| Component | Status |
|-----------|:------:|
| Log ingestion | ✅ |
| Detection rules | ✅ |
| Dashboard visualizations | ✅ |
| Alert generation | ✅ |
| Lookup functionality | ✅ |

---

## 🗺️ MITRE ATT&CK Mapping

| Detection | MITRE Technique |
|-----------|------------------|
| Failed SSH Logins | `T1110` — Brute Force |
| Successful SSH Login | `T1078` — Valid Accounts |
| Brute Force | `T1110` |
| Username Enumeration | `T1110.001` |
| Privileged Login from Untrusted IP | `T1078` |
| Remote SSH Access | `T1133` |

---

## 📂 Repository Structure

```
SSH-Brute-Force-Detection-Splunk
│
├── README.md
├── LICENSE
│
├── queries/
│      all_spl_queries.md
│
├── lookups/
│      trusted_ips.csv
│
├── screenshots/
│      dashboard.png
│      brute_force_alert.png
│      successful_login.png
│      outside_business_hours.png
│      username_enumeration.png
│      privileged_login.png
│
├── docs/
│      setup.md
│      attack_simulation.md
│      validation.md
│
└── images/
       architecture.png
```

---

## 🚀 Future Improvements

- 📧 Email alert integration
- 🌐 Threat intelligence enrichment
- 📍 Geo-IP based detections
- ⚖️ Risk-based alerting
- 🏢 Splunk Enterprise Security integration
- 🤖 SOAR automation

---

## 🎓 Learning Outcomes

This project demonstrates practical SOC detection engineering skills including:

`Log Ingestion` · `SPL Development` · `Detection Engineering` · `Alert Creation` · `Dashboard Development` · `Threat Detection` · `Security Monitoring` · `MITRE ATT&CK Mapping` · `Investigation Workflows`

---

## 👤 Author

**Bishavjeet Singh Parmar**
B.Tech Computer Science and Engineering (Cyber Security)
Lovely Professional University

<p align="center">
  ⭐ If you found this project useful, consider giving it a star!
</p>

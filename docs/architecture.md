# ***Project Architecture***

> This document explains the architecture of the SSH Monitoring and Intrusion Detection System built using Kali Linux, Ubuntu Server, and Splunk Enterprise.



### **Architecture Diagram**


Kali Linux
      │
      │ SSH Attack
      ▼
Ubuntu Server
(OpenSSH)
      │
      │ Authentication Logs
      ▼
/var/log/auth.log
      │
      ▼
Splunk Enterprise
      │
      ├── SPL Queries
      ├── Dashboard
      ├── Alerts
      └── Investigation


\---



### **Components**



#### Kali Linux

Purpose: Simulates attacks.

Used for:

* Failed SSH login
* Successful SSH login
* SSH brute-force attacks
* Username enumeration
* Outside business-hours login
* Untrusted IP login testing

Tools:

* SSH client
* Hydra



\---



#### Ubuntu Server

Purpose: Target machine hosting OpenSSH.

Responsibilities:

* Accept SSH connections
* Authenticate users
* Generate authentication logs



\---



#### auth.log

Location:
`/var/log/auth.log`

Stores:

* Failed password
* Accepted password
* Invalid user
* Source IP
* Source Port
* Timestamp



\---



#### Splunk Enterprise

Purpose: SIEM platform.

Responsible for:

* Monitoring auth.log
* Indexing logs into `main`
* Running SPL queries
* Dashboard visualization
* Alert generation
* Investigation



\---



#### Data Flow

1. Kali launches SSH attacks.
2. Ubuntu records events in auth.log.
3. Splunk ingests auth.log.
4. Events are stored in index `main`.
5. SPL queries analyze events.
6. Dashboard visualizes activity.
7. Alerts notify suspicious behavior.
8. Analyst investigates.



\---



### **Architecture Summary**


Attack Simulation
      │
      ▼
Ubuntu OpenSSH
      │
      ▼
/var/log/auth.log
      │
      ▼
Splunk Data Input
      │
      ▼
Index = main
      │
      ▼
SPL Queries
      │
      ▼
Dashboard
      │
      ▼
Alerts
      │
      ▼
Investigation



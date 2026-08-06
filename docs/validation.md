# ***Validation Guide***

> This document describes the validation process followed to verify that all SPL queries, dashboard panels, and alert rules function correctly. Each validation follows the same workflow to ensure that events are generated, indexed, detected, visualized, and alerted successfully.

## 

### **Validation Workflow**



Generate Attack
       │
       ▼
Ubuntu Server (/var/log/auth.log)
       │
       ▼
Splunk Data Input
       │
       ▼
Index = main
       │
       ▼
Execute SPL Query
       │
       ▼
Dashboard Updated 

&#x20;      │
       ▼

Alert Condition Generated
       │
       ▼
Alert Triggered



\---


### Step 1 – Run Attacks

##### Failed SSH Login

Bash
ssh invaliduser@<Ubuntu-IP>


Purpose:

* Generates a failed SSH authentication event.
* Used to validate failed login detections.



\---



##### Successful SSH Login

Bash
ssh bishav@<Ubuntu-IP>


Purpose:

* Generates an Accepted password event.



\---



##### Failed Brute Force

Bash
hydra -l bishav -p WrongPassword ssh://<Ubuntu-IP>


Purpose:

* Generates repeated failed login events.



\---



##### Successful Brute Force

Bash
hydra -l bishav -P passwords.txt ssh://<Ubuntu-IP>


Purpose:

* Generates multiple failed logins followed by one successful login.



\---



##### Username Enumeration

Bash
hydra -L users.txt -p WrongPassword ssh://<Ubuntu-IP>


Purpose:

* Attempts authentication against multiple usernames.



\---



##### Outside Business Hours

Run after 18:00 or before 09:00.

Bash
ssh bishav@<Ubuntu-IP>



\---


##### Privileged Login from Untrusted IP

1. Remove current IP from `trusted\_ips.csv`
2. Refresh the lookup.
3. Login:

Bash
ssh bishav@<Ubuntu-IP>


\---



### Step 2 – Verify Logs

Authentication log:
/var/log/auth.log


Monitor logs:

Bash
sudo tail -f /var/log/auth.log


Failed logins:

Bash
grep "Failed password" /var/log/auth.log


Successful logins:

Bash
grep "Accepted password" /var/log/auth.log


\---



### Step 3 – Verify Searches

Verify ingestion:

SPL
index=main


Failed logins:

SPL
index=main "Failed password"


Successful logins:

SPL
index=main "Accepted password"


Brute force:

SPL
index=main "Failed password"
| rex "from (?<Attacker\_IP>\\d+\\.\\d+\\.\\d+\\.\\d+)"
| bucket \_time span=1m
| stats count by \_time Attacker\_IP
| where count>=5


\---



### Step 4 – Verify Dashboards

Verify the following dashboard panels update:

* Total Failed Login Attempts
* Failed Logins Over Time
* Successful Logins by User
* Top Client Source Port Analysis
* SSH Authentication Status Distribution
* IP Activity Summary
* SSH Authentication Summary by Host and Attacker



\---



### Step 5 – Verify Alerts

Navigate to:
Activity → Triggered Alerts


Expected alerts:

|Attack|Expected Alert|
|-|-|
|≥5 failed logins|Detect Possible Brute-Force Attacks|
|Failed then successful login|Suspicious Successful Login After Multiple Failed Attempts|
|Login outside business hours|SSH Login Outside Business Hours|
|Multiple usernames|Multiple Username Enumeration Attempt|
|Untrusted privileged login|Suspicious Privileged Account Login from Untrusted IP|



\---



### Validation Checklist

|Step|Status|
|-|:-:|
|Attack executed|✓|
|Ubuntu log generated|✓|
|Log indexed|✓|
|SPL query successful|✓|
|Dashboard updated|✓|
|Alert triggered|✓|




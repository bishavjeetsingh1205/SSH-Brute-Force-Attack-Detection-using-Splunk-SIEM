\# Investigation Queries



These queries support incident response and forensic investigations after suspicious activity has been detected or an alert has been triggered. They provide analysts with detailed event information required to understand the scope, timeline, and impact of an incident.



\---



\# 1. View Only SSH Authentication Logs



\*\*Purpose\*\*

Display only SSH authentication logs from the monitored log file.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

N/A (Investigation Query)

Informational



\---



\*\*SPL\*\*



index=main source="/var/log/auth.log"



\---



\*\*Explanation\*\*

This query filters events from /var/log/auth.log, which stores SSH authentication activities on the Ubuntu server. It allows analysts to inspect only authentication-related events while excluding unrelated system logs, making investigations more focused and efficient.



\---



\# 2. View Recent SSH Events



\*\*Purpose\*\*

Display the latest SSH-related events.



\---



\*\*MITRE ATT\&CK MAPPING and SEVERITY\*\*

N/A (Investigation Query)

Informational



\---



\*\*SPL\*\*



index=main

| sort -\_time



\---



\*\*Explanation\*\*

This query retrieves events from the main index and sorts them in descending order based on time, allowing analysts to quickly review the most recent SSH activities without applying additional filters.



\---



\# 3. IP Activity Summary



\*\*Purpose\*\*

Compare successful and failed SSH activity for each IP address.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1110 - Brute Force / T1078 - Valid Accounts

Medium



\---



\*\*SPL\*\*



index=main ("Failed password" OR "Accepted password")

| rex "from (?<Attacker\_IP>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| eval Status=if(searchmatch("Failed password"),"Failed","Successful")

| stats count by Attacker\_IP Status

| sort Attacker\_IP



\---



\*\*Explanation\*\*

The query searches both failed and successful authentication events, classifies each event as Failed or Successful using eval, and summarizes the number of each type per source IP. This helps analysts understand the authentication behavior associated with individual IP addresses.


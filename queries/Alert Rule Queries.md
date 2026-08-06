\# Investigation Queries



These queries support incident response and forensic investigations after suspicious activity has been detected or an alert has been triggered. They provide analysts with detailed event information required to understand the scope, timeline, and impact of an incident.



\---



\# 1. Detect Possible Brute-Force Attacks



\*\*Purpose\*\*

Detect repeated failed login attempts from the same IP address within one minute.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1110 - Brute Force

High



\---



\*\*SPL\*\*



index=main "Failed password" 

| rex "from (?<Attacker\_IP>\\d+\\.\\d+\\.\\d+\\.\\d+)" 

| bucket \_time span=1m 

| stats count by \_time Attacker\_IP 

| where count>=5 



\---



\*\*Explanation\*\*

This query extracts the attacker's IP address, groups events into one-minute intervals using bucket, and counts failed login attempts per IP. If an IP generates five or more failed logins within a minute, the query flags it as a potential brute-force attack.



\---



\# 2. Suspicious Successful Login After Multiple Failed Attempts



\*\*Purpose\*\*

Detect possible account compromise following repeated failed authentication attempts.



\---



\*\*MITRE ATT\&CK MAPPING and SEVERITY\*\*

T1110 - Brute Force + T1078 - Valid Accounts

Critical



\---



\*\*SPL\*\*



index=main ("Failed password" OR "Accepted password")

| rex "from (?<Attacker\_IP>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| eval Status=if(searchmatch("Failed password"),"Failed","Successful")

| bucket \_time span=5m

| stats count(eval(Status="Failed")) AS Failed\_Attempts count(eval(Status="Successful")) AS Successful\_Logins by \_time Attacker\_IP

| where Failed\_Attempts>=5 AND Successful\_Logins>=1



\---



\*\*Explanation\*\*

This query searches both failed and successful SSH login events, extracts the attacker IP, and groups events into five-minute intervals. It counts failed and successful logins for each IP and identifies cases where an attacker performs five or more failed attempts followed by at least one successful login within the same time window. This behaviour may indicate a successful brute-force attack or compromised credentials.



\---



\# 3. SSH Login Outside Business Hours



\*\*Purpose\*\*

Detect successful SSH logins occurring outside normal working hours.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1078 - Valid Accounts

High



\---



\*\*SPL\*\*



index=main "Accepted password"

| rex "for (?<Username>\\w+)"

| eval Hour=strftime(\_time,"%H")

| where Hour<9 OR Hour>=18

| table \_time host Username Hour



\---



\*\*Explanation\*\*

This query searches for successful SSH authentication events, extracts the username, and determines the login hour using the event timestamp. It returns only those logins that occur before 09:00 or after 18:00, helping analysts identify potentially suspicious access outside normal business hours.


---



\# 4. Multiple Username Enumeration Attempt



\*\*Purpose\*\*

Detect attempts to authenticate against multiple different usernames from the same IP address.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1589.001 - Gather Victim Identity: Credentials / T1110.001 - Password Guessing

Medium



\---



\*\*SPL\*\*



index=main "Failed password"

| rex "from (?<Attacker\_IP>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| rex "for (invalid user )?(?<Username>\\w+)"

| bucket \_time span=5m

| stats dc(Username) AS Unique\_Usernames values(Username) AS Targeted\_Users by \_time Attacker\_IP

| where Unique\_Usernames>=3



\---



\*\*Explanation\*\*

This query extracts both the attacker IP address and username from failed SSH authentication events, groups events into five-minute intervals, and counts the number of unique usernames targeted by each IP address using dc(Username). If an attacker attempts three or more different usernames within the same time window, the activity is flagged as a potential username enumeration attack, which is commonly performed before launching a brute-force attack.



\---



\# 5. Suspicious Privileged Account Login from Untrusted IP



\*\*Purpose\*\*

Detect successful logins to privileged accounts originating from IP addresses that are not trusted.



\---



\*\*MITRE ATT\&CK MAPPING and SEVERITY\*\*

T1078 - Valid Accounts + T1133 - External Remote Services

Critical



\---



\*\*SPL\*\*



index=main "Accepted password"

| rex "for (?<Username>\\w+)"

| rex "from (?<Attacker\_IP>\\d+\\.\\d+\\.\\d+\\.\\d+)"

| lookup trusted\_ips Attacker\_IP OUTPUT Hostname Owner Role Trusted

| where Username IN ("root","admin","ubuntu","bishav")

&#x20;   AND (isnull(Trusted) OR Trusted!="Yes")

| rename host AS Victim\_Host

| table \_time Username Attacker\_IP Victim\_Host Hostname Owner Role Trusted

| sort -\_time



\---



\*\*Explanation\*\*

This query searches for successful SSH logins, extracts the username and source IP address, and compares the source IP against the trusted\_ips lookup table. It filters events where the login is performed using privileged accounts such as root, admin, ubuntu, or bishav, and where the source IP is either absent from the trusted IP list or explicitly marked as untrusted. The query displays important investigation details including login time, username, attacker IP, victim host, and lookup information, enabling analysts to quickly identify potentially unauthorized privileged access.


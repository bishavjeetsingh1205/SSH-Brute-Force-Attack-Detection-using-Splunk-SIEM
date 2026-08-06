\# Detection \& Monitoring Queries



These queries provide continuous visibility into SSH authentication activity. They help SOC analysts monitor login behavior, identify suspicious patterns, analyze attack trends, and gather operational insights. Although these queries can also be displayed on dashboards, their primary purpose is to detect and monitor security-related events.


\---



\# 1. Detect Failed SSH Logins



\*\*Purpose\*\*

Identify unsuccessful SSH authentication attempts.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1110 - Brute Force

Low



\---



\*\*SPL\*\*



index=main "Failed password" 



\---



\*\*Explanation\*\*

This query searches for log entries containing the text "Failed password", which indicates unsuccessful SSH login attempts. It helps analysts monitor authentication failures, identify password guessing attempts, and investigate potential brute-force attacks.



\---



\# 2. Detect Successful SSH Logins



\*\*Purpose\*\*

Identify successful SSH authentication attempts.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1078 - Valid Accounts

Medium



\---



\*\*SPL\*\*



index=main "Accepted password"



\---



\*\*Explanation\*\*

This query searches for log entries containing "Accepted password", which indicates that a user has successfully authenticated through SSH. It provides visibility into legitimate login activity and can be correlated with previous failed login attempts to identify suspicious access.



\---



\# 3. Count Failed Login Attempts



\*\*Purpose\*\*

Calculate the total number of failed SSH login attempts.

\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1110 - Brute Force

Low



\---



\*\*SPL\*\*



index=main "Failed password"

| stats count



\---



\*\*Explanation\*\*

The query searches for all failed SSH authentication events and uses the stats count command to calculate the total number of failures. This provides a quick overview of authentication failures and can be displayed as a single-value metric on a dashboard.



\---



\# 4. Find Attacker IP Addresses



\*\*Purpose\*\*

Identify the IP addresses generating failed login attempts.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1595 - Active Scanning / T1110 - Brute Force

Low



\---



\*\*SPL\*\*



index=main "Failed password" 

| rex "from (?<Attacker\_IP>\\d+\\.\\d+\\.\\d+\\.\\d+)" 

| stats count by Attacker\_IP 

| sort -count 



\---



\*\*Explanation\*\*

The query extracts the source IP address from each failed SSH login event using the rex command. It then counts the number of failed attempts originating from each IP address and sorts the results in descending order, helping identify the most active attackers.



\---



\# 5. Find Targeted Usernames



\*\*Purpose\*\*

Identify usernames targeted during failed login attempts.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1589.001 - Gather Victim Identity: Credentials

Low



\---



\*\*SPL\*\*



index=main "Failed password" 

| rex "for (invalid user )?(?<Username>\\w+)" 

| stats count by Username 



\---



\*\*Explanation\*\*

This query extracts usernames from failed authentication events, including both valid and invalid usernames, using a regular expression. It then counts how many times each username was targeted, allowing analysts to identify accounts that attackers frequently attempt to access.



\---



\# 6. Successful Logins by User



\*\*Purpose\*\*

Display the number of successful SSH logins for each user.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1078 - Valid Accounts

Medium



\---



\*\*SPL\*\*



index=main "Accepted password" 

| rex "for (?<Username>\\w+)" 

| stats count by Username 



\---



\*\*Explanation\*\*

This query searches for SSH events containing "Accepted password", extracts the username using the rex command, and groups the results using stats count by Username. It provides a summary of successful logins per user, helping analysts identify frequently accessed accounts and monitor user login activity.

---



\# 7. Top Client Source Port Analysis



\*\*Purpose\*\*

Identify the client source ports most frequently used during failed SSH login attempts.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

N/A (Traffic Analysis)

Informational



\---



\*\*SPL\*\*



index=main "Failed password" 

| rex "port (?<Port>\\d+)" 

| stats count by Port 

| sort -count 



\---



\*\*Explanation\*\*

This query extracts the client source port from failed SSH authentication logs using a regular expression. It then counts how many times each source port appears and sorts the results in descending order. Although client ports are usually ephemeral, this analysis can help identify unusual connection patterns or repeated attack behavior.



\---



\# 8. Failed Logins Over Time



\*\*Purpose\*\*

Visualize the trend of failed SSH login attempts over time.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1110 - Brute Force

Medium



\---



\*\*SPL\*\*



index=main "Failed password" 

| timechart span=1m count 



\---



\*\*Explanation\*\*

This query searches for failed authentication events and uses the timechart command with a one-minute interval to plot the number of failed logins over time. It helps analysts identify spikes in failed authentication attempts that may indicate brute-force attacks or other malicious activity.



\---



\# 9. SSH Authentication Status Distribution



\*\*Purpose\*\*

Compare the number of successful and failed SSH authentication attempts.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1110 - Brute Force / T1078 - Valid Accounts

Low



\---



\*\*SPL\*\*



index=main ("Failed password" OR "Accepted password") 

| eval Status=if(searchmatch("Failed password"),"Failed","Successful") 

| stats count by Status 



\---



\*\*Explanation\*\*

This query searches both successful and failed SSH authentication events and classifies each event as either Successful or Failed using the eval command. The stats command then counts the number of events for each status, providing an overall view of authentication success and failure across the monitored environment.



\---



\# 10. SSH Authentication Summary by Host and Attacker



\*\*Purpose\*\*

Summarize authentication activity between attacker IPs and monitored hosts.



\---



\*\*MITRE ATT\\\&CK MAPPING and SEVERITY\*\*

T1110 - Brute Force / T1078 - Valid Accounts

Medium



\---



\*\*SPL\*\*



index=main ("Failed password" OR "Accepted password") 

| rex "from (?<Attacker\_IP>\\d+\\.\\d+\\.\\d+\\.\\d+)" 

| eval Status=if(searchmatch("Failed password"),"Failed","Successful") 

| stats count(eval(Status="Failed")) AS Failed\_Attempts count(eval(Status="Successful")) AS Successful\_Logins by host Attacker\_IP 

| eval Total\_Attempts=Failed\_Attempts+Successful\_Logins 

| eval Failure\_Rate=round((Failed\_Attempts/Total\_Attempts)\*100,2) 

| eval Success\_Rate=round((Successful\_Logins/Total\_Attempts)\*100,2) 

| rename host AS Host Attacker\_IP AS Attacker\_IP 

| sort -Failed\_Attempts



\---



\*\*Explanation\*\*

This query extracts attacker IP addresses, classifies authentication events as successful or failed, and calculates the total failed and successful login attempts for each host and attacker IP combination. It also computes the total number of attempts along with failure and success percentages, providing analysts with a comprehensive overview of authentication activity and helping identify systems experiencing repeated attack attempts.


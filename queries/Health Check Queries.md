# Health Check Queries

These queries are used to verify that the Splunk environment is functioning correctly before performing any security analysis. They confirm that log data is being successfully collected and indexed, ensuring that subsequent searches, dashboards, and alerts operate on live authentication data.

---

# Verify Data is Being Indexed

**Purpose**
Verify that Splunk is successfully ingesting data into the main index.

---

**MITRE ATT\&CK MAPPING and SEVERITY**
N/A (SIEM Health Check)
Informational

---

**SPL**

index=main

---

**Explanation**
This query searches the main index without applying any filters. It returns all indexed events, allowing the analyst to confirm that log ingestion is functioning correctly before performing further analysis or creating detections.
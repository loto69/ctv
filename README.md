https://www.perplexity.ai/search/this-are-outputs-please-give-m-zZ2Wf3m1RBSRb5sS52WL6Q#0


Exp 1

sudo apt update
sudo apt install ufw
sudo ufw enable
sudo ufw status verbose

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow sh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 80/tcp
sudo ufw allow from 192.168.1.10 to any port 22 proto tcp
sudo ufw status verbose

Exp 2

sudo apt update
sudo apt install clamav clamav-daemon
sudo systemctl stop clamav-freshcalm
sudo freshclam
stop system stop clamav-freshclam
sudo clamscan -r / --bell -i
sudo systemctl start clamav-freshclam
curl -O https://secure.eicar.org/eiar.com.txt
clamscan eicar.com.txt

Exp 3
sudo setoolkit

Exp 4: Performing Vulnerability Scanning Using Nessus
login
create a new scan
basic network scan
in target enter 127.0.0.1
run the scan and wait for few minutes


 Exp 7: Analyzing Network Traffic with Wireshark

To download dd file: https://cfreds-archive.nist.gov/dfr-test-images.html
open wireshark 
press eth0 or wifi
start capturing packets

Exp 8: Investigating a Cyber Incident using Forensics Tools

Autopsy
open and create a case
install any image(.dd) file and upload and scan

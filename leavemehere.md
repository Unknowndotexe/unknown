DIGITAL DUMPSTER DIVING EXAMPLES

Looked up the "example" company name
Combine "example_company" + asset_name + "password"

Asset Discovery

Brute force domain -> Find different environments (.dev,.corp,.stage,uat) -> Brute force again -> Different permutations, Different environment, e.g. dashboard.dev.site.com vs dashboard-dev.site.com

Google Dork: site.com +inurl: dev -cdn

Tools:

sublist3r<br>
enumall<br>
massdns<br>
altdns<br>
brutesubs<br>
dns-parallel-prober<br>
dnscan<br>
knockpy<br>
tko-subs<br>
HostileSubBruteForce<br>


Certificate Transparency Tools

Censys
Look for SSL certificates
Example: 443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names:snapchat.com

Shodan
Search by hostname. Filter for: Ports 8443,8080, etc
Title: "Dashboard [Jenkins]" | Product: Tomcat Hostname: somecorp.com | Org: evilcorp | ssl: Google

Certspotter
Great API
Easy to automate | Make a bash alias -> Automate -> Win

Crt.sh
Great API and web interface | Allows using a wild card | You may get different results from differents sources

Vulnerabilities found with Shodan <br>
![image](https://user-images.githubusercontent.com/79203900/181038374-13ac73d9-d607-403f-b40c-d3d0c3afe631.png)<br>
Vulnerabilities found with Censys <br>
![image](https://user-images.githubusercontent.com/79203900/181038499-c6d84ba2-9225-4dfb-b238-9b841b5fe21c.png)<br>

OSINT

WHOIS
ARIN (Canada, United States, some Caribbean nations) | RIPE NCC (Europe, Russia, Middle East, Central Asia) | APNIC (Asia-Pacific region) | LACNIC (Latin America, some Caribbean nations) | AFRINIC (Africa)


Content Discovery

Content Discovery Process

Port Scan -> Screenshot open ports (default: 80, 443) -> Look for interesting Files / Directories -> Always keep an archive of your report 

Tools<br>
dirbuster<br>
gograbber<br>
gobuster<br>
dirsearch<br>

Content Discovery Examples<br>
![image](https://user-images.githubusercontent.com/79203900/181039258-ed1803c1-3af0-4140-9c71-6df92d8e356a.png)<br>
![image](https://user-images.githubusercontent.com/79203900/181039391-be989719-7145-4ba6-ac8d-eafa7d9dae6b.png)<br>

Gathering information from Open Sources<br><br>
Owner of IP-address range<br>
Address Range<br>
Domain Names<br>
Computing Platforms<br>
Network Architecture<br>
User(name) Information<br>
Physical Location<br>
Active Services<br>
Technical Contact<br>
Business Partners<br>
Administrative Contacts<br>
Email Addresses<br>
Technology being used<br>
Phone No's<br>
Route to target's<br>
Internet Accessible data<br>
Public Server's Banner Information.<br>
DNS Servers<br>
WEB Servers<br>
SMTP Servers<br>
Zones & Sub-domains<br>
Locate Firewalls/Perimeter devices.<br>


Techniques<br><br>
Target's Website<br><br>
Mirror the web<br>
Use Grep or Similar<br>
Scan for keywords<br>
Banner Information<br>
Applications<br>
Cgi's<br>
Cookie style<br>
Scripting language<br>
Code-reading<br>
Weblogs info [e.g. MRTG]<br>
Search Engines (Google)<br><br>
intitle: "index of /etc"<br>
inurl: "config.php.bak"<br>
site:"target.com"<br>
filetype:".bak"<br>
Cross-Links<br>
Search for group postings<br>
News Articles<br>
Whois<br><br>
DNS<br><br>
AXFR<br>
Version<br>
Zones & Sub-domains<br>
Nmap -sL<br>
DNSDig<br>
Nslookup<br>
Dig commands<br>
Host commands<br>
Active services<br>
Traceroute<br><br>
ISP information<br>
Locate Firewalls<br>
Network Infrastructure<br>
Tcptraceroute<br>
Firewalk<br>
Finger<br><br>
SamSpade<br><br>
Netcraft<br><br>
SMTP<br><br>
vrfy; email_enumeration<br>
Banner information<br>
Bounced Emails<br>
Email Header<br>
expn; email mapping<br>
Job Databases<br><br>
Job requirements<br>
Employee profile<br>
Hardware information<br>
Software information<br>
Personal Website<br><br>
Employee job profile<br>
Hardware information<br>
Software information<br>
Ping<br><br>
List of live systems<br>
RTT, delays<br>
N/W connectivity<br>



<br>Reconnaissance & Enumeration <br><br>

Bash Log<br>
Log all commands and their output:<br><br>
  script target.log
  
Port Scanning <br>
<br>Nmap<br><br>
  nmap -A -sS -Pn -n x.x.x.x<br>
  -A Enables OS detection, version detection, script scanning, and traceroute <br>
  -sS TCP SYN port scan (Default)<br>
  ![image](https://user-images.githubusercontent.com/79203900/181041917-75f1a793-03a9-4e5d-8fa0-444cba9c9d49.png)<br>
  -Pn Disable host discovery. Port scan only<br>
  HOST DISCOVERY: Host discovery is one of the earliest phases of network reconnaissance. The adversary usually starts with a range of IP addresses belonging to a target network 

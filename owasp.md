<em>This write up breaks each OWASP topic down and includes details on what the vulnerability is, how it occurs and how you can exploit it. We will put the theory into practise by completing supporting challanges.</em></br>
<pre>Injection
Broken Authentication
Sensitive Data Exposure
XML External Entity
Broken Access Control
Security Misconfiguration
Cross-site Scripting
Insecure Deserialization
Components with Known Vulnerabilities
Insufficient Logging & Monitoring</pre></br>
<em>This write up has been configured for beginners and assume no previous knowledge of security</em></br>
<pre>https://tryhackme.com/room/owasptop10</pre></br>
<em><b>Severity 1 -> Injection</b></br>
Injection flaws are very common in applications today. These flaws occur because user controlled input is interpreted as actual commands 
or parameters by the application. Injection attacks depend on what technologies are being used and how exactly the input is 
interpreted by these technologies. Some common examples include: </br>
SQL Injection: This occurs when user controlled input is passed to SQL queries. As a result, an attacker 
can pass in SQL queries to manipulate the outcome of such queries. </br>
Command Injection: This occuras when user input is passed to system commands. As a result, an attacker
is able to execute arbitrary system commands on application servers.</br></br>
If an attacker is able to succesfully pass input that is interpreted correctly, they ould be able to do the following:</br>
Access, Modify and Delete information in a database when this input is passed into database queries.
 This would mean that an attacker can steal sensitive information such as personal details and credentials.</br>
 Execute Arbitrary system commands on a server that would allow an attacker to gain access to user's systems. This would 
 enable them to steal sensitive data and carry out more attacks against infrastructure linked to the server on which the command is executed.
 </br></br>
 
 The main defence for preventing injection attacks is ensuring that user controlled input is not interpreted as queries or commands! 
 There are different ways of doing this: </br>
 Using an allow list: when input is sent to the server, this input is compared to a list of safe input or characters. If the 
 input is marked as safe, then it is processed. Otherwise, it is rejected and the application throws an error. </br>
 Stripping input: If the input contains dangerous characters, these characters are removed before they are processed.
 </em></br>
 
 </br><b>Severity 1 -> OS Command Injection</b></br>
 <em>Command Injection occurs when server-side code (like PHP) in a web application makes a system call on the hosting machine. 
It is a web vulnerability that allows an attacker to take advantage of thata made system call 
to execute operating system commands on the server.</br>
Sometimes this won't always end in something malicious, like a whoami or just reading of files. That isn't too bad. But the thing
 about command injection is it opens up many options for the attacker. The worst thing they could do 
 would be to spawn a reverse shell to become the user that the web server is running as. </br>
 A simple ;nc -e /bin/bash is all that's needed and they own your server; Some variants of netcat don't support the -e option. 
 You can use a list of <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md"> this </a> reverse shells as an alternative!
 </br>
 Once the attacker has a foothold on the web server, they can start the usual enumeration of your system and start looking for ways to pivot around. Now that we know what command injection is, we'll start going into the different 
 types and how to test for them.</em></br>
 
 </br><b>Severity 1 -> Command Injection PRACTICAL</b></br>
 <b>What is Active Command Injection?</b></br>
 <em>Blind command injection occurs when the system command made to the server does not return the 
response to the user in the HTML document. Active command injection will return the response to the user. It 
can be made visible through several HTML elements. </br>
Let's consider a scenario:</em></br>
<pre>EvilCorp has started development on a web based shell but has accidentally left it exposed to the Internet. It's nowhere near finished but contains the same command 
injection vulnerability as before! But this time, the response from the system call can be seen on the page! They'll never learn!</pre></br>
<em>Just like before, let's look at the sample code from evilshell.php and go over what it's doing and why it makes 
it active command injection. See if you can figure it out.</em></br>
<b>EvilShell (evilshell.php) Code Example</b></br>
```php
<?php
  if (isset($_GET["commandString"])) {
    $command_string = $_GET["commandString"];
    try {
      passthru($command_string);
    } catch (Error $error) {
      echo "<p class=mt-3><b>$error</b></p>";
    }
  }
?>
```
</br>

<em>In pseudocode, the above snippet is doing the following: </br>
1. Checking if the parameter "commandString" is set 
2. If it is, then the variable $command_string gets what was passed into the input field 
3. The program then goes into a try block to execute the function passthru($command_string). You can read the docs on passthru() on <a href ="https://www.php.net/manual/en/function.passthru.php">PHP's website</a>, but in general, 
it is executing what gets entered into the input then passing the output directly back to the brwoser.
4. If the try does not succeed, output the error to page. Generally this won't output anything because you can't output stderr 
but PHP doesn't let you have a TRY without a CATCH.</em></br>

<em>Commands to try: </br>
Linux: </br>
1. whoami
2. id
3. ifconfig / ip addr / ip a s 
4. uname -a
5. ps -ef
</br>
</em></br>
1. What strange text file is in the website root directory?
<img src="https://user-images.githubusercontent.com/79203900/149321030-29bb0137-2d64-46de-9729-e6c430b17a11.png"/>
</br><em>The strange text file: drpepper.txt</em></br></br>
2. How many non-root/non-service/non-daemon users are there?
<img src="https://user-images.githubusercontent.com/79203900/149321527-bfd22f3c-899a-449e-95a3-678d47787e02.png"/>
</br><em>There are 0 non-root/non-service/non-daemon users</em></br></br>
3. What user is this app running as? and what is the user's shell set as?
</br><em>For this question we need to understand the /etc/passwd format!
</br> The /etc/passwd file stores essential information, which required during login. 
In other words, it stores user account information. The /etc/passwd is a plain text file. It 
contains a list of the system's accounts, giving for each account some useful information like 
User ID, group ID, home directory, shell, and more. </br>
The /etc/passwd contains one entry per line for each user of the system. All fields are separated by a colon symbol. 
Total of seven fields as follows:</em></br></br>
<pre>
unknowndotexe:x:1000:1000:PAUBKA:/home/paubka:usr/bin/zsh
-------------:-:----:----:------:------------:-----------
      1      :2:  3 :  4 :   5  :      6     :      7   </pre></br>

</br><em>From the above code tag:</br>
1. Username: It is used when user logs in. It should be between 1 and 32 character in lenght.</br>
2. Password: An x character indicates that encrypted password is stored in /etc/shadow file. Please note that you need to use the passwd command to computes the hash of a password typed at the CLI or to store/update the hash of the password in /etc/shadow file.
3. User ID (UID): Each user must be assigned a user ID (UID). UID 0 is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
4. Group ID (GID): The primary group ID (stored in /etc/group file)
5. User ID info (GECOS): The comment field. It allow you to add extra information about the users such as user's full name, phone number, etc. This field use by finger command.
6. Home directory: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes /
7. Command/shell: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell. For example, sysadmin can use the nologin shell, which acts as a replacement shell for the user accounts. If shell set to /sbin/nologin and the user tries to log in to the Linux system directly, the /sbin/nologin shell closes the connection.</em></br>

</br><em>Use the stat command to see details about the file:</em></br>
<pre>
stat /etc/passwd

File: /etc/passwd
  Size: 3445      	Blocks: 8          IO Block: 4096   regular file
Device: fd02h/64770d	Inode: 25954390    Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2021-09-04 01:34:01.794296901 +0530
Modify: 2021-09-04 00:33:40.430038177 +0530
Change: 2021-09-04 00:33:40.434038185 +0530
 Birth: -
</pre></br>
</br><em>3. What user is this app running as? and what is the user's shell set as?</em></br>
<pre>
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
--------:-:--:--:--------:--------:-----------------
    1   :2: 3: 4:    5   :    6   :         7
    
    What user is this app running as?
    Answer: www-data
    1 : Username: It is used when user logs in. It should be between 1 and 32 character in lenght.
    
    What is the user's shell set as?
    Answer: /usr/sbin/nologin
    7 : Command/shell: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell. For example, sysadmin can use the nologin shell, which acts as a replacement shell for the user accounts. If shell set to /sbin/nologin and the user tries to log in to the Linux system directly, the /sbin/nologin shell closes the connection.
    
</pre></br>

<b><em>4. What version of Ubuntu is running?</b></br>
</em>
<img src="https://user-images.githubusercontent.com/79203900/149351639-fc966b58-8aa2-4248-9d69-d4ef4a1a834d.png"/> </br>
</br></br> 
<em><b>Linux lsb_release command</b></br>
It will be useful to get through this command for better understanding.</br>
The <b>lsb_release</b> command displays LSB (Linux Standard Base) information about your specific
Linux distribution, including version number, release codename, and distributor ID.</br></em>
</br>
<pre>lsb_release [OPTIONS]

Options
As with other GNU software, lsb_release uses a single dash (-) for short options, and two dashes (--) for long options.

-v, --version -> Show the version of the Linux Standard Base your system is compliant with. The version is displayed as a colon-separated list of LSB module description.
-i, --id -> Display the ID of your Linux distributor. For instance, if you are running Debian, this option displays: Distributor ID: Debian</pre></br>
-d, --description -> Display a description of your Linux distribution. For instance, if you are running CentOS 7, this displays something like: Description: CentOS Linux release 7.3.1611 (Core)
-r, --release -> Display the release number of the current operating system. For instance, if you are running Fedora 25, this outputs: Release: 25
-c, --codename -> Display the codename of the current operating system. For instance, if you are running Ubuntu 16.04, this displays: Codename: xenial, if you are using Kali: Codename: kali-rolling
-a, --all -> Display all the information above.

NOTE*
If you receive a "No LSB modules are available" or similar message, you need to install the LSB core software first. 
To install it, run the command:
sudo apt-get update && sudo apt-get install lsb-core (Ubuntu and Debian)
sudo yum update && sudo yum install redhat-lsb-core (CentOS)
sudo dnf update && sudo dnf install redhat-lsb-core (Fedora)
</pre>

<em><b>Linux uname command --> Related </b>
</br> On Unix-like operating systems, the uname command prints information about the current system. </em></br>

<pre>Description 
Print certain system information. If no OPTION is specified, uname assumes the -s option.
-s, --kernel-name -> Print the kernel name. 
Kernel referring to an operating system, the kernel is the first section of the operating system to load into memory.

Syntax
uname [OPTION]...

Options:
-a, --all -> Prints all information, omitting -p and -i if the information is unknown.
Linux kali 4.xx.x-kalix-xxxxx #1 SMP Debian 4.xx.xx-xkali1 (20xx-xx-xx) x86_64 GNU/Linux

If -a (--all) is specified, the information is printed in the following order of individual options:

-s, --kernel-name -> Prints the kernel name.
┌──(kali㉿kali)-[~]
└─$ uname --kernel-name
Linux

-n, --nodename -> Print the network node hostname.
┌──(kali㉿kali)-[~]
└─$ uname --nodename   
kali

-r, --kernel-release -> Print the kernel release.
┌──(kali㉿kali)-[~]
└─$ uname --kernel-release
x.xx.x-kalix-amd64

-v, --kernel-version -> Print the kernel version
┌──(kali㉿kali)-[~]
└─$ uname --kernel-version
#1 SMP Debian x.xx.xx-1kali1 (202x-xx-xx)

-m, --machine -> Print the machine hardware name.
┌──(kali㉿kali)-[~]
└─$ uname --machine       
x86_64
                        
-p, --processor -> Print the processor type, or "unknown"
┌──(kali㉿kali)-[~]
└─$ uname --processor
unknown

-i,--hardware-platform -> Print the hardware platform, or "unknown".
┌──(kali㉿kali)-[~]
└─$ uname --hardware-platform                                                                                 127 ⨯
unknown

-o, --operating-system -> Print the operating system.
┌──(kali㉿kali)-[~]
└─$ uname --operating-system 
GNU/Linux
                           
uname -a
SunOS hope 5.7 Generic_106541-08 sun4m sparc SUNW,SPARCstation-10

</pre></br></br>

</br><img src="https://user-images.githubusercontent.com/79203900/149357795-58443616-27eb-4270-9797-c454e3e6c106.png"/></br></br>

<b><em>4. What version of Ubuntu is running?</b></br>
<em>Using lsb_release --all we can see that the version of Ubuntu: 18.04.4</em></br>


</br><em>5. Print out the MOTD. What favorite beverage is shown?</em></br>
<img src="https://user-images.githubusercontent.com/79203900/149361800-cd815468-ebf8-4e40-bb57-c204cba21b44.png"/>
</br></br>
</br><img src="https://user-images.githubusercontent.com/79203900/149364877-167409c7-9784-478b-92ed-7db60a01f106.png"/>


</br></br><b><em>Severity 2 -> Broken Authentication</em></b></br>
</br><em>Authentication and session management constitute core components of modern web applications. Authentication allows users to gain access to web applications by verifying their identities. The most common form of authentication is using a username and password mechanism. A user would enter these credentials, the server would verify them. If they are correct, the server would then provide the user's browser with a session cookie. A session cookie is needed because web servers use HTTP(S) to communicate which is stateless. Attaching session cookies means that the server will know who is sending what data. The server can then keep track of user's acctions.</em></br>
</br><em>If an attacker is able to find flaws in the authentication mechanism, they would then succesfully gain access to other users accounts. This would allow the attacker to access sensitive data (depending on the purpose of the application). Some common flaws in authentication mechanisms include:</em></br>
</br><em>
1. Brute Force attacks: If a web application uses usernames and passwords,an attacker is able to launch brute force attacks that allow them to guess the username and passwords using multiple authentication attempts.</br>
2. Use of weak credentials: web applications should set strong password policies. If applications allow users to set passwords such as password1 or common passwords, then an attacker is able to easily guess them and access user accounts. They can do this without brute forcing and without multiple attempts.</br>
3. Weak Session Cookies: Session cookies are how the server keeps track of users. If session cookies contain predictable values, an attacker can set their own session cookies and access users accounts.</br>
There can be various mitigation for broken authentication mechanisms depending on the exact flaw: </br>
1. To avoid password guessing attacks, ensure the application enforces a strong password policy.
2. To avoid brute force attacks, ensure that the application enforces an automatic lockout after a certain number of attempts. This would prevent an attacker from launching more brute force attacks.
3. Implement Multi Factor Authentication, if a user has multiple methods of authentication, for example, using username and passwords and receiving a code on their mobile device, then it would be difficult for an attacker to get access to both credentials to get access to their account.</em></br>
</br><em>For this example, we'll be looking at a logic flaw within the authentication mechanism.</br>
A lot of times what happens is that developers forgets to sanitize the input (username and password) given by the user in the code of their application, which can make them vulnerable to attacks like SQL injection. However, we are going to focus on a vulnerability that happens because of a developer's mistake but is very easy to exploit i.e. re-registration of an existing user.
</br>
Let's understand this with the help of an example, say there is an existing user with the name admin and now we want to get access to their account so what we can do is try to re-register that username but with slight modification. We are going to enter " admin" (notice the space in the starting).</br> 
Now when you enter that in the username field and enter other required information like email id or password and submit that data. It will actually register a new user but that user will have the same rights as normal admin. That new user will also be able to see all the content presented under the user <b>admin</b>.</em></br>
<em>Let's try to register a user name darren, you'll see that user already exists so then try to register a user " darren" and you'll see that you are now logged in and will be able to see the content present only in Darren's account which in our case is the flag that you need to retrieve.</em></br></br></br>
</br><em><b>Severity 3 -> Sensitive Data Exposure</b></em></br>
<em>When a webapp accidentally divulges sensitive data, we refer to it as "Sensitive Data Exposure". This is often data directly linked to customers (e.g. names, dates-of-birth, financial information, etc), but could also be more technical information, such as <b>usernames and passwords.</b></em></br>
<em>At more complex levels this often involves techniques such as "Man in The Middle Attack", whereby the attacker would force user connections through a device which they control, then take advantage of weak encryption on any transmitted data to gain access to the intercepted information (if the data is even encrypted in the first place). Of course, many examples are much simpler, and vulnerabilities can be found in web apps which can be exploited without any advanced networking knowledge. Indeed, in some cases, the sensitive data can be found directly on the webserver itself.</em></br>
</br><em>The most common way to store a large amount of data in a format that is easily accessible from many locations at once is in database. This is obviously perfect for something like a web application, as there may be many users interacting with the website at any one time. Database engines usually follow the <b>Structured Query Language (SQL) syntax;</b>however, alternative formats (such as NoSQL) are rising in popularity.</em></br>
</br><em><b>SQL - Structured Query Language</b></em></br>
<em>SQL is a language to operate databases; it includes database creation, deletion, fetching rows, modifying rows, etc. SQL is an ANSI (American National Standards Institute) standard language, but there are many different versions of the SQL language.</em></br>
<em>SQL is Structured Query Language, which is computer language for storing, manipulating and retrieving data stored in a relational database.</em></br>
<em>SQL is the standard language for Relational Database System. All the <b>Relational Database Management Systems (RDMS) </b> like MySQL, MS Access, Oracle, Sybase, Informix, Postgres and SQL Server use SQL as their standard database language.</em></br>
<em>SQL is widely popular because it offers the following advantages:</br></br>
1. Allows users to access data in the relational database management systems (RDMS).</br>
2. Allows users to describe the data.</br>
3. Allows users to define the data in a database and manipulate that data.</br>
4. Allows to embed within other languages using SQL modules, librarie and pre-compilers.</br>
5. Allows users to create and drop databases and tables.</br>
6. Allows users to create, view, store procedure, functions in a database.</br>
7. Allows users to set permissions on tables, procedures and views.</em></br>
</br><em>SQL Commands</br>
The standard SQL commands to interact with relational databases are <b>CREATE, SELECT, INSERT, UPDATE, DELETE and DROP.</b> These commands can be classified into the following groups based on their nature:</em></br>
</br><em>DDL - Data Definition Language</em></br>
</br><em>
1. CREATE - Creates a new table, a view of a table, or other object in the database.</br>
2. ALTER - Modifies an existing database object, such as table.</br>
3. DROP - Deletes an entire table, a view of a table or other objects in the database.</em></br>
</br><em>DML - Data manipulation Language</em></br>
</br><em>
1. SELECT - Retrieves certain records from one or more tables.</br>
2. INSERT - Creates a record</br>
3. UPDATE - Modifies records</br>
4. DELETE - Deletes records</br>
</em></br>
</br><em>DCL - Data Control Language</em></br>
</br><em>
1. GRANT - Gives a privilege to user</br>
2. REVOKE - Takes back privileges granted from user</em></br>
</br><em>In a production endivronment it is common to see databases set up on dedicated servers, running a database service such as MySQL or MariaDB; However, databases can also be stored as files. These databases are referred to as "flat-file" databases, as they are stored as a single file on the computer. This is much easier than setting up a full database server, and so could potentially be seen in smaller web applications. Accessing a database server is outwith the scope of today's task, so let's focus instead on flat-file databases.</em></br>
</br><em>As mentioned previously, flat-file databases are stored as a file on the disk of a computer. Usually this would not be a problem for a webapp, but what happens if the database is stored underneath the root directory of the website (i.e. one of the files that a user connecting to the website is able to access)? Well, we can download it and query it on our own machine, with full access to everything in the database. Sensitive Data Exposure indeed!</em></br>
</br><em>That is a big hint for the challenge, so let's briefly cover some of the syntax we would use to query a flat-file database.</em></br>
</br><em>The most common (and simplest) format of flat-file database is an sqlite database. These can be interacted with in most programming languages, and have a dedicated client for querying them on the command line. This client is called "sqlite3", and is installed by default on Kali.</em></br>
</br><em>Let's suppose we have succesfully managed to download a database: </br>
We can check the file with the syntax: file example.db </br> Example of output: example.db: SQLite 3.x database, last written using SQLite version 303xxxx</em></br>
</br><em>To access it we can use: sqlite3 <database-name> </br> Example of output: SQLite version 3.32.3 202x-xx-xx xx:xx:xx</br>
Enter ".help" for usage hints.</br>
sqlite> </em></br>
<em>From here we can see the tables in the database by using the .tables command.</em></br>
</br><em>At this point we can dump all of the data from the table, but we won't necessarily know what each column means unless we look at the table information. First let's use: 
</br> PRAGMA table_info(tablename); - to see the table informaton, then we'll use: SELECT * FROM tablename; to dump the information from the table.</em></br>
</br><img src="https://user-images.githubusercontent.com/79203900/150679306-65d460a0-deb6-4b11-92ff-cf8a9ba5602b.png"/>
<em></br>We can see from the table information that there are four columns: custID, custNAME, creditCard, password. You may notice that this matches up with the result. Take the first row:</br>
0|Joy Paulson|4916 9012 2231 7905|5f4dcc3b5aa765d61d8327deb882cf99</em></br>
<em>We have the custID (0), the custName (Joy Paulson), the creditCard (4916 9012 2231 7905) and a password hash (5f4dcc3b5aa765d61d8327deb882cf99).</em></br>
<em>We will look at cracking this hash.</em></br>
<em>As we found a collection of password hashes, one for each user. In this task we will briefly cover how to crack these.
</br> When it comes to hash cracking, Kali comes pre-installed with various tools - if you know how to use these then feel free to do so; however they are outwith the scope of this material.</em></br>
<em>Instead we will be using the online tool: Crackstation. This website is extremely good at cracking weak password hashes. For more complicated hashed we would need more sophisticated tools; however, all of the crackable password hashes used in today's challange are weak MD5 hashes, which Cracksttion should handle very nicely indeed.</em></br>
<img src="https://user-images.githubusercontent.com/79203900/150681043-e7473b7a-cab9-48c5-bf97-3e4079a4ebcb.png"/></br>
</br><img src="(https://user-images.githubusercontent.com/79203900/150681184-93590659-5592-4326-ad5f-1c57dece67a5.png"/></br>
</br><em>We can see that the hash was successfully broken, and that the user's password was "password" , how secure!</br>
It's worth noting that Crackstation works using a massive wordlist.If the password is not in the wordlist then Crackstation will not be able to break the hash.</em></br>
<em>It's time to put what we've learnt into practice!</br>
Let's have a look around the webapp. The developer has left themselves a note indicating that there is sensitive data in a specific directory!</em></br>
</br><img src="https://user-images.githubusercontent.com/79203900/150681447-beab2da3-07bc-4a62-bfbc-4953dcd7f7e4.png"/></br></br>
<em>Let's navigate to the directory we found. Here we can see a file that stands out as being likely to contain sensitive data. webapp.db. </em></br>
</br><img src="https://user-images.githubusercontent.com/79203900/150681546-4be16e04-c10a-4a22-aa17-9da045fda6b1.png"/></br></br>
<em>After downloading the database we can check which tables are available in the database.</em></br>
<img src="https://user-images.githubusercontent.com/79203900/150681715-8a2e9a06-aa82-4777-84f2-2247ce9bebb0.png"/></br></br>
</br></br>
<em>We are interested in what is on table with the name users. We can be guided by the structure of the syntax: PRAGMA table_info (users);</em></br>
<img src="https://user-images.githubusercontent.com/79203900/150682029-63f76819-9477-468a-bfe7-fcce82489673.png"/></br></br>
<img src="https://user-images.githubusercontent.com/79203900/150682146-e1af19db-6eb2-4da0-a125-878624c1f6f4.png"/></br></br>
<img src="https://user-images.githubusercontent.com/79203900/150682286-69968d5e-1148-4291-9d25-0a832ce03b90.png"/></br></br>
<br><br><b>Severity 4 - XML External Entity<em></b></em><br><br>
<em>An XML External Entity (XXE) attack is a vulnerability that abuses features of XML parser/data. It often allows an attacker to interact with any backend or external systems that the application itself can access and can allow the attacker to read the file on that system. They can also cause Denial of Service (DoS) attack or could use XXE to perform Server-Side Request Forgery (SSRF) inducing the web application to make requests to other applications. XXE - XML External Entity - may even enable port scanning and lead to remote code execution.</em></br>
</br>
<em>There are two types of XXE attacks: in-band and out-of-band (OOB - XXE) - (Out-of-Band-XML-External-Entity).</em><br>
1. An in-band XML External Entity attack is the one in which the attacker can receive an immediate response to the XML External Entity payload.<br>
2. An Out-Of-Band XML External Entity attacks (also called blind XEE), there is no immediate response from the web application and attacker has to reflect the output of their XXE payload to some other file or their own server.<br>
<br><br><em><b>XML External Entity - eXtensible Markup Language</b></em><br>
<em>Before we move on to learn about XXE exploitation we'll have to understand XML properly.</em><br>
<em>XML (eXtensible Markup Language) is a markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable. It is a markup language used for storing and transporting data.</em><br>
<em>Why we are using XML?</em><br>
1. eXtensible Markup Language is platform-independent and programming language independent, thus it can be used on any system and supports the technology change when that happens. <br>
2. The data stored and transported using XML can be changed at any point in time without affecting the data presentation.<br>
3. eXtensible Markup Language allows validation using DTD and Schema. This validation ensures that the XML document is free from any syntax error.
4. eXtensible Markup Language simplifies data sharing between various systems because of its platform-independent nature. XML data doesn't require any conversion when transferred between different systems.
<em>Syntax</em><br>
<em>Every XML document mostly starts with what is known as XML Prolog.</em><br><br>

```
<?xml version="1.0" encoding="UTF-8"?>
```

<br><em>Above the line is called XML prolog and it specifies the XML version and the encoding used in the XML document. This line is not compulsory to use but it is considered a "good practice" to put that line in all your XML documents.</em><br>
<em>Every eXtensible Markup Language document must contain a 'ROOT' element. For example:</em><br>

```
<?xml version="1.0" encoding="UTF-8"?>
<mail>
    <to>unknown</to>
    <from>unknowndot</from>
    <subject>unknowndotexe</subject>
    <text>?</text>
</mail>
```

<br><em>In the above example the <mail> is the ROOT element of that document and ```<to>,<from>,<subject>,<text>``` are the children elements. If the XML document doesn't have any root element then it would be considered wrong or invalid XML doc.</em><br>
<em>Another thing to remember is that eXtensible Markup Language is a case sensitive language. If a tag starts like ```<to>``` then it has to end by ```</to>``` and not by something like ```</To>```.</em><br>
 
<em>Like HyperText Markup Language we can use attributes in XML too. The syntax for having attributes is also very similar to HyperText Markup Language. For example:</em><br>
```
 <text category = "message">We need to learn about eXtensible Markup Language</text>
```
 <br><em>In the above example category is the attribute name and message is the attribute value.</em><br>
<img src="https://user-images.githubusercontent.com/79203900/150979115-2921b9f4-0a22-4210-bd22-ddb697e908f8.png"/>
<br><em>eXtensible Markup Language External Entity (XXE) - DTD </em><br>
<em>Before we move on to start learning about eXtensible Markup Language External Entity we'll have to understand what is DTD in XML.</em><br>
<em>DTD stands for Document Type Definition. A Document Type Definition defines the structure and the legal elements and attributes of an XML document.</em><br>
<em>Let us try to understand this with the help of an example. Say we have a file named note.dtd with the following content:</em><br>
```
<!DOCTYPE note [ <!ELEMENT note (to,from,heading,body)>
<!ELEMENT to (#PCDATA)> <!ELEMENT from (#PCDATA)>
<!ELEMENT heading (#PCDATA)> <!ELEMENT body (#PCDATA)> ]>
```
 <br><em>Now we can use this Document Type Definition to validate the information of some XML document and make sure that the XML file conforms to the rules of that DTD.</em><br>
<em>Below is given an eXtensible Markup Language document that uses ```note.dtd```</em><br><br>
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
    <to>unknown</to>
    <from>unknowndot</from>
    <heading>unknowndotexe</heading>
    <body>XXE attack</body>
</note>
```
<br><br><em>So now let's understand how that Document Type Definition validates the eXtensible Markup Language.</em><br>
<em>Here's what all those terms used in ```note.dtd``` mean:</em><br>
1. !DOCTYPE note - Defines a root element of the document named <b>note</b>
2. !ELEMENT note - Defines that the note element must contain the elements: "to,from,heading,body"
3. !ELEMENT to - Defines the ```to``` element to be of type "#PCDATA"
4. !ELEMENT from - Defines the ```from``` element to be of type "#PCDATA"
5. !ELEMENT heading - Define the ```heading``` element to be of type "#PCDATA"
6. !ELEMENT body - Defines the ```body``` element to be of type "#PCDATA"
 <br><br><b><em>NOTE: #PCDATA means parseable character data.</b></em><br>
<img src="https://user-images.githubusercontent.com/79203900/150984391-7d615ea9-5951-430c-b550-3d303697fe3f.png"/>
<br><em>eXtensible Markup Language External Entity (XXE) - XXE Payload</em><br>
<em>Now we'll see some XEE payload and see how they are working.</em><br>
1. The first payload we'll see is very simple. If you've read the previous task properly then you'll understand this payload very easily.
```
<!DOCTYPE replace [<!ENTITY name "dotexe">]>
 <userInfo>
  <firstName>unknown</firstName>
  <lastName>&name;</lastName>
 </userInfo>
```
 <br><br><em>As we can see we are defining a ```ENTITY``` called ```name``` and assigning it a value ```dotexe```. Later we are using that ENTITY in our code.</em><br>
2. We can also use XXE to read some file from the system by defining an ENTITY and having it use the SYSTEM keyword

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY read SYSTEM "file:///etc/passwd">]>
<root>&read;</root>
```
<br><br><em>Here again, we are defining an ENTITY with the name ```read``` but the difference is that we are setting it value to ```SYSTEM``` and path of the file.</em><br>
<em>If we use this payload then a website vulnerable to XXE(normally) would display the content of the file ```/etc/passwd```.</em><br>
<em>In a similar manner, we can use this kind of payload to read other files but a lot of times you can fail to read files in this manner or the reason for failure could be the file you are trying to read.</em><br><br>
<img src="https://user-images.githubusercontent.com/79203900/150987794-f97bbce0-e896-451e-aab7-1f8dd0a44388.png"/>
 <br><br><em>Now let us see some payloads in action. The payload that we'll be using is the one we saw in the previous task.</em><br>
1. Let's see how the website would look if we'll try to use the payload for displaying the name!
<img src="https://user-images.githubusercontent.com/79203900/150989179-9515281f-e354-45eb-a832-2a73a2289343.png"/>
<img src="https://user-images.githubusercontent.com/79203900/150991550-ee5139ce-d37f-4ff0-8273-636b3236f08a.png"/>
<img src="https://user-images.githubusercontent.com/79203900/150991846-d6af6062-69f4-456c-904e-f0dc58a98045.png"/>
 
 <br><br><em><b>Severity 5 - Broken Access Control</b></em><br>
 <em>Websites have pages that are protected from regular visitors, for example only the site's admin user should be able to access a page to manage other users. If a website visitor is able to access the protected page/pages that they are not authorised to view, the access controls are broken.</em><br>
<em>A regular visitor being able to access protected pages, can lead to the following:</em><br>
1. Being able to view sensitive information
2. Accessing unauthorized functionality

<em>OWASP - Open Web Application Security Project - listed a few attack scenarios demonstrating access control weaknesses;</em><br>
 <em><b>Scenario #1:</b> The application uses unverified data in a SQL call that is accessing account information:</em><br>
```
 pstmt.setString(1,request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery();
```
<br><br><em>An attacker simply modifies the ```acct``` parameter in the browser to send whatever account number they want. If not properly verified, the attacker can access any user's account. Example: http://example.com/app/accountInfo?acct=notmyacct</em><br>
 
 <em><b>Scenario #2:</b> An attacker simply force browses to target URLs. Adminrights are required for access to the admin page. Example: <br> http://example.com/app/getappInfo <br> http://example.com/app/admin_getappInfo</em><br>
 <em>If an unauthenticated user can access either page, it's a flaw. If a non-admin can access the admin page, this is a flaw.</em><br>
 <em>To put simply, broken access control allows attacker to bypass authorization which can allow them to view sensitive data or perform tasks as if they were a privileged user.</em><br>
 <br><em><b>Broken Access Control (IDOR Challenge)</b></em><br>
 <em>IDOR, or Insecure Direct Object Reference, is the act of exploiting a misconfiguration in the way user input is handled, to access resources you wouldn't ordinarily be able to access. IDOR is a type of access control vulnerability.</em><br>
 <em>For example, let's say we're logging into our bank account, and after correctly authenticating ourselves, we get taken to a URL like this : ``` https://example.com/bank?account_number=1234```. On that page we can see all our important bank details, and a user would do whatever they needed to do and move along their way thinking nothing is wrong.</em><br>
 <em>There is however a potentially huge problem here, a hacker may be able to change the account_number parameter to something else like 1235, and if the site is incorectly configured, then he would have access to someone else's bank information.</em><br>
<br><img src="https://user-images.githubusercontent.com/79203900/151336416-f3a70526-3517-4ca9-9b73-9331ebcc58c2.png"/>
 <br><img src="https://user-images.githubusercontent.com/79203900/151336536-cb4a46ab-1d19-4a09-b9e2-936bf71d1b5d.png"/>
 <br><img src="https://user-images.githubusercontent.com/79203900/151336793-f44fc4de-d258-45b3-b1b9-eea637806e2c.png"/>
 <br><br><br><em><b>Severity 6 - Security Misconfiguration</b></em><br>
 <em>Security Misconfiguration are distinct from the other Top10 vulnerabilities, because they occur when security could have been configured properly but was not.</em><br>
 <em>Security misconfiguration include:</em><br>
1. Poorly configured permissions on cloud services, like S3 buckets
2. Having unnecessary features enabled, like services, pages, accounts or privileges
3. Default accounts with unchanged passwords
4. Error messages that are overly detailed and allow an attacker to find out more about the system
5. Not using HTTP security headers, or revealing too much detail in the Server:HTTP header
<br><br><em>This vulnerability can often lead to more vulnerabilities, such as default credentials giving you access to sensitive data, XXE - eXtensible Markup Language External Entity or command injection on admin pages.</em><br>
 
 <br><br><em><b>Default Passwords</b></em><br>
 <em>Specifically, this VM focusses on default passwords. These are a specific example of a security misconfiguration. You could, and should, change any default password but people often don't.</em><br>
 <em>It's particularly common in embedded and Internet of Things devices, and much of the time the owners don't change these passwords.</em><br>
 <em>It's easy to imagine the risk of default credentials from an attacker's point of view. Being able to gain access to admin dashboards, services designed for system administrators or manufacturers, or even network infrastructure could be incredibly useful in attacking a business. From data exposure to easy RCE - Remote Code Execution, the effects of default credentials can be severe.</em><br>
<em>In October 2017, Dyn (a DNS provider) was taken offline by one of the most memorable DDoS attacks of the past 10 years. The flood of traffic came mostly from Internet of Things and networking devices like routers and modems, infected by the Mirai malware.</em><br>
 <em>How did the malware take over the system? Default passwords. The malware had a list of 63 username/password pairs, and attempted to log in to exposed telnet services.</em><br>
 <em>The DDoS attack was notable because it took many large websites and services offline. Amazon, Twitter, Netflix, GitHub, Xbox Live, PlayStation Network, and many more services went offline for several hours in 3 waves of DDoS attacks on Dyn.</em><br>
 
 <b><b><em>Practical example: The next VM we gonna use showcases a ```Security Misconfiguration```, as a part of the OWASP Top 10 Vulnerabilities list.</em><br>
  <br><img src="https://user-images.githubusercontent.com/79203900/151345101-92038704-6d0f-4f8e-8586-e97f55d717f1.png"/>
  <br><br><br><em>Severity 7 - XSS Explained - Cross-site scripting!<b></em></b><br><br>
  <em>Cross-site scripting, also known as XSS is a security vulnerability typically found in web applications. It's a type of injection which can allow an attacker to execute malicious scripts and have it execute on a victim's machine.</em><br>
  <em>A web application is vulnerable to Cross-site Scripting if it uses unsanitized user input. XSS is possible in Javascript, VBScript, Flash and CSS.</em><br>
  <em>There are three main types of cross-site scripting:</em><br>
1. Stored XSS - the most dangerous type of XSS. This is where a malicious string originates from the website's database. This often happens when a website allows user input that is not sanitised when inserted into the database.
2. Reflected XSS - The malicious payload is part of the victims request to the website. The website includes this payload in response back to the user. To summarise, an attacker needs to trick a victim into clicking a URL to execute their malicious payload.
3. DOM-Based XSS - DOM stands for Document Object Model and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document and this document can be either displayed in the browser windows or as the HTML source.
  
<br><b><em><b>XSS Payloads</b></em><br>
<em>Remember, cross-site scripting is a vulnerability that can be exploited to execute malicious Javascript on a victim's machine. Check out some common payloads types used:</em><br>
1. Popup's ```<script>alert("Hello World")</script>``` - Creates a Hello World message popup on a users browser.
2. Writing HTML (document.write) - Ovveride the website's HTML to add your own (essentially defacing the entire page).
3. XSS Keylogger (http://www.xss-payloads.com) - You can log all keystrokes of a user, capturing their password and other sensitive information they type into the webpage.
4. Port scanning (http://www.xss-payloads.com) - A mini local port scanner 
  
<br><br><em>You can make XSS payloads that take snapshots from a webcam or even get a more capable port and network scanner.</em><br>
  <br><b><em>XSS - Cross-site Scripting Challenge</em></b><br><br>
  <em>Next Virtual Machine we will deploy showcases DOM-Based, Reflected and Stored XSS.</em><br>
  
<br><em>Question #1: Craft a reflected XSS payload that will cause a popup saying "Hello"</em><br>
 

